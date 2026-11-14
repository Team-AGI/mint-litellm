"""SIEM 전달: 봉인된 사건과 경보를 외부 보안 관제 시스템으로 보낸다.

작업 ``siem_forward``(15초마다)가 대상(``mint.siem_targets``)마다 봉인 순번이 위치(커서)보다 큰
사건을 순서대로 읽어 묶음(``BATCH``건)으로 보내고, 받은 뒤에만 위치를 옮긴다(최소 한 번 전달: 보낸
뒤 위치를 저장하기 전에 멈추면 같은 묶음이 다시 간다. 수신 쪽은 ``event_id``로 중복을 거른다).
실패하면 대상별로 지수 백오프로 쉬고, 정해진 시간 넘게 이어지면 경보를 연다. 호출 경로는 건드리지
않고, 읽는 양은 묶음 하나로 제한된다.

내용은 허용한 필드만 담는다(사건 종류·시각·인스턴스·주체·서버·도구·판정과 사유·정책·승인·경보
등급). 인자·결과 값과 비밀은 사건에 없고, 문자열 값은 한 번 더 비밀·개인정보 가리기를 거친다.
"""

import json
import logging
import os
import socket
import ssl
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import psycopg

from mint_litellm import __version__
from mint_litellm.console import labels
from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.plugin.policy.sensitive_scan import mask_text
from mint_litellm.types.events import EventKind, decoded_decision

log = logging.getLogger("mint_litellm.siem")

KINDS = ("syslog", "cef", "hec", "elastic", "otlp")
ALERT_KIND = "siem_forward_failing"
BATCH = 100
# 한 번의 작업 실행이 대상 하나에 쓰는 시간 상한(초)
RUN_SECONDS = 10.0
IO_SECONDS = 10.0
MAX_BACKOFF_SECONDS = 600
MAX_MESSAGE_BYTES = 8192
MAX_VALUE = 256
# RFC 5424 구조화 데이터 식별자(문서용 사설 기업 번호)
SD_ID = "mint@32473"
FACILITY = 13  # log audit
DEFAULT_PORTS = {"tls": 6514, "tcp": 514, "udp": 514}

# 오류 코드(화면 표시명은 console.labels.SIEM_ERROR)
SECRET_MISSING = "secret_missing"


class SendError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# --- 한 건의 정규화 -----------------------------------------------------------------------------

# 일반 제어 사건 본문에서 그대로 내보내도 되는 키(식별자·열거값만)
SAFE_KEYS = (
    "server_id",
    "kind",
    "severity",
    "role",
    "org_id",
    "status",
    "policy_version_id",
    "approval_id",
    "call_approval_id",
    "mode",
    "name",
    "target",
    "scope",
    "outcome",
)
_DECISION = {EventKind.DECISION_EVALUATED.value, EventKind.DISCOVERY_EVALUATED.value}
_CALL = {EventKind.CALL_RESPONSE_RECEIVED.value, EventKind.CALL_OUTCOME_UNKNOWN.value}
_RENAME = {"server_id": "server", "kind": "subtype_kind", "severity": "subtype_severity"}
# 위험도(syslog 심각도 번호): 낮을수록 위험하다
_ALERT_SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5}


def _clean(value: Any) -> Any:
    """문자열은 제어 문자를 없애고 가린 뒤 자른다. 목록·사전은 안쪽까지 같게 처리한다."""
    if isinstance(value, str):
        text = mask_text("".join(" " if ord(c) < 32 or ord(c) == 127 else c for c in value))
        return text if len(text) <= MAX_VALUE else text[:MAX_VALUE] + "…"
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _category(kind: str) -> str:
    if kind in _DECISION:
        return "decision"
    if kind in _CALL:
        return "call"
    if kind.startswith(("approval_", "call_approval", "consent_", "denial_")):
        return "approval"
    if kind.startswith("alert_"):
        return "alert"
    if kind in {
        k.value
        for k in (
            EventKind.ENFORCEMENT_UNVERIFIED,
            EventKind.ENFORCEMENT_VERIFIED,
            EventKind.SERVER_IDENTITY_MISMATCH_OBSERVED,
            EventKind.BUFFER_OVERFLOW,
            EventKind.BUFFER_REPLAYED,
            EventKind.RESTORE_BLOCKED,
        )
    }:
        return "system"
    return "admin"


def _decision_fields(payload: dict) -> dict[str, Any]:
    d = decoded_decision(payload)
    stop = d.get("stop") or {}
    findings = d.get("findings") or []
    code = stop.get("reason_code") or (findings[0].get("reason_code") if findings else None)
    out: dict[str, Any] = {
        "server": d.get("resolved_server_id") or d.get("requested_server_name"),
        "tool": d.get("tool"),
        "action": d.get("enforced_action"),
        "outcome": d.get("outcome") if isinstance(d.get("outcome"), str) else None,
        "reason_code": code,
        "policy_ids": list(d.get("policy_ids") or []),
        "approval_id": d.get("consumed_call_approval_id") or d.get("selected_approval_id"),
        "mode": d.get("mode"),
    }
    if code:
        out["reason"] = labels.outcome_reason(code)
    return out


def build_record(row: dict, instance: str) -> dict[str, Any]:
    """사건 행을 허용한 필드만 가진 한 건으로 만든다. 값이 없는 필드는 뺀다."""
    kind = row["kind"]
    payload = row.get("payload") or {}
    subject = row.get("subject") or {}
    rec: dict[str, Any] = {
        "event_id": str(row["event_id"]),
        "time": _iso(row["inserted_at"]),
        "instance": instance,
        "kind": kind,
        "label": labels.pick(labels.EVENT_KIND, kind),
        "category": _category(kind),
        "actor": row.get("actor"),
        "seal_seq": row.get("seal_seq"),
        "principal_type": subject.get("principal_type"),
        "principal_id": subject.get("principal_id"),
        "org_id": subject.get("org_id"),
        "severity": 6,
    }
    parts = str(row.get("source_key") or "").split(":")
    if kind not in _DECISION | _CALL and len(parts) == 4:
        rec["entity"], rec["entity_id"] = parts[0], parts[1]
    if kind in _DECISION:
        rec.update(_decision_fields(payload))
        if rec.get("action") == "block":
            rec["severity"] = 4
    elif kind in _CALL:
        rec["server"] = payload.get("server_id")
        rec["outcome"] = payload.get("outcome") if isinstance(payload.get("outcome"), str) else None
        rec["policy_ids"] = list(payload.get("output_findings") or [])
        rec["approval_id"] = payload.get("call_approval_id")
        if payload.get("output_blocked") or payload.get("is_error"):
            rec["severity"] = 5
    else:
        is_alert = rec["category"] == "alert"
        for key in SAFE_KEYS:
            value = payload.get(key)
            if isinstance(value, str | int | bool):
                name = _RENAME.get(key, key)
                rec[name.replace("subtype_", "alert_") if is_alert else name] = value
        if kind == EventKind.ALERT_OPENED.value:
            rec["severity"] = _ALERT_SEVERITY.get(str(payload.get("severity")), 5)
            rec["alert_label"] = labels.pick(labels.ALERT_KIND, payload.get("kind"))
        elif rec["category"] != "alert":
            rec["severity"] = 5
    if rec.get("outcome"):
        rec["outcome_label"] = labels.pick(labels.OUTCOME, rec["outcome"])
    rec = {k: _clean(v) for k, v in rec.items() if v not in (None, "", [])}
    rec["summary"] = _summary(rec)
    return rec


def _summary(rec: dict) -> str:
    bits = [rec["label"]]
    if rec.get("alert_label"):
        bits.append(rec["alert_label"])
    for key, name in (
        ("outcome_label", ""),
        ("server", "서버 "),
        ("tool", "도구 "),
        ("reason", "사유 "),
        ("entity_id", "대상 "),
    ):
        if rec.get(key):
            bits.append(f"{name}{rec[key]}")
    if rec.get("actor"):
        bits.append(f"실행자 {labels.actor(rec['actor'])}")
    return " · ".join(bits)


def probe_record(instance: str) -> dict[str, Any]:
    """시험 전송용 한 건. 원장에는 남지 않는다."""
    return {
        "event_id": str(uuid.uuid4()),
        "time": _iso(datetime.now(UTC)),
        "instance": instance,
        "kind": "siem_test",
        "label": "SIEM 시험 전송",
        "category": "system",
        "severity": 6,
        "summary": "SIEM 시험 전송: 이 메시지가 보이면 전달 설정이 맞습니다.",
    }


# --- 형식 ---------------------------------------------------------------------------------------


def _sd_value(value: Any) -> str:
    text = ",".join(map(str, value)) if isinstance(value, list) else str(value)
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _token(text: str) -> str:
    """RFC 5424 헤더 토큰(공백 없는 인쇄 가능 ASCII). 비면 줄표."""
    out = "".join(c if 33 <= ord(c) <= 126 else "_" for c in text)
    return out or "-"


_SD_FIELDS = (
    "event_id",
    "instance",
    "kind",
    "category",
    "actor",
    "principal_type",
    "principal_id",
    "org_id",
    "server",
    "tool",
    "action",
    "outcome",
    "reason_code",
    "policy_ids",
    "approval_id",
    "alert_kind",
    "alert_severity",
    "seal_seq",
    "entity",
    "entity_id",
)


def syslog_message(rec: dict, host: str, *, text: str | None = None) -> bytes:
    """RFC 5424 한 건. ``text``가 없으면 구조화 데이터와 한국어 요약을, 있으면 그 본문만 담는다."""
    pri = FACILITY * 8 + int(rec.get("severity", 6))
    sd = "-"
    if text is None:
        params = " ".join(
            f'{name}="{_sd_value(rec[name])}"' for name in _SD_FIELDS if rec.get(name) is not None
        )
        sd = f"[{SD_ID} {params}]"
        body = b"\xef\xbb\xbf" + rec["summary"].encode("utf-8")
    else:
        body = text.encode("utf-8")
    head = (
        f"<{pri}>1 {rec['time']} {_token(host)[:255]} mint-litellm - {_token(rec['kind'])[:32]}"
        f" {sd} "
    ).encode()
    return (head + body)[:MAX_MESSAGE_BYTES]


def _cef_header(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_value(value: Any) -> str:
    text = ",".join(map(str, value)) if isinstance(value, list) else str(value)
    return text.replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


_CEF_SEVERITY = {2: 10, 3: 8, 4: 6, 5: 4, 6: 3}
_CEF_FIELDS = (
    ("externalId", "event_id"),
    ("suser", "actor"),
    ("duser", "principal_id"),
    ("act", "action"),
    ("outcome", "outcome"),
    ("reason", "reason"),
    ("cat", "category"),
    ("cs1", "server"),
    ("cs2", "tool"),
    ("cs3", "policy_ids"),
    ("cs4", "approval_id"),
    ("cs5", "reason_code"),
    ("cs6", "instance"),
    ("msg", "summary"),
)
_CEF_LABELS = {
    "cs1": "server",
    "cs2": "tool",
    "cs3": "policyIds",
    "cs4": "approvalId",
    "cs5": "reasonCode",
    "cs6": "instance",
}


def cef_line(rec: dict) -> str:
    """CEF:0 한 줄. 헤더는 ``\\``·``|``, 확장 값은 ``\\``·``=``·줄바꿈을 이스케이프한다."""
    ts = datetime.fromisoformat(rec["time"].replace("Z", "+00:00"))
    ext = [f"rt={int(ts.timestamp() * 1000)}"]
    for key, field in _CEF_FIELDS:
        if rec.get(field) is not None:
            if key in _CEF_LABELS:
                ext.append(f"{key}Label={_CEF_LABELS[key]}")
            ext.append(f"{key}={_cef_value(rec[field])}")
    head = "|".join(
        _cef_header(p)
        for p in (
            "CEF:0",
            "MINT",
            "MINT for LiteLLM",
            __version__,
            rec["kind"],
            rec["label"],
            str(_CEF_SEVERITY.get(int(rec.get("severity", 6)), 3)),
        )
    )
    return head + "|" + " ".join(ext)


def _document(rec: dict) -> dict[str, Any]:
    return {k: v for k, v in rec.items() if k != "severity"} | {"severity_number": rec["severity"]}


def hec_body(recs: list[dict], host: str, options: dict) -> bytes:
    out = []
    for rec in recs:
        item = {
            "time": datetime.fromisoformat(rec["time"].replace("Z", "+00:00")).timestamp(),
            "host": host,
            "source": "mint-litellm",
            "sourcetype": "mint:event",
            "event": _document(rec),
        }
        if options.get("index"):
            item["index"] = options["index"]
        out.append(json.dumps(item, ensure_ascii=False))
    return "\n".join(out).encode("utf-8")


def elastic_body(recs: list[dict], options: dict) -> bytes:
    index = options.get("index") or "mint-events"
    lines = []
    for rec in recs:
        lines.append(json.dumps({"create": {"_index": index, "_id": rec["event_id"]}}))
        lines.append(json.dumps({"@timestamp": rec["time"], **_document(rec)}, ensure_ascii=False))
    return ("\n".join(lines) + "\n").encode("utf-8")


_OTLP_NUMBER = {2: 21, 3: 17, 4: 13, 5: 10, 6: 9}
_OTLP_TEXT = {21: "FATAL", 17: "ERROR", 13: "WARN", 10: "INFO2", 9: "INFO"}


def otlp_body(recs: list[dict]) -> bytes:
    def attr(key: str, value: Any) -> dict:
        text = ",".join(map(str, value)) if isinstance(value, list) else str(value)
        return {"key": key, "value": {"stringValue": text}}

    records = []
    for rec in recs:
        ts = datetime.fromisoformat(rec["time"].replace("Z", "+00:00"))
        number = _OTLP_NUMBER.get(int(rec["severity"]), 9)
        records.append(
            {
                "timeUnixNano": str(int(ts.timestamp() * 1_000_000)) + "000",
                "severityNumber": number,
                "severityText": _OTLP_TEXT[number],
                "body": {"stringValue": rec["summary"]},
                "attributes": [
                    attr(f"mint.{k}", v)
                    for k, v in rec.items()
                    if k not in ("time", "summary", "severity")
                ],
            }
        )
    doc = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        attr("service.name", "mint-litellm"),
                        attr("service.version", __version__),
                        attr("mint.instance", recs[0]["instance"]),
                    ]
                },
                "scopeLogs": [{"scope": {"name": "mint-litellm"}, "logRecords": records}],
            }
        ]
    }
    return json.dumps(doc, ensure_ascii=False).encode("utf-8")


# --- 전송 ---------------------------------------------------------------------------------------


def error_code(error: BaseException) -> str:
    """오류를 짧은 코드로 줄인다. 메시지는 주소·비밀이 들어갈 수 있어 남기지 않는다."""
    if isinstance(error, SendError):
        return error.code
    # httpx는 원인(``__cause__``) 안쪽에 소켓 오류를 담는다
    chain, seen = [], error
    while seen is not None and len(chain) < 5:
        chain.append(seen)
        seen = seen.__cause__ or seen.__context__
    for item in chain:
        if isinstance(item, ssl.SSLError):
            return "tls_error"
        if isinstance(item, TimeoutError | httpx.TimeoutException):
            return "timeout"
        if isinstance(item, ConnectionRefusedError):
            return "connection_refused"
        if isinstance(item, socket.gaierror):
            return "dns_error"
    if isinstance(error, OSError | httpx.TransportError):
        return "connection_failed"
    return type(error).__name__[:60]


def read_secret(ref: str | None, environ: dict[str, str] | None = None) -> str | None:
    if not ref:
        return None
    kind, _, value = ref.partition(":")
    try:
        if kind == "env":
            text = (environ if environ is not None else os.environ).get(value, "")
        else:
            text = Path(value).read_text(encoding="utf-8")
    except OSError:
        text = ""
    text = text.strip()
    if not text:
        raise SendError(SECRET_MISSING)
    return text


def parse_endpoint(kind: str, endpoint: str) -> tuple[str, str, int | None, str]:
    """(scheme, host, port, path). 형식에 맞지 않으면 ``ControlError``."""
    parts = urlsplit(endpoint)
    syslog = kind in ("syslog", "cef")
    allowed = ("tls", "tcp", "udp") if syslog else ("http", "https")
    if parts.scheme not in allowed or not parts.hostname or parts.username or parts.password:
        shown = "tls://호스트:포트, tcp://…, udp://…" if syslog else "http(s)://호스트[:포트]/경로"
        raise ControlError(f"주소 형식이 올바르지 않습니다. {shown} 형식으로 적으십시오.")
    port = parts.port or (DEFAULT_PORTS[parts.scheme] if syslog else None)
    return parts.scheme, parts.hostname, port, parts.path


def normalize_endpoint(kind: str, endpoint: str) -> str:
    """검사하고 기본 경로를 채운다(Splunk·Elastic·OTLP는 흔한 수집 경로)."""
    endpoint = endpoint.strip()
    parse_endpoint(kind, endpoint)
    default = {"hec": "/services/collector/event", "otlp": "/v1/logs"}.get(kind)
    parts = urlsplit(endpoint)
    if default and parts.path in ("", "/"):
        return parts._replace(path=default).geturl()
    if kind == "elastic" and not parts.path.rstrip("/").endswith("_bulk"):
        return parts._replace(path=parts.path.rstrip("/") + "/_bulk").geturl()
    return endpoint


def display_endpoint(endpoint: str) -> str:
    """화면에는 주소의 접속 지점만 낸다(경로·질의에 비밀이 있을 수 있다)."""
    parts = urlsplit(endpoint)
    return f"{parts.scheme}://{parts.hostname}" + (f":{parts.port}" if parts.port else "")


def _send_syslog(target: dict, recs: list[dict], host: str) -> None:
    scheme, name, port, _ = parse_endpoint(target["kind"], target["endpoint"])
    options = target["options"] or {}
    cef = target["kind"] == "cef"
    messages = [syslog_message(r, host, text=cef_line(r) if cef else None) for r in recs]
    if scheme == "udp":
        with socket.socket(
            socket.AF_INET6 if ":" in name else socket.AF_INET, socket.SOCK_DGRAM
        ) as sock:
            for message in messages:
                sock.sendto(message, (name, port))
        return
    if options.get("framing") == "newline":
        data = b"".join(m.replace(b"\n", b" ") + b"\n" for m in messages)
    else:  # RFC 6587 옥텟 세기
        data = b"".join(str(len(m)).encode() + b" " + m for m in messages)
    with socket.create_connection((name, port), timeout=IO_SECONDS) as raw:
        if scheme == "tls":
            context = ssl.create_default_context(cafile=options.get("ca_file") or None)
            with context.wrap_socket(raw, server_hostname=name) as tls:
                tls.sendall(data)
        else:
            raw.sendall(data)


def _send_http(target: dict, recs: list[dict], host: str, secret: str | None) -> None:
    options = target["options"] or {}
    kind = target["kind"]
    headers = {"User-Agent": f"mint-litellm/{__version__}"}
    if kind == "hec":
        body, headers["Content-Type"] = hec_body(recs, host, options), "application/json"
        if secret:
            headers["Authorization"] = f"Splunk {secret}"
    elif kind == "elastic":
        body, headers["Content-Type"] = elastic_body(recs, options), "application/x-ndjson"
        if secret:
            headers["Authorization"] = f"ApiKey {secret}"
    else:
        body, headers["Content-Type"] = otlp_body(recs), "application/json"
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
    with httpx.Client(
        timeout=IO_SECONDS, follow_redirects=False, verify=options.get("ca_file") or True
    ) as http:
        response = http.post(target["endpoint"], content=body, headers=headers)
    if response.status_code // 100 != 2:
        raise SendError(f"http_{response.status_code}")
    if kind == "elastic":
        try:
            failed = [
                i
                for item in response.json().get("items", [])
                for i in item.values()
                if i.get("status", 200) >= 400 and i.get("status") != 409
            ]
        except ValueError:
            failed = []
        if failed:
            raise SendError(f"elastic_item_{failed[0]['status']}")


def deliver(target: dict, recs: list[dict], environ: dict[str, str] | None = None) -> None:
    """한 묶음을 보낸다. 실패하면 ``SendError``(오류 코드)."""
    host = socket.gethostname()
    try:
        if target["kind"] in ("syslog", "cef"):
            _send_syslog(target, recs, host)
        else:
            _send_http(target, recs, host, read_secret(target["secret_ref"], environ))
    except SendError:
        raise
    except Exception as error:
        raise SendError(error_code(error)) from None


# --- 작업 ---------------------------------------------------------------------------------------

EVENTS_SQL = (
    "SELECT event_id, inserted_at, kind, source_key, actor, subject, payload, seal_seq"
    " FROM mint.events WHERE instance_id = %s AND seal_seq > %s ORDER BY seal_seq LIMIT %s"
)


def backoff_seconds(failures: int) -> int:
    return min(5 * 2 ** max(failures - 1, 0), MAX_BACKOFF_SECONDS)


def _failed(conn: psycopg.Connection, t: dict, code: str, count: int) -> None:
    conn.execute(
        "UPDATE mint.siem_targets SET failed_total = failed_total + %s, last_error = %s,"
        " last_attempt_at = now(), failing_since = COALESCE(failing_since, now()),"
        " consecutive_failures = consecutive_failures + 1,"
        " next_attempt_at = now() + make_interval(secs => %s)"
        " WHERE instance_id = %s AND name = %s",
        (count, code, backoff_seconds(t["consecutive_failures"] + 1), t["instance_id"], t["name"]),
    )


def _delivered(conn: psycopg.Connection, t: dict, last_seq: int, count: int) -> None:
    conn.execute(
        "UPDATE mint.siem_targets SET cursor_seq = %s, sent_total = sent_total + %s,"
        " last_delivered_at = now(), last_attempt_at = now(), last_error = NULL,"
        " failing_since = NULL, consecutive_failures = 0, next_attempt_at = NULL"
        " WHERE instance_id = %s AND name = %s",
        (last_seq, count, t["instance_id"], t["name"]),
    )


def _run_test(conn: psycopg.Connection, t: dict, environ: dict[str, str] | None) -> None:
    code = None
    try:
        deliver(t, [probe_record(t["instance_id"])], environ)
    except SendError as error:
        code = error.code
    conn.execute(
        "UPDATE mint.siem_targets SET last_test_at = now(), last_test_error = %s"
        " WHERE instance_id = %s AND name = %s",
        (code, t["instance_id"], t["name"]),
    )


def _watch(conn: psycopg.Connection, t: dict, minutes: int) -> None:
    """전달이 ``minutes``분 넘게 막혀 있으면 경보를 열고, 풀리면 닫는다."""
    key = f"{ALERT_KIND}:{t['name']}"
    row = fetchone(
        conn,
        "SELECT failing_since, last_error, now() - failing_since >= make_interval(mins => %s)"
        " AS long FROM mint.siem_targets WHERE instance_id = %s AND name = %s",
        (minutes, t["instance_id"], t["name"]),
    )
    if row is None:
        return
    with conn.transaction():
        if row["failing_since"] is None:
            alerts.resolve(conn, t["instance_id"], key)
        elif row["long"] and not fetchone(
            conn,
            "SELECT 1 AS x FROM mint.alerts WHERE instance_id = %s AND dedup_key = %s"
            " AND status <> 'resolved'",
            (t["instance_id"], key),
        ):
            alerts.raise_alert(
                conn,
                t["instance_id"],
                kind=ALERT_KIND,
                severity="high",
                dedup_key=key,
                subject={
                    "target": t["name"],
                    "last_error_code": row["last_error"],
                    "minutes": minutes,
                },
            )


def _forward(job: Any, t: dict, environ: dict[str, str] | None) -> None:
    conn = job.conn
    deadline = time.monotonic() + RUN_SECONDS
    while time.monotonic() < deadline:
        job.checkpoint()
        rows = fetchall(conn, EVENTS_SQL, (t["instance_id"], t["cursor_seq"], BATCH))
        if not rows:
            return
        recs = [build_record(r, t["instance_id"]) for r in rows]
        try:
            deliver(t, recs, environ)
        except SendError as error:
            _failed(conn, t, error.code, len(recs))
            return
        t["cursor_seq"] = rows[-1]["seal_seq"]
        _delivered(conn, t, t["cursor_seq"], len(recs))
        if len(rows) < BATCH:
            return


def run(job: Any, environ: dict[str, str] | None = None) -> None:
    """대상마다 시험 요청 처리, 묶음 전달, 경보 점검을 한다. 실패는 대상별로 기록하고 끝낸다."""
    conn = job.conn
    minutes = getattr(job.settings, "siem_alert_minutes", 15)
    targets = fetchall(
        conn,
        "SELECT *, (next_attempt_at IS NULL OR next_attempt_at <= now()) AS due,"
        " (test_requested_at IS NOT NULL AND (last_test_at IS NULL"
        "  OR last_test_at < test_requested_at)) AS test_due"
        " FROM mint.siem_targets WHERE instance_id = %s ORDER BY name",
        (job.instance_id,),
    )
    for t in targets:
        lock = (f"siem:{t['instance_id']}:{t['name']}",)
        got = fetchone(conn, "SELECT pg_try_advisory_lock(hashtext(%s)) AS ok", lock)
        if not got or not got["ok"]:
            continue  # 다른 실행기가 이 대상을 보내는 중이다
        try:
            if t["test_due"]:
                _run_test(conn, t, environ)
            if t["due"]:
                _forward(job, t, environ)
            _watch(conn, t, minutes)
        finally:
            conn.execute("SELECT pg_advisory_unlock(hashtext(%s))", lock)


# --- 관리 ---------------------------------------------------------------------------------------


def head_seq(conn: psycopg.Connection, instance: str) -> int:
    row = fetchone(
        conn,
        "SELECT COALESCE(max(seal_seq), 0) AS n FROM mint.events WHERE instance_id = %s",
        (instance,),
    )
    return int(row["n"])


def add(
    conn: psycopg.Connection,
    instance: str,
    *,
    name: str,
    kind: str,
    endpoint: str,
    secret_ref: str | None,
    options: dict,
    from_start: bool,
    created_by: str,
) -> None:
    if kind in ("syslog", "cef") and secret_ref:
        raise ControlError("syslog·CEF 대상에는 토큰을 쓰지 않습니다.")
    endpoint = normalize_endpoint(kind, endpoint)
    try:
        conn.execute(
            "INSERT INTO mint.siem_targets (instance_id, name, kind, endpoint, secret_ref,"
            " options, cursor_seq, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                instance,
                name,
                kind,
                endpoint,
                secret_ref,
                json.dumps(options),
                0 if from_start else head_seq(conn, instance),
                created_by,
            ),
        )
    except psycopg.errors.UniqueViolation:
        conn.rollback()
        raise ControlError(f"{name} 대상이 이미 있습니다.") from None
    except psycopg.errors.CheckViolation:
        conn.rollback()
        raise ControlError(
            "이름은 소문자로 시작하는 소문자·숫자·-·_ 32자 이하로 적으십시오."
        ) from None


def listing(conn: psycopg.Connection, instance: str) -> list[dict]:
    """대상 목록. 비밀 읽을 곳은 종류만, 주소는 접속 지점만 낸다."""
    head = head_seq(conn, instance)
    rows = fetchall(
        conn, "SELECT * FROM mint.siem_targets WHERE instance_id = %s ORDER BY name", (instance,)
    )
    for row in rows:
        row["backlog"] = max(head - row["cursor_seq"], 0)
        row["address"] = display_endpoint(row["endpoint"])
        row["secret_source"] = (row["secret_ref"] or "").partition(":")[0] or None
    return rows


def request_test(conn: psycopg.Connection, instance: str, name: str) -> bool:
    return (
        conn.execute(
            "UPDATE mint.siem_targets SET test_requested_at = now() WHERE instance_id = %s"
            " AND name = %s",
            (instance, name),
        ).rowcount
        == 1
    )

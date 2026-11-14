"""SIEM 전달: 형식(RFC 5424·CEF), 가리기, 위치·재시도·경보(가짜 수신 서버).

형식 시험은 데이터베이스 없이 돌고, 전달 시험은 MINT_TEST_DATABASE_URL이 없으면 건너뛴다.
"""

import json
import socket
import socketserver
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from uuid import uuid4

import pytest
from ctl_fixtures import INSTANCE

from mint_litellm.control import siem

LOOPBACK = "127.0" + ".0.1"  # 주소 이름 조회 지연을 피한다
KEY = "AKIA" + "ABCDEFGHIJKLMNOP"  # 클라우드 접근 키 모양(시험용 가짜 값)


def decision_row(**over):
    row = {
        "event_id": uuid4(),
        "inserted_at": datetime(1999, 12, 31, 23, 59, 59, 123456, tzinfo=UTC),
        "kind": "decision_evaluated",
        "source_key": "call:x:1:decision_evaluated",
        "actor": None,
        "subject": {"principal_type": "user", "principal_id": "alice", "org_id": "acme"},
        "payload": {
            "v": 2,
            "enforced_action": "block",
            "resolved_server_id": "docs",
            "tool": "read",
            "outcome": "blocked",
            "policy_ids": ["P1", "P2"],
            "selected_approval_id": "ap-1",
            "stop": {"status": "stop", "reason_code": "APPROVAL_ABSENT", "detail": "비밀 값"},
            "arguments": {"password": "hunter2"},
        },
        "seal_seq": 7,
    }
    row.update(over)
    return row


# --- 형식 ---------------------------------------------------------------------------------------


def test_record_carries_operator_labels_and_no_arguments_or_detail():
    rec = siem.build_record(decision_row(), INSTANCE)
    assert rec["reason_code"] == "APPROVAL_ABSENT" and rec["reason"] == "승인 없음"
    assert rec["outcome_label"] == "정책 차단" and rec["policy_ids"] == ["P1", "P2"]
    assert rec["approval_id"] == "ap-1" and rec["principal_id"] == "alice"
    text = json.dumps(rec, ensure_ascii=False)
    assert "hunter2" not in text and "비밀 값" not in text and "arguments" not in text


def test_strings_are_masked_and_control_characters_removed():
    payload = {"v": 2, "tool": f"x {KEY}\nline", "enforced_action": "allow"}
    rec = siem.build_record(decision_row(payload=payload), INSTANCE)
    assert KEY not in json.dumps(rec) and "[MASKED:cloud_access_key]" in rec["tool"]
    assert "\n" not in rec["tool"]


def test_control_events_forward_only_identifier_fields():
    rec = siem.build_record(
        {
            "event_id": uuid4(),
            "inserted_at": datetime(1999, 1, 2, tzinfo=UTC),
            "kind": "operator_added",
            "source_key": "operator:boss:1:operator_added",
            "actor": "root",
            "subject": None,
            "seal_seq": 3,
            "payload": {"role": "admin", "name": "boss", "token": "tok-secret", "note": "메모"},
        },
        INSTANCE,
    )
    assert rec["category"] == "admin" and rec["entity_id"] == "boss" and rec["role"] == "admin"
    assert "tok-secret" not in json.dumps(rec) and "메모" not in json.dumps(rec)


def test_alert_event_carries_kind_and_severity():
    rec = siem.build_record(
        {
            "event_id": uuid4(),
            "inserted_at": datetime(1999, 1, 2, tzinfo=UTC),
            "kind": "alert_opened",
            "source_key": "alert:a1:0:alert_opened",
            "actor": "mint-worker",
            "subject": None,
            "seal_seq": 4,
            "payload": {"kind": "call_spike", "severity": "high"},
        },
        INSTANCE,
    )
    assert (rec["alert_kind"], rec["alert_severity"], rec["severity"]) == ("call_spike", "high", 3)


def test_rfc5424_golden_with_structured_data_escaping():
    rec = {
        "event_id": "e1",
        "time": "1999-12-31T23:59:59.123456Z",
        "instance": "i1",
        "kind": "decision_evaluated",
        "severity": 4,
        "summary": "요약",
        "server": 'a]b"c\\d',
        "tool": "t",
    }
    assert (
        siem.syslog_message(rec, "host 1")
        == (
            "<108>1 1999-12-31T23:59:59.123456Z host_1 mint-litellm - decision_evaluated "
            '[mint@32473 event_id="e1" instance="i1" kind="decision_evaluated" '
            'server="a\\]b\\"c\\\\d" tool="t"] ﻿요약'
        ).encode()
    )


def test_cef_golden_escapes_header_and_extension():
    rec = {
        "event_id": "e1",
        "time": "1999-12-31T23:59:59.123456Z",
        "instance": "i1",
        "kind": "k",
        "label": "a|b\\c",
        "severity": 3,
        "summary": "x=y\nz",
        "server": "s",
        "policy_ids": ["P1", "P2"],
    }
    assert siem.cef_line(rec) == (
        f"CEF:0|MINT|MINT for LiteLLM|{siem.__version__}|k|a\\|b\\\\c|8|rt=946684799123"
        " externalId=e1 cs1Label=server cs1=s cs3Label=policyIds cs3=P1,P2"
        " cs6Label=instance cs6=i1 msg=x\\=y\\nz"
    )


def test_bodies_for_http_targets():
    rec = siem.build_record(decision_row(), INSTANCE)
    hec = json.loads(siem.hec_body([rec], "h", {"index": "main"}))
    assert hec["event"]["event_id"] == rec["event_id"] and hec["index"] == "main"
    lines = siem.elastic_body([rec], {}).decode().splitlines()
    assert json.loads(lines[0])["create"]["_id"] == rec["event_id"]
    assert json.loads(lines[1])["@timestamp"] == rec["time"]
    log = json.loads(siem.otlp_body([rec]))["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert log["severityText"] == "WARN" and log["body"]["stringValue"] == rec["summary"]


def test_endpoint_defaults_and_validation():
    assert siem.normalize_endpoint("hec", "https://s.test:8088") == (
        "https://s.test:8088/services/collector/event"
    )
    assert siem.normalize_endpoint("elastic", "https://e.test/").endswith("/_bulk")
    assert siem.normalize_endpoint("otlp", "https://o.test").endswith("/v1/logs")
    assert siem.display_endpoint("https://s.test:8088/services?token=x") == "https://s.test:8088"
    for kind, bad in (
        ("syslog", "https://s.test"),
        ("hec", "tcp://s.test:1"),
        ("hec", "https://user:pw@s.test"),
    ):
        with pytest.raises(siem.ControlError):
            siem.normalize_endpoint(kind, bad)


def test_backoff_doubles_up_to_a_cap():
    assert [siem.backoff_seconds(n) for n in (1, 2, 3, 20)] == [5, 10, 20, 600]


# --- 가짜 수신 서버 -----------------------------------------------------------------------------


class Collector(ThreadingHTTPServer):
    def __init__(self, status=200, body=b"{}"):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                size = int(self.headers.get("Content-Length", 0))
                self.server.requests.append((dict(self.headers), self.rfile.read(size)))
                self.send_response(self.server.status)
                self.send_header("Content-Length", str(len(self.server.reply)))
                self.end_headers()
                self.wfile.write(self.server.reply)

            def log_message(self, *args):
                pass

        super().__init__((LOOPBACK, 0), Handler)
        self.requests, self.status, self.reply = [], status, body
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://{LOOPBACK}:{self.server_address[1]}"

    def ids(self):
        out = []
        for _, body in self.requests:
            out += [json.loads(line)["event"]["event_id"] for line in body.decode().splitlines()]
        return out

    def stop(self):
        self.shutdown()
        self.server_close()


@pytest.fixture
def collector():
    server = Collector()
    yield server
    server.stop()


psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import seal  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402


@pytest.fixture
def admin(fresh_db):
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        yield conn


def add_events(conn, n, start=0):
    for i in range(start, start + n):
        conn.execute(
            "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key, actor,"
            " payload)"
            " VALUES (gen_random_uuid(), %s, now() - interval '1 minute', 'server_approved', %s,"
            " 'root', %s)",
            (INSTANCE, f"server:s{i}:1:server_approved", json.dumps({"server_id": f"s{i}"})),
        )
    seal.seal_once(conn, INSTANCE)


def target(conn, name="t1", kind="hec", endpoint="", secret_ref=None, from_start=True, **opt):
    siem.add(
        conn,
        INSTANCE,
        name=name,
        kind=kind,
        endpoint=endpoint,
        secret_ref=secret_ref,
        options=opt,
        from_start=from_start,
        created_by="root",
    )


def job(conn, minutes=15):
    return SimpleNamespace(
        conn=conn,
        instance_id=INSTANCE,
        checkpoint=lambda: None,
        settings=SimpleNamespace(siem_alert_minutes=minutes),
    )


def row(conn, name="t1"):
    return fetchone(conn, "SELECT * FROM mint.siem_targets WHERE name = %s", (name,))


def release(conn, name="t1"):
    conn.execute("UPDATE mint.siem_targets SET next_attempt_at = NULL WHERE name = %s", (name,))


def test_delivers_in_order_with_token_and_moves_the_cursor(admin, collector):
    add_events(admin, 3)
    target(admin, endpoint=collector.url, secret_ref="env:T_TOKEN")
    env = {"T_TOKEN": "tok-1"}
    siem.run(job(admin), env)
    headers, _ = collector.requests[0]
    assert headers["Authorization"] == "Splunk tok-1"
    assert len(collector.ids()) == 3
    t = row(admin)
    assert (t["cursor_seq"], t["sent_total"], t["last_error"], t["failing_since"]) == (
        3,
        3,
        None,
        None,
    )
    assert t["last_delivered_at"] is not None
    siem.run(job(admin), env)  # 새 사건이 없으면 보내지 않는다
    assert len(collector.requests) == 1
    add_events(admin, 1, start=3)
    siem.run(job(admin), env)
    assert len(collector.ids()) == 4 and row(admin)["cursor_seq"] == 4


def test_a_new_target_starts_after_the_existing_events(admin, collector):
    add_events(admin, 2)
    target(admin, endpoint=collector.url, from_start=False)
    siem.run(job(admin), {})
    assert collector.requests == []
    add_events(admin, 1, start=2)
    siem.run(job(admin), {})
    assert len(collector.ids()) == 1


def test_batches_are_bounded(admin, collector, monkeypatch):
    monkeypatch.setattr(siem, "BATCH", 2)
    add_events(admin, 5)
    target(admin, endpoint=collector.url)
    siem.run(job(admin), {})
    assert [len(b.decode().splitlines()) for _, b in collector.requests] == [2, 2, 1]
    assert row(admin)["cursor_seq"] == 5


def test_failure_keeps_the_cursor_backs_off_then_redelivers_at_least_once(admin, collector):
    add_events(admin, 2)
    target(admin, endpoint=collector.url)
    collector.status = 503  # 받은 뒤 오류로 답한다: 수신 쪽은 사건을 이미 가졌다
    siem.run(job(admin), {})
    t = row(admin)
    assert (t["cursor_seq"], t["last_error"], t["consecutive_failures"]) == (0, "http_503", 1)
    assert t["failing_since"] is not None and t["next_attempt_at"] is not None
    siem.run(job(admin), {})  # 백오프 중에는 다시 보내지 않는다
    assert len(collector.requests) == 1
    collector.status = 200
    release(admin)
    siem.run(job(admin), {})
    ids = collector.ids()
    assert len(ids) == 4 and len(set(ids)) == 2  # 같은 사건이 다시 간다(중복 제거는 수신 쪽)
    t = row(admin)
    assert (t["cursor_seq"], t["consecutive_failures"], t["failing_since"]) == (2, 0, None)
    assert t["failed_total"] == 2


def test_long_failure_opens_one_alert_and_recovery_closes_it(admin, collector):
    add_events(admin, 1)
    target(admin, endpoint=collector.url)
    collector.status = 500
    for _ in range(3):
        release(admin)
        siem.run(job(admin, minutes=0), {})
    opened = fetchall(admin, "SELECT * FROM mint.alerts WHERE kind = 'siem_forward_failing'")
    assert len(opened) == 1 and opened[0]["count"] == 1  # 되풀이해도 한 건, 횟수도 그대로
    assert opened[0]["subject"]["target"] == "t1"
    collector.status = 200
    release(admin)
    siem.run(job(admin, minutes=0), {})
    alert = fetchone(admin, "SELECT status FROM mint.alerts WHERE kind = 'siem_forward_failing'")
    assert alert["status"] == "resolved"


def test_no_alert_before_the_threshold(admin, collector):
    add_events(admin, 1)
    target(admin, endpoint=collector.url)
    collector.status = 500
    siem.run(job(admin, minutes=15), {})
    assert fetchall(admin, "SELECT 1 FROM mint.alerts WHERE kind = 'siem_forward_failing'") == []


def test_missing_secret_fails_without_sending(admin, collector):
    add_events(admin, 1)
    target(admin, endpoint=collector.url, secret_ref="env:NOPE")
    siem.run(job(admin), {})
    assert row(admin)["last_error"] == "secret_missing" and collector.requests == []


def test_elastic_item_failure_is_a_failure_but_duplicates_are_not(admin):
    reply = {"errors": True, "items": [{"create": {"status": 409}}, {"create": {"status": 400}}]}
    server = Collector(body=json.dumps(reply).encode())
    try:
        add_events(admin, 1)
        target(admin, kind="elastic", endpoint=server.url)
        siem.run(job(admin), {})
        assert row(admin)["last_error"] == "elastic_item_400"
        server.reply = json.dumps({"errors": True, "items": [{"create": {"status": 409}}]}).encode()
        release(admin)
        siem.run(job(admin), {})
        assert row(admin)["cursor_seq"] == 1
    finally:
        server.stop()


def test_otlp_posts_json_logs(admin, collector):
    add_events(admin, 2)
    target(admin, kind="otlp", endpoint=collector.url, secret_ref="env:K")
    siem.run(job(admin), {"K": "bearer-1"})
    headers, body = collector.requests[0]
    assert headers["Authorization"] == "Bearer bearer-1"
    assert len(json.loads(body)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]) == 2


class Tcp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                chunks = []
                while chunk := self.request.recv(4096):
                    chunks.append(chunk)
                self.server.data += b"".join(chunks)

        super().__init__((LOOPBACK, 0), Handler)
        self.data = b""
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"tcp://{LOOPBACK}:{self.server_address[1]}"


def frames(data):
    out = []
    while data:
        size, _, data = data.partition(b" ")
        out.append(data[: int(size)])
        data = data[int(size) :]
    return out


@pytest.mark.parametrize("kind", ["syslog", "cef"])
def test_syslog_over_tcp_uses_octet_counting_and_cef_wraps_the_line(admin, kind):
    add_events(admin, 2)
    server = Tcp()
    try:
        target(admin, kind=kind, endpoint=server.url)
        siem.run(job(admin), {})
    finally:
        server.shutdown()
        server.server_close()
    lines = frames(server.data)
    assert len(lines) == 2 and all(line.startswith(b"<109>1 ") for line in lines)
    assert (b"CEF:0|MINT" in lines[0]) == (kind == "cef")
    assert (b"[mint@32473 " in lines[0]) == (kind == "syslog")
    assert row(admin)["cursor_seq"] == 2


def test_syslog_over_udp_sends_one_datagram_per_event(admin):
    add_events(admin, 2)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOOPBACK, 0))
    sock.settimeout(5)
    try:
        target(admin, kind="syslog", endpoint=f"udp://{LOOPBACK}:{sock.getsockname()[1]}")
        siem.run(job(admin), {})
        got = [sock.recv(65535) for _ in range(2)]
    finally:
        sock.close()
    assert all(b"server_approved" in g for g in got) and row(admin)["cursor_seq"] == 2


def test_test_request_is_handled_by_the_runner_and_reports_the_error_code(admin, collector):
    target(admin, endpoint=collector.url)
    assert siem.request_test(admin, INSTANCE, "t1") and not siem.request_test(admin, INSTANCE, "x")
    siem.run(job(admin), {})
    t = row(admin)
    assert t["last_test_at"] is not None and t["last_test_error"] is None
    assert json.loads(collector.requests[0][1])["event"]["kind"] == "siem_test"
    siem.run(job(admin), {})  # 같은 요청은 한 번만 처리한다
    assert len(collector.requests) == 1
    dead = socket.socket()
    dead.bind((LOOPBACK, 0))
    port = dead.getsockname()[1]
    dead.close()
    target(admin, name="t2", endpoint=f"http://{LOOPBACK}:{port}")
    siem.request_test(admin, INSTANCE, "t2")
    siem.run(job(admin), {})
    assert row(admin, "t2")["last_test_error"] == "connection_refused"


def test_listing_hides_the_secret_and_the_path(admin):
    add_events(admin, 3)
    target(
        admin,
        endpoint="https://s.test:8088/services/collector/event?k=1",
        secret_ref="env:T_TOKEN",
        from_start=False,
    )
    (t,) = siem.listing(admin, INSTANCE)
    assert (t["address"], t["secret_source"], t["backlog"]) == ("https://s.test:8088", "env", 0)


def test_syslog_targets_refuse_a_token(admin):
    with pytest.raises(siem.ControlError):
        target(admin, kind="syslog", endpoint="tls://s.test", secret_ref="env:X")

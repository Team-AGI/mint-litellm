"""자체 방어 검증기: 승인된 읽기 도구에 합성 위험 입력을 보내 정책 집행을 원장으로 확인한다.

호출은 시험 전용 키(운영자가 미리 만든 ``mint-verify-`` 키)로 게이트웨이를 거쳐 보내고, 판정은
호출자가 받은 응답과 원장의 ``decision_evaluated``(결과 쪽은 ``call_response_received``)를
기대와 대조해 낸다. 검증기는 승인을 만들거나 바꾸지 않는다. 읽기 도구만 부르고,
페이로드는 합성 값이며 표식을 담는다.
"""

import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from mint_litellm.control import alerts
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.defense_profile import (
    BLOCKED,
    CASES,
    PROFILE_VERSION,
    RESULT_CASES,
    RESULT_TOOL,
    SLOT_NAMES,
    payload_is_safe,
)
from mint_litellm.control.errors import ControlError
from mint_litellm.types.events import AlertKind, EventKind
from mint_litellm.types.ids import new_uuid7

PASS, FAIL, WARN, SKIPPED = "pass", "fail", "warn", "skipped"
MAX_CALLS = 60
BLOCK_MARK = "MINT-"
MASK_MARK = "[MASKED:"
_REFERENCE = re.compile(r"[0-9a-f]{8}-[0-9a-f-]{27}:[1-9][0-9]{0,8}")
_FILL = {"string": "MINT-VERIFY", "integer": 1, "number": 1, "boolean": False, "array": [],
         "object": {}}


@dataclass
class Call:
    id: str
    group: str
    doc: str
    tool: str
    arg: str
    arguments: dict[str, Any]
    expect: str
    policies: tuple[str, ...]
    result_side: bool = False


@dataclass
class Plan:
    calls: list[Call] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)


def _strings(schema: dict) -> list[str]:
    """페이로드를 넣을 수 있는 문자열 칸(열거형 제외). 이름 순이라 매번 같다."""
    props = (schema or {}).get("properties") or {}
    out = []
    for name in sorted(props):
        spec = props[name] if isinstance(props[name], dict) else {}
        kinds = spec.get("type")
        kinds = kinds if isinstance(kinds, list) else [kinds]
        if "string" in kinds and "enum" not in spec:
            out.append(name)
    return out


def pick_arg(schema: dict, slot: str) -> str | None:
    """칸 종류에 이름이 맞는 문자열 인자를 먼저, 없으면 이름 순 첫 문자열 인자를 고른다."""
    names = _strings(schema)
    for hint in SLOT_NAMES[slot]:
        for name in names:
            if name.lower() == hint:
                return name
    for hint in SLOT_NAMES[slot]:
        for name in names:
            if hint in name.lower():
                return name
    return names[0] if names else None


def build_arguments(schema: dict, arg: str, value: str) -> dict[str, Any] | None:
    """필수 인자는 유형 기본값(열거형은 첫 값)으로 채운다. 채울 수 없으면 None."""
    props = (schema or {}).get("properties") or {}
    out: dict[str, Any] = {arg: value}
    for name in schema.get("required") or []:
        if name in out:
            continue
        spec = props.get(name) if isinstance(props.get(name), dict) else {}
        if spec.get("enum"):
            out[name] = spec["enum"][0]
            continue
        kind = spec.get("type")
        kind = kind[0] if isinstance(kind, list) and kind else kind
        if kind not in _FILL:
            return None
        out[name] = _FILL[kind]
    return out


def _skip(plan: Plan, case_id: str, group: str, doc: str, why: str) -> None:
    plan.skipped.append({"id": case_id, "group": group, "doc": doc, "status": SKIPPED,
                         "note": why})


def make_plan(
    tools: list[dict], marker: str, *, allowed_host: str = "", test_server: bool = False,
    max_calls: int = MAX_CALLS,
) -> Plan:
    """승인된 읽기 도구에서 시험 호출 계획을 만든다. 도구마다 이름 순 첫 칸을 쓰므로 결정적이다."""
    reads = sorted(
        (t for t in tools if t["action_type"] == "read"), key=lambda t: t["tool"]
    )
    parsed = [(t["tool"], json.loads(t["canonical_text"]).get("input_schema") or {}) for t in reads]
    plan = Plan()
    for case in CASES:
        if case.needs_allowed_host and not allowed_host:
            _skip(plan, case.id, case.group, case.doc, "승인 목적지를 --allowed-host로 주지 않음")
            continue
        value = case.payload(marker, allowed_host)
        if not payload_is_safe(value, allowed_host):  # 시험집이 바뀌어도 외부로 나가지 않게
            _skip(plan, case.id, case.group, case.doc, "안전하지 않은 목적지라 보내지 않음")
            continue
        for tool, schema in parsed:
            arg = pick_arg(schema, case.slot)
            args = build_arguments(schema, arg, value) if arg else None
            if args is not None:
                plan.calls.append(Call(case.id, case.group, case.doc, tool, arg, args,
                                       case.expect, case.policies))
                break
        else:
            _skip(plan, case.id, case.group, case.doc, "문자열 인자가 있는 읽기 도구가 없음")
    result_tool = next((t for t, _ in parsed if t == RESULT_TOOL), None)
    for cid, kind, where, expect, policy in RESULT_CASES:
        doc = f"결과 쪽 {kind}({where})"
        if not test_server:
            _skip(plan, cid, "result", doc, "시험 서버가 아니라 실행하지 않음(--test-server)")
        elif result_tool is None:
            _skip(plan, cid, "result", doc, f"읽기 도구 {RESULT_TOOL}이 없음")
        else:
            plan.calls.append(Call(cid, "result", doc, result_tool, "kind",
                                   {"kind": kind, "where": where, "marker": marker}, expect,
                                   (policy,), result_side=True))
    if len(plan.calls) > max_calls:
        for c in plan.calls[max_calls:]:
            _skip(plan, c.id, c.group, c.doc, "서버당 호출 상한 초과")
        plan.calls = plan.calls[:max_calls]
    return plan


# --- 게이트웨이 호출 ------------------------------------------------------------------------


def key_id_of(key: str) -> str:
    """원장 판정 사건의 키 식별자(LiteLLM 키 토큰, 키의 SHA-256 16진수)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def list_names(gateway: str, key: str, server_id: str) -> dict[str, str]:
    """게이트웨이가 시험 키에 보여 주는 도구 이름(접두사 포함)을 원래 이름으로 되짚는다."""
    reply = httpx.get(f"{gateway.rstrip('/')}/mcp-rest/tools/list", params={"server_id": server_id},
                      headers={"Authorization": f"Bearer {key}"}, timeout=30)
    reply.raise_for_status()
    tools = reply.json().get("tools") or []
    return {t["name"]: t["name"] for t in tools if isinstance(t, dict) and t.get("name")}


def call_gateway(gateway: str, key: str, server_id: str, name: str, arguments: dict) -> dict:
    """한 호출. ``{status, text, blocked}``만 돌려주고 응답 본문 전체는 남기지 않는다."""
    try:
        reply = httpx.post(
            f"{gateway.rstrip('/')}/mcp-rest/tools/call",
            headers={"Authorization": f"Bearer {key}"},
            json={"server_id": server_id, "name": name, "arguments": arguments}, timeout=60,
        )
        status, text = reply.status_code, reply.text
    except httpx.HTTPError as error:
        return {"status": None, "text": f"transport:{type(error).__name__}", "blocked": False,
                "reference": None}
    found = _REFERENCE.search(text)
    return {"status": status, "text": text, "reference": found.group(0) if found else None,
            "blocked": status >= 400 or BLOCK_MARK in text}


def resolve_name(names: dict[str, str], tool: str) -> str:
    """게이트웨이가 보여 준 이름 중 이 도구의 것(접두사 포함). 없으면 도구 이름 그대로."""
    for name in sorted(names):
        if name == tool or name.endswith(f"-{tool}"):
            return name
    return tool


# --- 원장 대조 ------------------------------------------------------------------------------


def _codes(payload: dict) -> list[str]:
    found = [str(i) for i in payload.get("policy_ids") or []]
    for item in [*(payload.get("findings") or []), payload.get("stop") or {}]:
        if isinstance(item, dict) and item.get("reason_code"):
            found.append(str(item["reason_code"]))
    return found


def _has_policy(codes: list[str], policies: tuple[str, ...]) -> bool:
    return any(p in c for p in policies for c in codes)


def judge(
    call: Call, client: dict, decision: dict | None, response: dict | None
) -> tuple[str, str]:
    """(pass|fail|warn, 한 줄 설명). 판정의 근거는 원장이고 호출자 응답은 교차 확인이다."""
    if decision is None:
        return FAIL, "원장에 판정 사건이 없음"
    blocked_in_ledger = decision.get("enforced_action") == "block"
    codes = _codes(decision)
    if call.result_side:
        if blocked_in_ledger:
            return FAIL, "호출 단계에서 막힘(결과 쪽을 확인하지 못함)"
        if response is None:
            return FAIL, "원장에 응답 사건이 없음"
        out = [str(i) for i in response.get("output_findings") or []]
        text = client["text"]
        if call.expect == BLOCKED:
            if BLOCK_MARK not in text:
                return FAIL, "막혀야 하는 결과가 호출자에게 전달됨"
            if not _has_policy(out, call.policies):
                return WARN, f"막혔으나 정책 기록이 다름({','.join(out) or '없음'})"
            return PASS, "결과가 막힘"
        if MASK_MARK not in text:
            return FAIL, "가려져야 하는 값이 호출자에게 전달됨"
        if not response.get("sensitive_findings"):
            return WARN, "가려졌으나 응답 사건에 종류별 건수가 없음"
        return PASS, "값이 가려짐"
    if call.expect == BLOCKED:
        if not blocked_in_ledger:
            return FAIL, "막혀야 하는데 허용됨"
        if not client["blocked"]:
            return FAIL, "원장은 차단인데 호출자에게는 통과함"
        if not _has_policy(codes, call.policies):
            return WARN, f"막혔으나 사유가 다름({','.join(codes) or '없음'})"
        return PASS, "차단"
    if blocked_in_ledger or client["blocked"]:
        return FAIL, f"허용되어야 하는데 막힘(과차단 {','.join(codes) or '사유 없음'})"
    return PASS, "허용"


def _fetch_events(conn, instance: str, key_id: str, since, calls_made: int, wait: float,
                  sleep: Callable[[float], None], commit: Callable[[], None]) -> list[dict]:
    deadline = time.monotonic() + wait
    while True:
        rows = fetchall(
            conn,
            "SELECT invocation_id, attempt_id, payload FROM mint.events WHERE instance_id = %s"
            " AND kind = 'decision_evaluated' AND payload->'principal'->>'key_id' = %s"
            " AND inserted_at >= %s ORDER BY inserted_at, event_id",
            (instance, key_id, since),
        )
        commit()
        if len(rows) >= calls_made or time.monotonic() >= deadline:
            return rows
        sleep(0.5)


def correlate(calls: list[Call], clients: list[dict], rows: list[dict]) -> list[dict | None]:
    """호출마다 판정 사건 하나. 응답의 참조가 있으면 그것으로, 없으면 도구가 같은 앞쪽 미사용 사건.

    호출은 순서대로 하나씩 보내므로 같은 도구의 사건 순서가 호출 순서와 같다.
    """
    by_ref = {f"{r['invocation_id']}:{r['attempt_id']}": r for r in rows}
    used: set[str] = set()
    out: list[dict | None] = [None] * len(calls)
    for i, client in enumerate(clients):
        ref = client.get("reference")
        if ref in by_ref and ref not in used:
            used.add(ref)
            out[i] = by_ref[ref]
    for i, call in enumerate(calls):
        if out[i] is not None:
            continue
        for r in rows:
            ref = f"{r['invocation_id']}:{r['attempt_id']}"
            tool = str(r["payload"].get("tool") or "")
            if ref not in used and (tool == call.tool or tool.endswith(f"-{call.tool}")):
                used.add(ref)
                out[i] = r
                break
    return out


def run_verify(
    ctx: Context,
    *,
    server_id: str,
    key: str,
    gateway: str,
    allowed_host: str = "",
    test_server: bool = False,
    max_calls: int = MAX_CALLS,
    wait: float = 15.0,
    caller: Callable[..., dict] = call_gateway,
    namer: Callable[..., dict[str, str]] = list_names,
    sleep: Callable[[float], None] = time.sleep,
    commit: Callable[[], None] | None = None,
) -> dict:
    conn, instance = ctx.conn, ctx.instance_id
    commit = commit or conn.commit  # 다른 연결이 쓴 원장 행을 보려면 읽기 사이에 끝내야 한다
    if not fetchone(conn, "SELECT 1 AS x FROM mint.servers WHERE instance_id = %s"
                    " AND server_id = %s", (instance, server_id)):
        raise ControlError(f"서버가 없습니다: {server_id}")
    tools = fetchall(
        conn,
        "SELECT tool, action_type, canonical_text FROM mint.tool_contracts WHERE instance_id = %s"
        " AND server_id = %s AND status = 'approved'",
        (instance, server_id),
    )
    run_id = str(new_uuid7())
    marker = f"MINT-VERIFY-{run_id.replace('-', '')[-12:]}"
    plan = make_plan(tools, marker, allowed_host=allowed_host, test_server=test_server,
                     max_calls=max_calls)
    if not plan.calls:
        raise ControlError("보낼 호출이 없습니다. 승인된 읽기 도구와 문자열 인자가 필요합니다.")
    since = fetchone(conn, "SELECT clock_timestamp() AS t")["t"]
    commit()
    names = namer(gateway, key, server_id)
    clients = []
    # ponytail: 순차 호출(동시 1). 원장 대조가 호출 순서에 기대므로 동시 2는 참조 회신을 확인한 뒤.
    for call in plan.calls:
        clients.append(caller(gateway, key, server_id, resolve_name(names, call.tool),
                              call.arguments))
    key_id = key_id_of(key)
    rows = _fetch_events(conn, instance, key_id, since, len(plan.calls), wait, sleep, commit)
    matched = correlate(plan.calls, clients, rows)
    responses = {}
    if matched:
        for r in fetchall(
            conn,
            "SELECT invocation_id, attempt_id, payload FROM mint.events WHERE instance_id = %s"
            " AND kind = 'call_response_received' AND invocation_id = ANY(%s)",
            (instance, [m["invocation_id"] for m in matched if m]),
        ):
            responses[f"{r['invocation_id']}:{r['attempt_id']}"] = r["payload"]
        commit()
    results = []
    for call, client, row in zip(plan.calls, clients, matched, strict=True):
        ref = f"{row['invocation_id']}:{row['attempt_id']}" if row else None
        status, note = judge(call, client, row["payload"] if row else None, responses.get(ref))
        results.append({"id": call.id, "group": call.group, "doc": call.doc, "tool": call.tool,
                        "arg": call.arg, "expect": call.expect, "status": status, "note": note,
                        "reference": ref})
    results.extend(plan.skipped)
    counts = {s: sum(1 for r in results if r["status"] == s) for s in (PASS, FAIL, WARN, SKIPPED)}
    failed = [r["id"] for r in results if r["status"] == FAIL]
    ctx.emit(
        EventKind.DEFENSE_VERIFY_RUN, run_id, 1,
        {"run_id": run_id, "server_id": server_id, "profile": "default",
         "profile_version": PROFILE_VERSION, "key_id": key_id, "calls": len(plan.calls),
         "counts": counts, "failed": failed},
    )
    dedup = f"{AlertKind.DEFENSE_VERIFY_FAILED.value}:{server_id}"
    if failed:
        alerts.raise_alert(
            conn, instance, kind=AlertKind.DEFENSE_VERIFY_FAILED.value, severity="high",
            dedup_key=dedup,
            subject={"server_id": server_id, "run_id": run_id, "failed": len(failed),
                     "cases": failed},
        )
    else:
        alerts.resolve(conn, instance, dedup)
    return {"run_id": run_id, "server_id": server_id, "profile": "default",
            "profile_version": PROFILE_VERSION, "marker": marker, "counts": counts,
            "results": results}

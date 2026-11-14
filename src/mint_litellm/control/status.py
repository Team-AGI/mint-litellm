"""``status``: 모드, 정책 판본, 경보, 관측 항목."""

from datetime import datetime, timedelta
from typing import Any

from mint_litellm.compat import capabilities
from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.control import approvals, checks, settings_store, todo
from mint_litellm.control.config import ControlConfig
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.policy_check import PolicyState
from mint_litellm.control.services import reads
from mint_litellm.types.events import AlertKind, EventKind
from mint_litellm.types.settings import OBSERVATION_ITEMS, Mode, effective_mode

EXPIRY_WARNING = timedelta(days=7)


def _shadow(ctx: Context) -> dict[str, Any] | None:
    shadow = reads.policy_shadow(ctx.conn, ctx.instance_id)
    if shadow is None:
        return None
    return {
        "version": shadow["version_id"],
        "evaluated": shadow["stats"]["evaluated"],
        "errors": shadow["stats"]["errors"],
        "skipped": shadow["stats"]["skipped"],
        **shadow["totals"],
    }


def collect(
    ctx: Context,
    cfg: ControlConfig,
    litellm: LiteLLMAdmin | None,
    config: dict | None,
    env: dict[str, str],
    policy_state: PolicyState | None = None,
) -> dict[str, Any]:
    stored = settings_store.load(ctx.conn, ctx.instance_id)
    active = fetchone(
        ctx.conn,
        "SELECT id, activated_at FROM mint.policy_versions"
        " WHERE instance_id = %s AND status = 'active'",
        (ctx.instance_id,),
    )
    servers = {
        r["status"]: r["n"]
        for r in fetchall(
            ctx.conn,
            "SELECT status, count(*) AS n FROM mint.servers WHERE instance_id = %s GROUP BY status",
            (ctx.instance_id,),
        )
    }
    alerts: list[dict[str, Any]] = [
        {
            "kind": AlertKind.APPROVAL_EXPIRING.value,
            "approval_id": str(a["id"]),
            "server_id": a["server_id"],
            "valid_until": a["valid_until"].isoformat(),
        }
        for a in approvals.expiring_approvals(ctx, EXPIRY_WARNING)
    ]
    alerts.extend(_mismatch_alerts(ctx))
    if policy_state is not None and policy_state.state == "mismatch":
        alerts.append({"kind": "policy_bundle_mismatch", "version": policy_state.version})
    observations: dict[str, Any] = {}
    if litellm is not None:
        report = checks.run_checks(config, env, litellm, replicas=cfg.replicas,
                                   compat_probe=lambda: None)
        observations = report.observations
        names: dict[str, int] = {}
        for entry in litellm.list_servers():
            for label in {entry.get("server_name"), entry.get("alias")} - {None, ""}:
                names[label] = names.get(label, 0) + 1
        alerts.extend(
            {"kind": AlertKind.SERVER_IDENTITY_CONFLICT.value, "name": name}
            for name, count in sorted(names.items()) if count > 1
        )
    elif config is not None:
        observations = checks.run_checks(config, env, None, compat_probe=lambda: None).observations
    ceiling = cfg.mode_ceiling
    found = compat.litellm_assessment()
    return {
        "litellm_compat": {
            "version": found.version,
            "grade": found.grade,
            "tested": found.tested,
            "missing": list(found.missing),
            "degraded": capabilities.degraded_findings(found),
            "affected_policies": list(capabilities.affected_policies(found.grade)),
        },
        "instance_id": ctx.instance_id,
        "mode": {
            "stored": stored["mode"],
            "ceiling": ceiling.value,
            "effective": effective_mode(ceiling, Mode(stored["mode"])).value,
        },
        "default_org_id": stored["default_org_id"],
        "policy_version": None if active is None else active["id"],
        "policy_shadow": _shadow(ctx),
        "policy_bundle": None
        if policy_state is None
        else {"state": policy_state.state, "detail": policy_state.detail},
        "servers": servers,
        "enforcement": enforcement_states(ctx),
        "alerts": alerts,
        "todo": todo.collect(ctx.conn, ctx.instance_id),
        "observations": {name: observations.get(name, "확인 불가") for name in OBSERVATION_ITEMS},
    }


def _failed_items(value: Any) -> list[dict[str, Any]]:
    """실패 항목은 ``{"item", "name", "detail"}`` 객체의 목록이다. 다른 형식이어도 죽지 않는다."""
    if not isinstance(value, list):
        return []
    items = []
    for entry in value:
        if isinstance(entry, dict):
            items.append(entry)
        else:
            items.append({"name": str(entry), "detail": ""})
    return items


def enforcement_states(ctx: Context) -> list[dict[str, Any]]:
    """워커마다 가장 최근의 ``enforcement_verified``·``enforcement_unverified`` 한 건.

    워커는 ``worker_id``(호스트 이름:프로세스 번호)로 묶으므로 재시작 전후는 한 줄이다. 줄마다 전환
    시각과 실행 식별자(사건 키의 실행 uuid)를 함께 보인다. 표시는 최근 전환이며 그 워커가 지금
    살아 있다는 뜻이 아니다.
    """
    rows = fetchall(
        ctx.conn,
        "SELECT DISTINCT ON (payload->>'worker_id') kind, inserted_at, source_key, payload"
        " FROM mint.events WHERE instance_id = %s"
        " AND kind IN (%s, %s)"
        " ORDER BY payload->>'worker_id', inserted_at DESC, event_id DESC",
        (
            ctx.instance_id,
            EventKind.ENFORCEMENT_VERIFIED.value,
            EventKind.ENFORCEMENT_UNVERIFIED.value,
        ),
    )
    states = []
    for row in rows:
        payload = row["payload"] if isinstance(row["payload"], dict) else {}
        passed = row["kind"] == EventKind.ENFORCEMENT_VERIFIED.value
        failed = _failed_items(payload.get("failed"))
        parts = str(row["source_key"]).split(":")
        states.append(
            {
                "worker_id": str(payload.get("worker_id") or "-"),
                "passed": passed,
                "failed": failed,
                "litellm": payload.get("litellm") if isinstance(payload.get("litellm"), dict)
                else None,
                "run_id": parts[1] if len(parts) > 1 else None,
                "last_transition_at": row["inserted_at"].isoformat(),
                "payload": payload,
            }
        )
    return sorted(states, key=lambda s: s["worker_id"])


# 한 번 기동한 워커는 거의 동시에 점검을 마친다. 가장 최근 전환에서 이 시간보다 더 앞선 워커는
# 업그레이드·재시작 전의 것으로 본다.
BOOT_WINDOW = timedelta(minutes=15)


def split_live_workers(states: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """(가장 최근 기동의 워커, 이전 기동에서 남은 워커 수). 워커는 전환 때만 보고하므로 보고가
    가장 최근 전환에서 ``BOOT_WINDOW`` 안인 것만 지금의 워커로 센다."""
    if not states:
        return [], 0
    newest = max(datetime.fromisoformat(s["last_transition_at"]) for s in states)
    live = [
        s for s in states if newest - datetime.fromisoformat(s["last_transition_at"]) <= BOOT_WINDOW
    ]
    return live, len(states) - len(live)


def _mismatch_alerts(ctx: Context) -> list[dict[str, Any]]:
    """플러그인이 관측한 서버 계약 불일치. 그 뒤 서버를 다시 등록하면 해소된 것으로 본다."""
    rows = fetchall(
        ctx.conn,
        "SELECT DISTINCT ON (e.payload->>'server_id') e.payload->>'server_id' AS server_id,"
        " e.payload->'fields' AS fields, e.inserted_at FROM mint.events e"
        " WHERE e.instance_id = %s AND e.kind = 'server_identity_mismatch_observed'"
        " AND e.inserted_at > COALESCE((SELECT max(r.inserted_at) FROM mint.events r"
        " WHERE r.instance_id = e.instance_id AND r.kind = 'server_registered'"
        " AND r.payload->>'server_id' = e.payload->>'server_id'), '-infinity')"
        " ORDER BY e.payload->>'server_id', e.inserted_at DESC",
        (ctx.instance_id,),
    )
    return [
        {
            "kind": "server_identity_mismatch_observed",
            "server_id": r["server_id"],
            "fields": r["fields"] if isinstance(r["fields"], list) else [],
            "observed_at": r["inserted_at"].isoformat(),
        }
        for r in rows
    ]


def shadow_line(shadow: dict[str, Any]) -> str:
    return (
        f"시험 판본: {shadow['version']} (평가 {shadow['evaluated']}건, "
        f"허용에서 차단 {shadow['allow_to_deny']}건, 차단에서 허용 {shadow['deny_to_allow']}건, "
        f"그 밖의 변경 {shadow['other']}건, 오류 {shadow['errors']}건, "
        f"건너뜀 {shadow['skipped']}건)"
    )


def _compat_line(found: dict[str, Any] | None) -> str:
    if not found or found["version"] is None:
        return "LiteLLM: 확인 불가(이 환경에 설치되어 있지 않음)"
    line = f"LiteLLM: {found['version']} 등급 {found['grade']}"
    if not found["tested"]:
        line += " (검증되지 않은 판본)"
    if found["grade"] != "A":
        line += f" - 빠진 능력: {', '.join(found['missing'])}"
        line += (
            "; 저하 운용(MINT_ALLOW_DEGRADED_LITELLM)이 켜진 경우에만 B·C가 기동한다"
            if found["grade"] in ("B", "C")
            else "; 등급 A만 기동한다"
        )
    return line


def _degraded_lines(found: dict[str, Any] | None) -> list[str]:
    if not found or not found.get("degraded"):
        return []
    lines = [f"  저하 운용 - 보장하지 않는 것: {text}" for text in found["degraded"]]
    lines.append(f"  집행이 약해지는 정책: {', '.join(found['affected_policies'])}")
    return lines


def render(info: dict[str, Any]) -> str:
    mode = info["mode"]
    lines = [
        f"배치: {info['instance_id']}",
        f"모드: {mode['effective']} (저장 {mode['stored']}, 환경 상한 {mode['ceiling']})",
        f"기본 조직: {info['default_org_id'] or '없음'}",
        f"정책 판본: {info['policy_version'] or '없음'}",
        _compat_line(info.get("litellm_compat")),
        *_degraded_lines(info.get("litellm_compat")),
        "서버: " + (", ".join(f"{k} {v}" for k, v in sorted(info["servers"].items())) or "없음"),
        "경보: " + ("없음" if not info["alerts"] else ""),
    ]
    for alert in info["alerts"]:
        detail = {k: v for k, v in alert.items() if k != "kind"}
        lines.append(f"  {alert['kind']} {detail}")
    shadow = info.get("policy_shadow")
    if shadow:
        lines.append(shadow_line(shadow))
    bundle = info.get("policy_bundle")
    if bundle and bundle["state"] != "none":
        label = {"match": "일치", "mismatch": "불일치", "unverified": "확인 불가"}[bundle["state"]]
        detail = f" ({bundle['detail']})" if bundle["detail"] else ""
        lines.append(f"정책 번들 내용: {label}{detail}")
    lines.append("집행 점검(워커별 최근 전환; 워커가 살아 있다는 뜻은 아님)")
    if not info["enforcement"]:
        lines.append("  기록 없음")
    for state in info["enforcement"]:
        if state["passed"]:
            lines.append(
                f"  {state['worker_id']}: 통과 {state['last_transition_at']}"
                f" 실행 {state['run_id'] or '-'}"
            )
        else:
            names = ", ".join(
                f"{item.get('name', '?')}: {item.get('detail', '')}" for item in state["failed"]
            ) or "원인 미상"
            lines.append(
                f"  {state['worker_id']}: 실패 {names} {state['last_transition_at']}"
                f" 실행 {state['run_id'] or '-'}"
            )
    lines.append("관측 항목")
    lines.extend(f"  {k}: {v}" for k, v in info["observations"].items())
    if info.get("todo"):
        lines.append(todo.render(info["todo"]))
    return "\n".join(lines)

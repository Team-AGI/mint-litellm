"""「시작하기」 점검표: 실제 상태에서 항목마다 완료·미완료·확인 필요를 계산한다."""

from typing import Any

from mint_litellm.console import labels
from mint_litellm.console.core import Actor, can
from mint_litellm.console.labels import Status
from mint_litellm.control import status as control_status
from mint_litellm.control import webhook_store
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.operators import SERVICE_ACCOUNTS

DONE = Status("완료", "ok")
OPEN = Status("미완료", "wait")
CHECK = Status("확인 필요", "error")


def _count(actor: Actor, sql: str, *args) -> int:
    return fetchone(actor.conn, sql, (actor.instance, *args))["n"]


def mark_time(actor: Actor, mark: str) -> Any:
    row = fetchone(
        actor.conn,
        "SELECT marked_at FROM mint.setup_marks WHERE instance_id = %s AND mark = %s",
        (actor.instance, mark),
    )
    return row["marked_at"] if row else None


def mark(conn, instance: str, name: str, by: str) -> None:
    conn.execute(
        "INSERT INTO mint.setup_marks (instance_id, mark, marked_by) VALUES (%s, %s, %s)"
        " ON CONFLICT (instance_id, mark) DO UPDATE SET marked_by = excluded.marked_by,"
        " marked_at = clock_timestamp()",
        (instance, name, by),
    )


def _item(key, title, status, line, href=None, action=None, **extra):
    return {
        "key": key,
        "title": title,
        "status": status,
        "line": line,
        "href": href,
        "action": action,
        **extra,
    }


def _gateway(workers) -> dict:
    info = next((w["litellm"] for w in workers if w["litellm"]), None)
    if not workers or info is None:
        return _item(
            "gateway", "게이트웨이 연결", OPEN, "복제본 보고가 아직 없습니다.", "/", "대시보드"
        )
    badge = labels.litellm_badge(info)
    status = DONE if badge.level == "ok" else CHECK
    return _item("gateway", "게이트웨이 연결", status, badge.text, "/", "대시보드")


def _policy(actor: Actor, workers) -> dict:
    active = _count(
        actor,
        "SELECT count(*) AS n FROM mint.policy_versions WHERE instance_id = %s"
        " AND status = 'active'",
    )
    if not active:
        return _item("policy", "정책 적용", OPEN, "적용된 정책 판본이 없습니다.", "/policy", "정책")
    if workers and all(w["passed"] for w in workers):
        return _item(
            "policy", "정책 적용", DONE, "정책 판본 적용, 집행 검증 통과", "/policy", "정책"
        )
    return _item(
        "policy",
        "정책 적용",
        CHECK,
        "집행 검증이 통과되지 않았습니다.",
        "/ledger?kind=enforcement_unverified",
        "검증 기록",
    )


def _servers(actor: Actor) -> dict:
    approved = _count(
        actor,
        "SELECT count(*) AS n FROM mint.servers WHERE instance_id = %s AND status = 'approved'",
    )
    total = _count(actor, "SELECT count(*) AS n FROM mint.servers WHERE instance_id = %s")
    if approved:
        return _item(
            "servers", "MCP 서버 신청·승인", DONE, f"승인된 MCP 서버 {approved}개",
            "/servers", "MCP 서버",
        )
    if total:
        return _item(
            "servers",
            "MCP 서버 신청·승인",
            CHECK,
            "승인된 MCP 서버가 없습니다.",
            "/approvals?tab=servers",
            "승인 센터",
        )
    if not can(actor, "intake create"):
        return _item(
            "servers", "MCP 서버 신청·승인", OPEN, "등록된 MCP 서버가 없습니다.",
            "/intakes", "도입 신청",
        )
    return _item(
        "servers", "MCP 서버 신청·승인", OPEN, "등록된 MCP 서버가 없습니다.",
        "/intakes/new", "신청 시작",
    )


def _approval_flow(actor: Actor) -> dict:
    """승인할 수 있는 사람: 관리자도 승인할 수 있으므로 관리자와 승인자를 함께 센다."""
    rows = fetchall(
        actor.conn,
        "SELECT role, count(*) AS n FROM mint.operators WHERE instance_id = %s"
        " AND role IN ('admin', 'approver') AND name <> 'root'"
        " AND name <> ALL(%s) AND coalesce(user_id, '') <> ALL(%s)"
        " AND (expires_at IS NULL OR expires_at > now()) GROUP BY role",
        (actor.instance, list(SERVICE_ACCOUNTS), list(SERVICE_ACCOUNTS)),
    )
    count = {r["role"]: r["n"] for r in rows}
    admins, approvers = count.get("admin", 0), count.get("approver", 0)
    if admins or approvers:
        line = f"승인할 수 있는 사람 {admins + approvers}명 · 관리자 {admins} · 승인자 {approvers}"
        return _item("approval", "승인자", DONE, line)
    return _item(
        "approval", "승인자", OPEN, "기본 관리자만 있습니다. 승인자를 따로 지정할 수 있습니다.",
        "/admin?tab=operators#operator-form", "승인자 지정", optional=True,
    )


def _alerts(actor: Actor) -> dict:
    """알림 주소와 시험 전송. 시험 전송까지 마쳐야 완료다(선택 항목)."""
    settings = webhook_store.effective(actor.config.stage2, actor.conn, actor.instance)
    tested = mark_time(actor, "webhook_test")
    if not settings.webhook_urls:
        return _item("alerts", "알림", OPEN, "알림 주소가 없습니다.", optional=True)
    if tested is None:
        return _item(
            "alerts", "알림", OPEN, "주소를 저장했습니다. 시험 전송으로 도착을 확인하십시오.",
            optional=True,
        )
    return _item("alerts", "알림", DONE, "시험 전송을 마쳤습니다.", optional=True)


def _endpoints(actor: Actor) -> dict:
    live = "revoked_at IS NULL AND coalesce(install_mode, '') <> 'removed'"
    total = _count(
        actor, f"SELECT count(*) AS n FROM mint.endpoint_installs WHERE instance_id = %s AND {live}"
    )
    fresh = _count(
        actor,
        "SELECT count(*) AS n FROM mint.endpoint_installs WHERE instance_id = %s"
        f" AND {live} AND reported_at > now() - interval '24 hours'",
    )
    gap = actor.config.kit_gap
    if gap and not fresh:
        return _item(
            "endpoint", "직원 PC 연결", CHECK,
            f"직원이 설치 명령을 만들 수 없습니다. 서버 설정이 빠졌습니다: {gap}",
        )
    if fresh:
        return _item(
            "endpoint",
            "직원 PC 연결",
            DONE,
            f"최근 24시간 보고 {fresh}대",
            "/endpoints",
            "엔드포인트",
        )
    if total:
        return _item(
            "endpoint",
            "직원 PC 연결",
            CHECK,
            "최근 24시간 보고가 없습니다.",
            "/endpoints",
            "엔드포인트",
        )
    return _item(
        "endpoint",
        "직원 PC 연결",
        OPEN,
        "연결된 PC가 없습니다. 각 PC에서 「내 단말」의 한 줄 설치 명령을 실행합니다.",
        "/staff/endpoint",
        "한 줄 설치 명령 받기",
    )


def _optional(actor: Actor) -> list[dict]:
    rules = _count(
        actor,
        "SELECT count(*) AS n FROM mint.call_approval_rules WHERE instance_id = %s"
        " AND status = 'active' AND action_class = 'read'",
    )
    reported = mark_time(actor, "audit_report")
    return [
        _item(
            "rule",
            "읽기 자동 승인 규칙",
            DONE if rules else OPEN,
            f"사용 중인 규칙 {rules}개" if rules else "읽기 동작 자동 승인 규칙이 없습니다.",
            "/approvals?tab=rules",
            "규칙",
            optional=True,
        ),
        _item(
            "report",
            "감사 보고서",
            DONE if reported else OPEN,
            "보고서를 한 번 만들었습니다." if reported else "만든 보고서가 없습니다.",
            "/reports/audit",
            "보고서",
            optional=True,
        ),
    ]


def _password(default_in_use: bool) -> dict:
    if default_in_use:
        return _item(
            "password", "기본 비밀번호 바꾸기", OPEN,
            "처음 로그인한 비밀번호를 그대로 쓰고 있습니다.",
            "/account/password", "비밀번호 바꾸기",
        )
    return _item(
        "password", "기본 비밀번호 바꾸기", DONE, "기본 비밀번호를 바꿨습니다.",
        "/account/password", "비밀번호",
    )


def _accounts(actor: Actor) -> dict:
    approved = _count(
        actor,
        "SELECT count(*) AS n FROM mint.signup_requests WHERE instance_id = %s"
        " AND status = 'approved'",
    )
    waiting = _count(
        actor,
        "SELECT count(*) AS n FROM mint.signup_requests WHERE instance_id = %s"
        " AND status = 'pending'",
    )
    people = _count(
        actor,
        "SELECT count(DISTINCT user_id) AS n FROM mint.endpoint_installs WHERE instance_id = %s",
    )
    if approved or people:
        return _item(
            "accounts", "사람 계정 등록", DONE, f"등록된 계정 {max(approved, people)}명",
            "/signup-requests", "가입 요청",
        )
    if waiting:
        return _item(
            "accounts", "사람 계정 등록", CHECK, f"승인을 기다리는 가입 요청 {waiting}건",
            "/signup-requests", "가입 요청",
        )
    return _item(
        "accounts", "사람 계정 등록", OPEN, "가입 요청을 승인하거나 LiteLLM에서 초대합니다.",
        "/signup-requests", "가입 요청",
    )


def steps(actor: Actor, default_password: bool = False) -> list[dict]:
    workers = control_status.enforcement_states(actor.ctx)
    return [
        _password(default_password),
        _accounts(actor),
        _endpoints(actor),
        _servers(actor),
        _gateway(workers),
        _policy(actor, workers),
        _approval_flow(actor),
        _alerts(actor),
        *_optional(actor),
    ]


def pending(items: list[dict]) -> int:
    return sum(1 for i in items if not i.get("optional") and i["status"] is not DONE)

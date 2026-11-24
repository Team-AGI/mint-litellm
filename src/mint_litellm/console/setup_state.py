"""「시작하기」 점검표: 실제 상태에서 항목마다 완료·미완료·확인 필요를 계산한다."""

from typing import Any

from mint_litellm.console import labels
from mint_litellm.console.core import Actor, can
from mint_litellm.console.labels import Status
from mint_litellm.control import status as control_status
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.operators import SERVICE_ACCOUNTS

DONE = Status("완료", "ok")
OPEN = Status("미완료", "wait")
CHECK = Status("확인 필요", "error")

INSTALL_COMMANDS = (
    ("리눅스", "tar -xzf mint-kit.tar.gz && ./install.sh"),
    ("윈도우", "install.cmd"),
)


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
    solo = _count(
        actor,
        "SELECT count(*) AS n FROM mint.operators WHERE instance_id = %s"
        " AND role IN ('admin', 'approver') AND name <> 'root'"
        " AND name <> ALL(%s) AND coalesce(user_id, '') <> ALL(%s)"
        " AND (expires_at IS NULL OR expires_at > now())",
        list(SERVICE_ACCOUNTS), list(SERVICE_ACCOUNTS),
    ) == 0
    approvers = _count(
        actor,
        "SELECT count(*) AS n FROM mint.operators WHERE instance_id = %s AND role = 'approver'"
        " AND (expires_at IS NULL OR expires_at > now())",
    )
    urls = actor.config.stage2.webhook_urls
    tested = mark_time(actor, "webhook_test")
    missing = []
    if not approvers:
        missing.append("승인자 없음")
    if not urls:
        missing.append("알림 주소 미설정")
    elif not tested:
        missing.append("시험 전송 전")
    if not missing:
        status = DONE
    elif not approvers and not urls:
        status = OPEN
    else:
        status = CHECK
    line = "승인자와 알림이 준비되었습니다." if not missing else " · ".join(missing)
    if not approvers:
        extra = {"href": "/admin", "action": "운영자"}
    elif urls and actor.role == "admin":
        extra = {"post": "/setup/webhook-test", "action": "시험 전송"}
    else:
        extra = {}
    if solo and not approvers and not urls:
        line = "기본 관리자가 직접 결정할 수 있습니다."
    return _item("approval", "알림·승인자", status, line, optional=solo, **extra)


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
    commands = {"commands": INSTALL_COMMANDS}
    if fresh:
        return _item(
            "endpoint",
            "직원 PC 연결",
            DONE,
            f"최근 24시간 보고 {fresh}대",
            "/endpoints",
            "엔드포인트",
            **commands,
        )
    if total:
        return _item(
            "endpoint",
            "직원 PC 연결",
            CHECK,
            "최근 24시간 보고가 없습니다.",
            "/endpoints",
            "엔드포인트",
            **commands,
        )
    return _item(
        "endpoint",
        "직원 PC 연결",
        OPEN,
        "설치된 엔드포인트가 없습니다.",
        "/staff/endpoint",
        "설치 묶음 받기",
        **commands,
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
        *_optional(actor),
    ]


def pending(items: list[dict]) -> int:
    return sum(1 for i in items if not i.get("optional") and i["status"] is not DONE)

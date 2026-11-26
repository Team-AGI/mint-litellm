"""화면 변경 경로(POST)별 최소 역할. 서버가 요청마다 확인하므로 폼을 직접 보내도 우회할 수 없다.

값 ``admin``은 관리자(Root 포함), ``approver``는 승인자 이상, ``any``는 로그인한 모든 운영자다.
표에 없는 변경 경로는 관리자만 쓸 수 있다(새 경로를 만들면 여기 적어야 한다).
"""

from fastapi import Depends, Request

from mint_litellm.console.core import UNSAFE, Actor, page_actor
from mint_litellm.control.errors import AdminCode, AdminError

ADMIN, APPROVER, ANY = "admin", "approver", "any"

ROUTE_ROLES: dict[str, str] = {
    # 접근·승인
    "/approvals": APPROVER,
    "/approvals/renew": ADMIN,
    "/approvals/dormant/keep": ADMIN,
    "/approvals/dormant/revoke": ADMIN,
    "/approvals/{approval_id}/recertify": ADMIN,
    "/approvals/{approval_id}/revoke": ADMIN,
    "/denials": APPROVER,
    "/denials/{denial_id}/lift": APPROVER,
    "/call-approval-rules": ADMIN,
    "/call-approval-rules/{rule_id}/disable": ADMIN,
    "/call-approvals/bulk/{decision}": APPROVER,
    "/call-approvals/{call_id}/{decision}": APPROVER,
    "/allowlists": ADMIN,
    "/allowlists/{allowlist_id}/lift": ADMIN,
    "/exceptions/{hold_id}/{decision}": APPROVER,
    "/key-blocks/{proposal_id}/{decision}": ADMIN,
    "/access-requests/{request_id}/resolve": APPROVER,
    "/access-requests/{request_id}/reject": APPROVER,
    # 기본 기능·사람 차단
    "/builtin-tools/block": ADMIN,
    "/builtin-tools/allow": ADMIN,
    "/people/block": ADMIN,
    "/people/unblock": ADMIN,
    "/people/operator": ADMIN,
    # 대시보드·정책
    "/ledger/{event_id}/block": APPROVER,
    "/ledger/denials/{denial_id}/undo": APPROVER,
    "/alerts/{alert_id}/acknowledge": ADMIN,
    "/policy/shadow/apply": ADMIN,
    "/policy/shadow/cancel": ADMIN,
    "/policy/mode": ADMIN,
    # 단말·설정
    "/endpoints/{alias}/pause": ADMIN,
    "/endpoints/{alias}/resume": ADMIN,
    "/endpoints/{alias}/reconnect": ADMIN,
    "/endpoints/apps/{app_id}/revoke": ADMIN,
    "/endpoints/{key_alias}/revoke": ADMIN,
    "/endpoints/revoke": ADMIN,
    "/operators/{name}/role": ADMIN,
    "/admin/operators/{name}/root": ADMIN,
    "/operators/{name}/chat-bind": ADMIN,
    "/operators/{name}/remove": ADMIN,
    "/admin/operators": ADMIN,
    "/admin/siem": ADMIN,
    "/admin/siem/{name}/test": ADMIN,
    "/admin/siem/{name}/remove": ADMIN,
    "/admin/backups": ADMIN,
    "/orgs": ADMIN,
    "/orgs/{org_id}/close": ADMIN,
    "/org-suggestions/rule": ADMIN,
    "/org-suggestions/{suggestion_id}/apply": ADMIN,
    "/org-suggestions/{suggestion_id}/ignore": ADMIN,
    "/setup/webhook": ADMIN,
    "/setup/webhook-test": ADMIN,
    "/account/password": ANY,
    # Root 화면(Root 여부는 각 화면이 다시 확인한다)
    "/root/halt": ADMIN,
    "/root/halt/lift": ADMIN,
    "/root/actions": ADMIN,
    "/root/actions/{action_id}/verify": ADMIN,
    "/people/{user_id}/lockout": ADMIN,
    "/people/{user_id}/unlock": ADMIN,
    "/people/{user_id}/sessions/end": ADMIN,
    # 서버·신청
    "/servers/{server_id}/tools/{operation}": ADMIN,
    "/servers/{server_id}/evidence": ADMIN,
    "/servers/{server_id}/suspend": ADMIN,
    "/servers/{server_id}/resume": ADMIN,
    "/servers/{server_id}/terminate": ADMIN,
    "/servers/{server_id}/relations/{relation_id}/terminate": ADMIN,
    "/servers/{server_id}/relations/{relation_id}/evidence": ADMIN,
    "/servers/{server_id}/relations/{relation_id}/finish": ADMIN,
    "/intakes": ADMIN,
    "/intakes/{intake_id}/withdraw": ADMIN,
    "/intakes/{intake_id}/requester": ADMIN,
    "/intakes/{intake_id}/inspect": APPROVER,
    "/intakes/{intake_id}/inspect-revoke": APPROVER,
    "/intakes/{intake_id}/evidence": ADMIN,
    "/intakes/{intake_id}/recheck": ADMIN,
    "/intakes/{intake_id}/decision": APPROVER,
    "/contracts/{server_id}/reapprove": ADMIN,
    "/contracts/{server_id}/approve-provisional": ADMIN,
}

_ALLOWED = {ADMIN: {"admin"}, APPROVER: {"admin", "approver"}, ANY: {"admin", "approver", "viewer"}}


def enforce_route_role(request: Request, actor: Actor = Depends(page_actor)) -> None:
    """변경 요청이면 이 경로의 최소 역할을 확인한다. 조회 요청은 건드리지 않는다."""
    if request.method not in UNSAFE:
        return
    route = request.scope.get("route")
    need = ROUTE_ROLES.get(getattr(route, "path", ""), ADMIN)
    if actor.role not in _ALLOWED[need]:
        label = "승인자 이상" if need == APPROVER else "관리자"
        raise AdminError(AdminCode.FORBIDDEN, f"{label}만 할 수 있는 작업입니다.")

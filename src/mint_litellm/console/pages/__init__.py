"""화면(서버 렌더링). 변경은 서비스 함수를 부르고, 실패하면 같은 화면에 오류를 보인다.

화면 모듈별로 라우터를 나누고 여기서 하나로 묶는다. 화면 경로를 바꾸면 구 경로는 이 파일의
``LEGACY``와 이동 핸들러가 303으로 새 경로에 넘겨, 이미 퍼진 링크가 계속 열리게 한다.
"""

from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages import approvals, dashboard, endpoints_admin, reports, servers
from mint_litellm.console.pages.common import see_other
from mint_litellm.control import links
from mint_litellm.control.errors import AdminCode, AdminError

router = APIRouter(dependencies=[Depends(require_csrf)])

# 구 화면 경로 -> (새 경로, 고정 쿼리)
LEGACY = {
    "/call-approvals": ("/approvals", {"tab": "calls"}),
    "/contracts": ("/servers", {"filter": "changed"}),
    "/revocations": ("/access", {"tab": "denials"}),
    "/endpoints/mcp": ("/endpoints", {"tab": "local-mcp"}),
}


def _move(path: str, params: dict[str, str]):
    def handler(request: Request):
        return see_other(request, path, **params)

    return handler


for old, (new, fixed) in LEGACY.items():
    router.add_api_route(old, _move(new, fixed), methods=["GET"], include_in_schema=False)


@router.get("/contracts/{server_id}", include_in_schema=False)
def contract_detail(server_id: str, request: Request):
    return see_other(request, f"/servers/{quote(server_id)}", tab="contract")


@router.get("/alerts/{alert_id}", include_in_schema=False)
def alert_detail(alert_id: str, request: Request):
    return see_other(request, "/alerts", open=alert_id)


@router.get("/approvals/new", include_in_schema=False)
def approval_form(request: Request, relation_id: str):
    rest = {k: v for k, v in request.query_params.items() if k != "relation_id"}
    query = "&".join(f"{k}={quote(v)}" for k, v in rest.items())
    target = f"/approvals/review/{quote(relation_id)}"
    return RedirectResponse(f"{target}?{query}" if query else target, status_code=303)


@router.get("/link/{token}")
def open_link(token: str, actor: Actor = Depends(page_actor)):
    """알림의 서명 링크. 해당 화면에서 항목을 미리 고르기만 하고 아무것도 승인하지 않는다."""
    key = actor.config.stage2.webhook_hmac_key
    parsed = links.parse(key, token) if key else None
    target = None
    if parsed is not None:
        kind, ref = parsed
        target = {
            "call": f"/approvals?tab=calls&focus={quote(ref)}",
            "recert": f"/access?tab=approvals&focus={quote(ref)}",
            "intake": f"/intakes/{quote(ref)}",
            "dormant": f"/access?tab=dormant&server={quote(ref)}",
        }.get(kind)
    if target is None:
        raise AdminError(AdminCode.NOT_FOUND, "링크가 만료되었거나 올바르지 않습니다.")
    return RedirectResponse(target, status_code=303)


for module in (dashboard, approvals, servers, endpoints_admin, reports):
    router.include_router(module.router)

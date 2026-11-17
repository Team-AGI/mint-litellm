"""화면 모듈이 함께 쓰는 보조 함수."""

from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from pydantic import ValidationError

from mint_litellm.console.core import STATUS, Actor, invalid_fields, screen_message
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.errors import AdminError, ControlError

Rebuild = Callable[..., Response]


def page_number(request: Request) -> int:
    value = request.query_params.get("page", "1")
    return int(value) if value.isdigit() else 1


def lines(text: str) -> list[str]:
    return [part.strip() for part in text.replace(",", "\n").splitlines() if part.strip()]


def act(
    actor: Actor, action: Callable[[], Any], ok: str, back: str, rebuild: Rebuild
) -> Response:
    """서비스 호출 하나. 성공하면 알림과 함께 목록으로, 실패하면 같은 화면에 오류를 보인다."""
    try:
        action()
    except ControlError as error:
        actor.conn.rollback()
        status = STATUS[error.code] if isinstance(error, AdminError) else 400
        return rebuild(error=screen_message(str(error)), status=status)
    except ValidationError as error:  # 항목 이름을 화면의 한글 이름으로 알린다
        actor.conn.rollback()
        fields = invalid_fields(error.errors())
        return rebuild(error=f"입력 값이 올바르지 않습니다: {fields}", status=400)
    except ValueError:  # 선택 목록에 없는 값 등 잘못된 폼 값
        actor.conn.rollback()
        return rebuild(error="입력 값이 올바르지 않습니다.", status=400)
    return RedirectResponse(f"{back}{'&' if '?' in back else '?'}ok={ok}", status_code=303)


def see_other(
    request: Request, path: str, drop: tuple[str, ...] = (), **params: str
) -> RedirectResponse:
    """구 경로의 화면 요청을 새 경로로 옮긴다. 요청에 붙은 나머지 쿼리는 그대로 이어 붙인다."""
    rest = {k: v for k, v in request.query_params.items() if k not in params and k not in drop}
    return RedirectResponse(f"{path}?{urlencode({**params, **rest})}", status_code=303)


def server_names(admin: Any) -> dict:
    """LiteLLM에 등록된 서버 식별자별 별칭. 읽지 못하면 비어 있다."""
    try:
        entries = admin.list_servers() if admin else []
    except ControlError:
        entries = []
    return {
        e.get("server_id") or e.get("id"): e.get("server_name") or e.get("alias") for e in entries
    }


def server_display(actor: Actor, rows: list[dict]) -> None:
    """등록된 이름과 계약 주소를 화면의 서버 행에 붙인다."""
    if not rows:
        return
    try:
        names = server_names(actor.litellm())
    except ControlError:  # 이 콘솔에 읽기 키가 없다
        names = {}
    addresses = {
        r["server_id"]: r["url"]
        for r in fetchall(
            actor.conn,
            "SELECT DISTINCT ON (server_id) server_id, url FROM mint.deployment_contracts "
            "WHERE instance_id = %s AND status IN ('candidate', 'approved') "
            "ORDER BY server_id, (status = 'candidate') DESC, id DESC",
            (actor.instance,),
        )
    }
    for row in rows:
        sid = row["server_id"]
        row["server_name"] = names.get(sid) or sid
        row["server_url"] = addresses.get(sid)

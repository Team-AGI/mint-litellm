"""LiteLLM 관리 API 쓰기 클라이언트(권한 동기화 전용).

읽기는 ``LiteLLMAdmin``을 그대로 쓰고, 쓰기는 이 모듈이 허용하는 경로·본문만 보낸다.

- 키·팀 갱신: ``/key/update``, ``/team/update``. 본문은 대상 식별자와
  ``object_permission{mcp_servers, mcp_tool_permissions}``뿐이다. LiteLLM은 두 값을 각각 통째로
  바꾸므로 언제나 전체 목록과 전체 맵을 보낸다. 다른 필드는 보내기 전에 거부한다.
- 서버: 승인·거절·고정·고정 해제 경로만 부른다. 서버 등록·수정·삭제·가져오기는 부르지 않는다.
- 모든 쓰기 직전에 ``before_write``를 부른다(되돌림 상태·임대 확인 자리, 예외를 내면 쓰지 않는다).
"""

import copy
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from mint_litellm.control.litellm_admin import LiteLLMAdmin, LiteLLMError, scrub
from mint_litellm.endpoint.routes import KIT_KEY_ROUTES

# 쓰기 허용 목록: (메서드, 경로 정규식). 서버 식별자 한 마디는 ``/``를 포함하지 않는다.
_SERVER = r"/v1/mcp/server/[^/]+"
WRITE_ROUTES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (method, re.compile(pattern))
    for method, pattern in (
        ("PUT", r"/v1/mcp/server"),  # 본문은 allow_all_keys 끄기뿐이다(아래 check_write)
        ("POST", r"/key/update"),
        ("POST", r"/team/update"),
        ("PUT", _SERVER + r"/approve"),
        ("PUT", _SERVER + r"/reject"),
        ("POST", _SERVER + r"/pin"),
        ("DELETE", _SERVER + r"/pin"),
    )
)

_ID_FIELD = {"/key/update": "key", "/team/update": "team_id"}
_PERMISSION_FIELDS = frozenset({"mcp_servers", "mcp_tool_permissions"})


class LiteLLMUnreachable(LiteLLMError):
    """연결·시간 초과. 응답을 받지 못했다."""

    code = "litellm_unreachable"


class LiteLLMHttpError(LiteLLMError):
    """LiteLLM이 2xx가 아닌 상태로 응답했다."""

    def __init__(self, message: str, status: int, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body  # 응답 본문(사유 판별용, 자격 열은 이미 지워진 값)
        self.code = f"litellm_http_{status}"


class LiteLLMForbidden(LiteLLMHttpError):
    """403(키가 팀 허용 서버를 넘는 경우 등) 또는 401."""


class WriteRefused(LiteLLMError):
    """허용 목록 밖의 경로나 본문이라 보내지 않았다."""

    code = "write_refused"


def check_write(method: str, path: str, body: Any) -> None:
    """보내기 전에 경로와 본문이 허용 범위인지 확인한다. 아니면 ``WriteRefused``."""
    if not any(m == method and pattern.fullmatch(path) for m, pattern in WRITE_ROUTES):
        raise WriteRefused(f"허용되지 않은 LiteLLM 쓰기 경로입니다: {method} {path}")
    if path == "/v1/mcp/server":
        if (
            not isinstance(body, dict)
            or set(body) != {"server_id", "allow_all_keys"}
            or not isinstance(body["server_id"], str)
            or not body["server_id"]
            or body["allow_all_keys"] is not False
        ):
            raise WriteRefused(
                "PUT /v1/mcp/server 본문은 {server_id, allow_all_keys: false}만 보낼 수 있습니다."
            )
        return
    if path.endswith("/reject"):
        if body is not None and (
            not isinstance(body, dict)
            or set(body) != {"review_notes"}
            or not isinstance(body["review_notes"], str)
        ):
            raise WriteRefused("거절 본문은 {review_notes: 문자열}만 보낼 수 있습니다.")
        return
    id_field = _ID_FIELD.get(path)
    if id_field is None:
        if body is not None:
            raise WriteRefused(f"{path}는 본문을 받지 않습니다.")
        return
    if not isinstance(body, dict) or set(body) != {id_field, "object_permission"}:
        raise WriteRefused(f"{path} 본문은 {id_field}와 object_permission만 가질 수 있습니다.")
    identifier, permission = body[id_field], body["object_permission"]
    if not isinstance(identifier, str) or not identifier:
        raise WriteRefused(f"{path}의 {id_field}가 비어 있습니다.")
    if not isinstance(permission, dict) or set(permission) != _PERMISSION_FIELDS:
        raise WriteRefused("object_permission은 mcp_servers와 mcp_tool_permissions를 모두, 그것만 "
                           "가져야 합니다(전체 목록 전송).")
    servers, tools = permission["mcp_servers"], permission["mcp_tool_permissions"]
    if not isinstance(servers, list) or not all(isinstance(s, str) for s in servers):
        raise WriteRefused("mcp_servers는 문자열 목록이어야 합니다.")
    if not isinstance(tools, dict) or not all(
        isinstance(k, str) and isinstance(v, list) and all(isinstance(t, str) for t in v)
        for k, v in tools.items()
    ):
        raise WriteRefused("mcp_tool_permissions는 서버 -> 도구 목록 맵이어야 합니다.")


class LiteLLMSync(LiteLLMAdmin):
    """읽기(상속)와 허용된 쓰기."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 10.0,
        before_write: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(base_url, api_key, timeout)
        self.before_write = before_write

    _check = staticmethod(check_write)

    def with_hook(self, before_write: Callable[[], None] | None) -> "LiteLLMSync":
        """쓰기 직전 훅만 바꾼 사본(작업마다 그 작업의 임대·취소 확인을 붙인다)."""
        clone = copy.copy(self)
        clone.before_write = before_write
        return clone

    # --- 전송 ---------------------------------------------------------------

    def _send(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any = None,
    ) -> tuple[int, Any]:
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        headers = {"Authorization": f"Bearer {self._key}"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self._base}{path}{query}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise LiteLLMUnreachable(f"LiteLLM 관리 API에 연결할 수 없습니다: {error}") from None
        try:
            parsed = scrub(json.loads(raw)) if raw else None
        except ValueError:
            parsed = None
        return status, parsed

    def _get(self, path: str, params: dict[str, Any] | None = None) -> tuple[int, Any]:
        return self._send("GET", path, params)

    def _write(self, method: str, path: str, body: Any = None) -> Any:
        """허용 목록을 확인하고 훅을 부른 뒤 보낸다. 2xx가 아니면 예외, 아니면 응답 본문."""
        self._check(method, path, body)
        if self.before_write is not None:
            self.before_write()
        status, parsed = self._send(method, path, body=body)
        if 200 <= status < 300:
            return parsed
        if status in (401, 403):
            raise LiteLLMForbidden(f"LiteLLM이 {path} 쓰기를 거부했습니다(HTTP {status}).", status)
        raise LiteLLMHttpError(
            f"LiteLLM {path} 쓰기 응답이 올바르지 않습니다(HTTP {status}).", status, parsed
        )

    # --- 키·팀 권한 ------------------------------------------------------------

    def update_key_permission(
        self, key: str, mcp_servers: list[str], mcp_tool_permissions: dict[str, list[str]]
    ) -> dict:
        """키의 서버 목록과 도구 맵을 전체로 바꾼다. 응답은 갱신된 키 객체이다."""
        return self._write(
            "POST",
            "/key/update",
            {
                "key": key,
                "object_permission": {
                    "mcp_servers": list(mcp_servers),
                    "mcp_tool_permissions": {k: list(v) for k, v in mcp_tool_permissions.items()},
                },
            },
        )

    def update_team_permission(
        self, team_id: str, mcp_servers: list[str], mcp_tool_permissions: dict[str, list[str]]
    ) -> dict:
        """팀의 서버 목록과 도구 맵을 전체로 바꾼다."""
        return self._write(
            "POST",
            "/team/update",
            {
                "team_id": team_id,
                "object_permission": {
                    "mcp_servers": list(mcp_servers),
                    "mcp_tool_permissions": {k: list(v) for k, v in mcp_tool_permissions.items()},
                },
            },
        )

    # --- 서버 ---------------------------------------------------------------

    def disable_allow_all_keys(self, server_id: str) -> dict | None:
        """모든 키에 열린 서버를 닫는다. 본문은 서버 식별자와 ``allow_all_keys: false``뿐이다."""
        return self._write(
            "PUT", "/v1/mcp/server", {"server_id": server_id, "allow_all_keys": False}
        )

    def pin(self, server_id: str) -> dict:
        """서버 도구를 지금 값으로 고정한다. 응답은 ``{도구: {description, input_schema}}``이다."""
        quoted = urllib.parse.quote(server_id, safe="")
        body = self._write("POST", f"/v1/mcp/server/{quoted}/pin")
        if not isinstance(body, dict):
            raise LiteLLMError("pin 응답 형식이 올바르지 않습니다.")
        return body

    def unpin(self, server_id: str) -> None:
        quoted = urllib.parse.quote(server_id, safe="")
        self._write("DELETE", f"/v1/mcp/server/{quoted}/pin")

    def approve_server(self, server_id: str) -> dict | None:
        quoted = urllib.parse.quote(server_id, safe="")
        return self._write("PUT", f"/v1/mcp/server/{quoted}/approve")

    def reject_server(self, server_id: str, notes: str) -> dict | None:
        """제출을 거절한다. 본문은 검토 메모(500자까지)뿐이다."""
        quoted = urllib.parse.quote(server_id, safe="")
        return self._write(
            "PUT", f"/v1/mcp/server/{quoted}/reject", {"review_notes": notes[:500]}
        )


KIT_ALIAS_PREFIX = "mint-kit-"
_KIT_KEY_FIELDS = frozenset({"user_id", "team_id", "key_alias", "allowed_routes"})


def check_kit_write(method: str, path: str, body: Any) -> None:
    """설치 묶음 키 발급 클라이언트가 보낼 수 있는 쓰기만 통과시킨다.

    생성 본문은 사용자·팀·별칭과 훅 경로만의 ``allowed_routes``뿐이고, 삭제는 설치 묶음 별칭만
    대상으로 한다.
    """
    if (method, path) == ("POST", "/key/generate"):
        if (
            not isinstance(body, dict)
            or not {"user_id", "key_alias", "allowed_routes"} <= set(body) <= _KIT_KEY_FIELDS
            or not all(isinstance(body[k], str) and body[k] for k in set(body) - {"allowed_routes"})
            or not body["key_alias"].startswith(KIT_ALIAS_PREFIX)
            or body["allowed_routes"] != list(KIT_KEY_ROUTES)
        ):
            raise WriteRefused(
                "/key/generate 본문은 사용자·팀·설치 묶음 별칭과 훅 경로만의 allowed_routes만 "
                "보낼 수 있습니다."
            )
    elif (method, path) == ("POST", "/key/delete"):
        aliases = body.get("key_aliases") if isinstance(body, dict) else None
        if (
            set(body or ()) != {"key_aliases"}
            or not isinstance(aliases, list)
            or not aliases
            or not all(isinstance(a, str) and a.startswith(KIT_ALIAS_PREFIX) for a in aliases)
        ):
            raise WriteRefused("/key/delete 본문은 설치 묶음 별칭 목록만 보낼 수 있습니다.")
    else:
        raise WriteRefused(f"허용되지 않은 LiteLLM 쓰기 경로입니다: {method} {path}")


class LiteLLMKitKeys(LiteLLMSync):
    """단말 설치 묶음의 사용자 키 발급 전용 클라이언트. 키 발급 전용 LiteLLM 키로 연다."""

    _check = staticmethod(check_kit_write)

    def generate_kit_key(self, *, user_id: str, team_id: str | None, alias: str) -> str:
        """사용자 한 명의 설치 묶음 키를 만든다. 이 키는 결정·결과·보고 경로만 부를 수 있다."""
        body: dict[str, Any] = {
            "user_id": user_id,
            "key_alias": alias,
            "allowed_routes": list(KIT_KEY_ROUTES),
        }
        if team_id:
            body["team_id"] = team_id
        reply = self._write("POST", "/key/generate", body)
        key = reply.get("key") if isinstance(reply, dict) else None
        if not isinstance(key, str) or not key:
            raise LiteLLMError("key/generate 응답 형식이 올바르지 않습니다.")
        return key

    def delete_kit_keys(self, aliases: list[str]) -> None:
        """설치 묶음 키를 별칭으로 지운다. 이미 없는 키는 지워진 것으로 본다."""
        try:
            self._write("POST", "/key/delete", {"key_aliases": list(aliases)})
        except LiteLLMHttpError as error:
            if error.status not in (400, 404):
                raise

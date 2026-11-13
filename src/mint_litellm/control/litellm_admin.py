"""LiteLLM 관리 API 읽기 전용 클라이언트.

제어 평면 키는 ``allowed_routes``로 읽기 경로만 열려 있고, 이 클라이언트는 GET만 보낸다.
응답에서 자격 열은 수신 즉시 버린다.
"""

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from mint_litellm.control.errors import ControlError
from mint_litellm.types.cli_commands import LITELLM_CREDENTIAL_FIELDS

_CREDENTIALS = frozenset(LITELLM_CREDENTIAL_FIELDS)
PAGE_SIZE = 100


class LiteLLMError(ControlError):
    pass


def scrub(value: Any) -> Any:
    """자격 열을 모든 깊이에서 제거한 사본. 비밀이 아닌 ``credentials.scopes``만 남긴다."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k == "credentials":
                scopes = v.get("scopes") if isinstance(v, dict) else None
                if isinstance(scopes, list):
                    out[k] = {"scopes": [s for s in scopes if isinstance(s, str)]}
            elif k not in _CREDENTIALS:
                out[k] = scrub(v)
        return out
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


class LiteLLMAdmin:
    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._timeout = timeout

    @property
    def key_token(self) -> str:
        """이 접속이 쓰는 키의 토큰(LiteLLM 키 객체의 토큰, 키의 SHA-256 16진수)."""
        return hashlib.sha256(self._key.encode("utf-8")).hexdigest()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> tuple[int, Any]:
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        request = urllib.request.Request(
            f"{self._base}{path}{query}", headers={"Authorization": f"Bearer {self._key}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise LiteLLMError(f"LiteLLM 관리 API에 연결할 수 없습니다: {error}") from None
        try:
            body = scrub(json.loads(raw)) if raw else None
        except ValueError:
            body = None
        return status, body

    def _ok(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        missing_ok: bool = False,
        shape: type = dict,
        key: str | None = None,
    ):
        """200 응답의 본문. ``shape``(와 ``key`` 안의 값)이 맞지 않으면 오류로 처리한다."""
        status, body = self._get(path, params)
        if status == 200:
            inner = (body.get(key) if isinstance(body, dict) else None) if key else body
            if not isinstance(body, (dict, list)) or not isinstance(inner, shape):
                raise LiteLLMError(f"LiteLLM {path} 응답 형식이 올바르지 않습니다.")
            return body
        if status == 404 and missing_ok:
            return None
        if status in (401, 403):
            raise LiteLLMError(
                f"제어 평면 키로 {path}를 읽을 수 없습니다(HTTP {status}). "
                "키의 allowed_routes와 proxy_admin 권한을 확인하십시오."
            )
        raise LiteLLMError(f"LiteLLM {path} 응답이 올바르지 않습니다(HTTP {status}).")

    def list_servers(self) -> list[dict]:
        return self._ok("/v1/mcp/server", shape=list)

    def get_server(self, server_id: str) -> dict | None:
        quoted = urllib.parse.quote(server_id, safe="")
        return self._ok(f"/v1/mcp/server/{quoted}", missing_ok=True)

    def list_server_credentials(self, server_id: str) -> list[dict] | None:
        """서버에 저장된 사용자별 자격(비밀 없는 목록: 사용자·종류). 경로가 없으면 None.

        서버 행이 없어도 자격 표를 서버 식별자로 읽으므로 폐기 뒤 확인에도 쓴다. 404는 이 목록
        경로가 없는 LiteLLM 판본이라는 뜻이다.
        """
        quoted = urllib.parse.quote(server_id, safe="")
        body = self._ok(f"/v1/mcp/server/{quoted}/user-credentials", missing_ok=True, shape=list)
        return None if body is None else [i for i in body if isinstance(i, dict)]

    def get_user(self, user_id: str) -> dict | None:
        """``user_info`` 객체. 사용자가 없으면 None."""
        body = self._ok("/user/info", {"user_id": user_id}, missing_ok=True, key="user_info")
        return None if body is None else body["user_info"]

    def get_key(self, key_id: str) -> dict | None:
        body = self._ok("/key/info", {"key": key_id}, missing_ok=True, key="info")
        return None if body is None else body["info"]

    def get_team(self, team_id: str) -> dict | None:
        body = self._ok("/team/info", {"team_id": team_id}, missing_ok=True, key="team_info")
        return None if body is None else body["team_info"]

    def list_keys(self) -> list[dict]:
        """메타데이터와 객체 권한을 포함한 전체 객체. ``return_full_object``가 필요하다."""
        keys: list[dict] = []
        page = 1
        while True:
            body = self._ok(
                "/key/list",
                {"return_full_object": "true", "size": PAGE_SIZE, "page": page},
                key="keys",
                shape=list,
            )
            keys.extend(k for k in body["keys"] if isinstance(k, dict))
            if page >= body.get("total_pages", 1):
                return keys
            page += 1

    def list_teams(self) -> list[dict]:
        return self._ok("/team/list", shape=list)

    def list_guardrails(self) -> list[dict]:
        return self._ok("/guardrails/list", key="guardrails", shape=list)["guardrails"]

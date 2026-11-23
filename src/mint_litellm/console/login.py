"""로그인 확인: 사람이 낸 본인 LiteLLM 키로 본인 키 정보와 본인 사용자 정보를 읽는다.

평문 키는 이 두 호출에만 쓰고 결과(키의 SHA-256, 사용자 식별자)만 남긴다. 거부 사유는 사람이 고칠 수
있는 말로 돌려주되 키 값은 어디에도 싣지 않는다.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from mint_litellm.control.operators import HUMAN_ROLES
from mint_litellm.control.services.console_sessions import teams_of


class LoginRefused(Exception):
    """로그인을 거부한다. ``str(error)``는 화면에 보여 줄 한국어 사유이다."""


@dataclass(frozen=True)
class Identity:
    user_id: str
    key_token: str
    # 본인 키 정보의 team_id에서 읽은 팀. 화면 입력이 아니다.
    team_ids: tuple[str, ...] = ()
    # 본인 사용자 정보(역할·이메일). 명부에 사람을 맞출 때 쓴다.
    user: dict = field(default_factory=dict, compare=False, repr=False)


def _get(client: httpx.Client, base: str, path: str, key: str) -> httpx.Response:
    try:
        return client.get(f"{base}{path}", headers={"Authorization": f"Bearer {key}"})
    except httpx.HTTPError:
        raise LoginRefused("LiteLLM에 연결할 수 없습니다. 잠시 뒤 다시 시도하십시오.") from None


def _json(response: httpx.Response) -> dict:
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise LoginRefused("LiteLLM 응답을 해석할 수 없습니다.")
    return body


def _expired(value: object) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return True
    parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return parsed <= datetime.now(UTC)


def verify(litellm_url: str, key: str, *, timeout: float = 10.0) -> Identity:
    """키가 사람 사용자의 활성 키이면 ``Identity``를, 아니면 ``LoginRefused``를 낸다."""
    key = key.strip()
    if not key:
        raise LoginRefused("키를 입력하십시오.")
    base = litellm_url.rstrip("/")
    token = hashlib.sha256(key.encode("utf-8")).hexdigest()
    with httpx.Client(timeout=timeout) as client:
        response = _get(client, base, "/key/info", key)
        if response.status_code == 401:
            message = str(_json(response).get("error", {}))
            if "blocked" in message.lower():
                raise LoginRefused("차단된 키입니다.")
            if "expired" in message.lower():
                raise LoginRefused("만료된 키입니다.")
            raise LoginRefused("키를 확인할 수 없습니다.")
        if response.status_code != 200:
            # 마스터 키와 등록되지 않은 키는 404이다. 이 콘솔은 사람 사용자의 키만 받는다.
            raise LoginRefused("키를 확인할 수 없습니다.")
        body = _json(response)
        info = body.get("info")
        if not isinstance(info, dict) or body.get("key") != token:
            raise LoginRefused("키를 확인할 수 없습니다.")
        if info.get("blocked"):
            raise LoginRefused("차단된 키입니다.")
        if _expired(info.get("expires")):
            raise LoginRefused("만료된 키입니다.")
        user_id = info.get("user_id")
        if not isinstance(user_id, str) or not user_id:
            raise LoginRefused("사람 사용자에 연결된 키가 아닙니다.")
        response = _get(client, base, "/user/info", key)
        if response.status_code != 200:
            raise LoginRefused("사용자를 확인할 수 없습니다.")
        user = _json(response).get("user_info")
        if (
            not isinstance(user, dict)
            or user.get("user_id") != user_id
            or user.get("user_role") not in HUMAN_ROLES
        ):
            raise LoginRefused("사람 사용자의 키가 아닙니다.")
    return Identity(user_id=user_id, key_token=token, team_ids=teams_of(info), user=user)

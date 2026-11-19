"""설치 직후 로그인할 기본 관리자(LiteLLM 사용자 ``root``)를 만든다. ``mint.sh up``이 실행한다.

LiteLLM은 /user/new에 비밀번호를 받지 않고, 관리자가 정한 비밀번호에는 재설정을 강제하며,
변경은 새 값이 현재 값과 달라야 한다. 그래서 임시 값으로 정한 뒤 로그인해 기본 비밀번호로 바꾼다.
이미 있는 사용자는 건드리지 않는다(비밀번호를 바꿨으면 그대로 둔다). 임시 값으로만 로그인되는
반쯤 만든 상태는 이어서 끝낸다.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

USER = "root"
PASSWORD = "rootrootroot"  # noqa: S105  # 공개된 기본값. 첫 로그인 뒤 콘솔에서 바꾼다.
TEMPORARY = "rootrootroot0"  # noqa: S105  # 변경 규칙(현재와 달라야 함) 때문에 거치는 값


def _call(
    base: str, path: str, body: dict | None, key: str, method: str = "POST"
) -> tuple[int, Any]:
    request = urllib.request.Request(
        base + path, None if body is None else json.dumps(body).encode(), method=method,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as reply:
            return reply.status, json.loads(reply.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, {}


def _login_key(base: str, password: str) -> str | None:
    """화면 로그인에 성공하면 그 세션의 키, 아니면 None."""
    status, body = _call(base, "/v2/login", {"username": USER, "password": password}, "")
    if status != 200:
        return None
    part = str(body.get("token", "")).split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).get("key")


def _finish(base: str) -> None:
    session = _login_key(base, TEMPORARY)
    if session is None:
        raise RuntimeError("임시 비밀번호로 로그인하지 못했습니다.")
    status, _ = _call(
        base, "/user/password/change", {"current_password": TEMPORARY, "new_password": PASSWORD},
        session,
    )
    if status != 200:
        raise RuntimeError(f"기본 비밀번호로 바꾸지 못했습니다(HTTP {status}).")


def ensure(base: str, master_key: str) -> str:
    """``created`` | ``completed`` | ``exists``. 실패하면 RuntimeError."""
    status, body = _call(base, "/user/info?user_id=" + USER, None, master_key, "GET")
    if status == 200 and (body or {}).get("user_info"):
        if _login_key(base, TEMPORARY) is None:
            return "exists"
        _finish(base)
        return "completed"
    if status not in (200, 400, 404):
        raise RuntimeError(f"LiteLLM 사용자 조회 실패(HTTP {status}).")
    status, _ = _call(
        base, "/user/new",
        {"user_id": USER, "user_email": USER, "user_role": "proxy_admin",
         "auto_create_key": False},
        master_key,
    )
    if status != 200:
        raise RuntimeError(f"LiteLLM 사용자 {USER}를 만들지 못했습니다(HTTP {status}).")
    status, _ = _call(base, "/user/update", {"user_id": USER, "password": TEMPORARY}, master_key)
    if status != 200:
        raise RuntimeError(
            f"비밀번호를 정하지 못했습니다(HTTP {status}). "
            "LiteLLM 설정의 password_policy_*를 확인하십시오."
        )
    _finish(base)
    return "created"


def main() -> None:
    try:
        result = ensure("http://litellm:4000", os.environ["LITELLM_MASTER_KEY"])
    except (RuntimeError, OSError, ValueError, KeyError, IndexError) as error:
        print(f"기본 관리자를 만들지 못했습니다: {error}", file=sys.stderr)
        sys.exit(1)
    if result != "exists":
        print("기본 관리자 root를 만들었습니다.")

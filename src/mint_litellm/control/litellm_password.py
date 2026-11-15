"""LiteLLM 사용자에게 관리 화면 비밀번호를 정해 준다(``/user/update``).

LiteLLM 관리 화면은 이메일과 비밀번호로 로그인한다. 콘솔도 같은 자격을 쓰므로, 사람 사용자를 처음
들이는 관리자는 비밀번호를 한 번 만들어 전해야 한다. 이 호출은 제어 평면 키가 아니라 관리 권한 키
(``MINT_LITELLM_ADMIN_KEY``)로만 한다. 비밀번호는 만든 자리에서 한 번 알리고 저장하지 않는다.
LiteLLM은 관리자가 정한 비밀번호에 첫 로그인 때 변경을 요구한다.
"""

import json
import secrets
import string
import urllib.error
import urllib.request

from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_admin import LiteLLMAdmin, LiteLLMError

MISSING_KEY = (
    "MINT_LITELLM_ADMIN_KEY가 없습니다. 비밀번호를 정하려면 LiteLLM 관리 권한 키(마스터 키)가 "
    "필요합니다. deploy/mint.sh cli로 실행하면 마스터 키를 넘겨 줍니다."
)


def generate_password() -> str:
    """LiteLLM 기본 규칙(12자 이상, 대문자·소문자·숫자)을 만족하는 무작위 비밀번호."""
    pool = string.ascii_letters + string.digits
    while True:
        password = "".join(secrets.choice(pool) for _ in range(20))
        if (
            any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
        ):
            return password


def set_password(
    base_url: str,
    admin_key: str,
    user_id: str,
    *,
    email: str | None = None,
    timeout: float = 10.0,
) -> tuple[str, str]:
    """비밀번호를 정하고 (로그인 아이디, 비밀번호)를 돌려준다. 아이디는 사용자의 이메일이다."""
    if not admin_key:
        raise ControlError(MISSING_KEY)
    try:
        user = LiteLLMAdmin(base_url, admin_key, timeout).get_user(user_id)
    except LiteLLMError as error:
        raise ControlError(str(error)) from None
    if user is None:
        raise ControlError(f"LiteLLM에 사용자 {user_id}가 없습니다.")
    login = email or user.get("user_email")
    if not isinstance(login, str) or not login:
        raise ControlError(
            f"사용자 {user_id}에 이메일이 없습니다. 관리 화면은 이메일로 로그인하므로 "
            "--email로 함께 정하십시오."
        )
    password = generate_password()
    body: dict[str, str] = {"user_id": user_id, "password": password}
    if email:
        body["user_email"] = email
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/user/update",
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {admin_key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ControlError(f"LiteLLM에 연결할 수 없습니다: {error}") from None
    if not 200 <= status < 300:
        raise ControlError(
            f"LiteLLM이 비밀번호 변경을 거부했습니다(HTTP {status}). 관리 권한 키인지, "
            "비밀번호 규칙을 바꾼 설정이 아닌지 확인하십시오."
        )
    return login, password

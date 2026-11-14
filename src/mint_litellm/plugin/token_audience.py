"""업스트림에 그대로 전달되는 호출자 토큰의 대상(aud) 확인(POL-R-05).

서명은 확인하지 않는다. 토큰을 발급한 인가 서버의 키를 알지 못하므로 읽은 ``aud``가 위조되지
않았다는 보증은 없고, 다른 대상용 토큰을 실수로 보내는 일을 잡는 결속 점검이다. JWT가 아닌
(불투명) 토큰은 읽을 수 없어 확인하지 않는다.
"""

import base64
import json
from collections.abc import Sequence
from typing import Final

OK: Final = "ok"
MISMATCH: Final = "mismatch"
UNCHECKED: Final = "unchecked"


def _claims(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return None
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def audience_verdict(token: str, accepted: Sequence[str]) -> str:
    """``ok``(aud가 인정 값을 포함), ``mismatch``(aud가 없거나 포함하지 않음), ``unchecked``."""
    claims = _claims(token)
    if claims is None:
        return UNCHECKED
    aud = claims.get("aud")
    values = aud if isinstance(aud, list) else [aud]
    got = {v.rstrip("/") for v in values if isinstance(v, str)}
    return OK if got & {a.rstrip("/") for a in accepted} else MISMATCH

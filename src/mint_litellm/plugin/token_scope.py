"""업스트림에 그대로 전달되는 호출자 토큰의 범위(scope) 확인(POL-O-15).

서명은 확인하지 않는다. 토큰을 발급한 인가 서버의 키를 알지 못하므로 읽은 범위가 위조되지
않았다는 보증은 없고, 승인된 범위보다 넓은 토큰을 실수로 보내는 일을 잡는 점검이다. JWT가 아닌
(불투명) 토큰은 읽을 수 없어 확인하지 않는다. 결과에는 초과한 범위 이름만 담고 토큰은 담지 않는다.
"""

from collections.abc import Iterable

from mint_litellm.plugin.token_audience import claims_of


def token_scopes(token: str) -> frozenset[str] | None:
    """``scope``(공백으로 구분한 문자열)와 ``scp``(문자열 또는 목록)의 범위. 읽을 수 없으면 None."""
    claims = claims_of(token)
    if claims is None:
        return None
    found: set[str] = set()
    for key in ("scope", "scp"):
        value = claims.get(key)
        parts = value.split() if isinstance(value, str) else value
        if not isinstance(parts, (list, tuple)):
            continue
        for part in parts:
            if isinstance(part, str):
                found.update(part.split())
    return frozenset(found)


def exceeded_scopes(token: str, approved: Iterable[str]) -> tuple[str, ...] | None:
    """승인된 범위를 넘는 토큰의 범위 이름(정렬). 불투명 토큰이면 None."""
    scopes = token_scopes(token)
    return None if scopes is None else tuple(sorted(scopes - set(approved)))

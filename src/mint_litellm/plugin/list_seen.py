"""도구 목록의 「보임·통과」 판정 반복을 거르는 기억.

같은 주체·서버·도구가 같은 상태 세대·설정 판본·정책 판본에서 다시 보이면 새 사건을 쓰지 않는다.
메모리에만 두며 크기와 유효 시간이 제한된다(프로세스가 다시 뜨면 한 번씩 다시 기록된다).
기록이 실제로 저장된 뒤에만 키를 넣으므로 기록 실패는 다음 목록에서 다시 기록된다.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mint_litellm.types.decision import DecisionSnapshot

DEFAULT_TTL_SECONDS = 86400
DEFAULT_MAX_ENTRIES = 100_000


def list_key(snapshot: DecisionSnapshot, policy_version_id: str | None) -> tuple | None:
    """중복 판단 키. 상태 세대·설정 판본·정책 판본 중 하나라도 모르면 키를 만들지 않는다.

    ``policy_version_id``는 활성 정책 판본이다(도구 목록 판정은 정책을 평가하지 않아 본문에는 없다).
    """
    if (
        snapshot.state_epoch is None
        or snapshot.settings_version is None
        or policy_version_id is None
        or snapshot.resolved_server_id is None
        or snapshot.tool is None
    ):
        return None
    who = snapshot.principal
    return (
        who.principal_type.value,
        who.principal_id,
        who.key_id,
        who.team_id,
        who.org_id,
        snapshot.resolved_server_id,
        snapshot.tool,
        snapshot.state_epoch,
        snapshot.settings_version,
        policy_version_id,
    )


class ListSeen:
    def __init__(
        self,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._clock = clock
        self._items: OrderedDict[tuple, float] = OrderedDict()

    def seen(self, key: tuple) -> bool:
        """유효한 키가 있으면 참. 어떤 오류든 거짓이다(그러면 사건을 쓴다)."""
        try:
            expires = self._items.get(key)
            if expires is None:
                return False
            if expires <= self._clock():
                del self._items[key]
                return False
            return True
        except Exception:
            return False

    def add(self, key: tuple) -> None:
        try:
            self._items[key] = self._clock() + self._ttl
            self._items.move_to_end(key)
            while len(self._items) > self._max:
                self._items.popitem(last=False)
        except Exception:
            pass

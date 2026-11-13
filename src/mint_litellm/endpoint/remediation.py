"""설치 보고 응답의 폐기 서버 목록과, 단말이 보고한 자동 제거의 사건.

관리형 설치의 묶음은 이 목록에 든 서버의 설정 항목·실행 프로세스·자동 시작 항목을 스스로 지우고
지운 것을 보고한다. 목록은 MINT가 아는 상태에서 만들고(단말의 주장이 아니다), 지웠다는 보고는
단말의 주장이라 사건으로만 남긴다.
"""

import hashlib
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from mint_litellm.types.events import Event, EventKind

LIVE = ("approved", "suspended")  # 이 밖의 상태(없는 서버 포함)는 폐기·미승인으로 본다
MAX_RETIRED = 256
ACTOR = "mint-endpoint-kit"


def retired_names(statuses: Mapping[str, str], reported: Iterable[str]) -> list[str]:
    """응답에 실을 폐기·반려·미승인 서버 이름. ``statuses``는 등록된 로컬 서버의 상태.

    등록된 서버 중 살아 있는 상태가 아닌 것과, 단말이 보고했지만 등록에 없는 이름을 모은다.
    """
    names = {name for name, status in statuses.items() if status not in LIVE}
    names |= {name for name in reported if name not in statuses}
    return sorted(names)[:MAX_RETIRED]


def remediation_events(
    instance_id: str,
    *,
    user_id: str,
    key_alias: str,
    removed: Iterable[Mapping[str, Any]],
    at: datetime,
) -> list[Event]:
    """보고된 제거 항목마다 사건 하나. 같은 항목을 같은 초에 다시 받으면 같은 사건이다."""
    events = []
    for item in removed:
        digest = hashlib.sha256(
            f"{key_alias}|{item['kind']}|{item['server']}|{item.get('target')}".encode()
        ).hexdigest()[:24]
        events.append(
            Event(
                instance_id=instance_id,
                inserted_at=at,
                kind=EventKind.ENDPOINT_REMEDIATED,
                source_key=f"endpoint:{digest}:{int(at.timestamp())}:endpoint_remediated",
                actor=ACTOR,
                subject={"user_id": user_id, "key_alias": key_alias, "server_id": item["server"]},
                payload={"kind": item["kind"], "target": item.get("target"),
                         "server_id": item["server"]},
            )
        )
    return events

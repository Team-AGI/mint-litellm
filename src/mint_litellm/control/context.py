"""명령 한 건의 실행 맥락: 연결, 배치, 인증된 운영자."""

from dataclasses import dataclass, field
from typing import Any

import psycopg

from mint_litellm.control import ledger
from mint_litellm.types.events import EventKind


@dataclass(frozen=True)
class Operator:
    name: str
    role: str
    user_id: str | None


@dataclass(frozen=True)
class Context:
    conn: psycopg.Connection
    instance_id: str
    operator: Operator
    emitted: list = field(default_factory=list)
    # 콘솔 화면이 아닌 경로(예: slack)로 들어온 행위이면 사건 본문에 채널로 남긴다.
    channel: str | None = None

    def emit(
        self,
        kind: EventKind,
        entity_id: Any,
        state_version: int,
        payload: dict[str, Any],
        subject: dict[str, Any] | None = None,
    ):
        event = ledger.record(
            self.conn,
            self.instance_id,
            kind,
            entity_id=str(entity_id),
            state_version=state_version,
            actor=self.operator.name,
            payload={**payload, "channel": self.channel} if self.channel else payload,
            subject=subject,
        )
        self.emitted.append(event)
        return event

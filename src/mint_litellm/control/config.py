"""환경 변수에서 읽는 제어 평면 설정."""

import os
import re
from dataclasses import dataclass
from pathlib import Path

from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.litellm_control import LiteLLMControl
from mint_litellm.types.settings import Mode

_LITELLM_NEEDED = (
    "MINT_LITELLM_URL과 MINT_LITELLM_KEY가 필요합니다. deploy/mint.sh up이 제어 평면 키를 "
    "만들어 넣으므로 deploy/mint.sh cli로 실행하거나, 직접 실행하면 두 환경 변수를 설정하십시오."
)
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


@dataclass(frozen=True)
class ControlConfig:
    database_url: str | None
    instance_id: str
    litellm_url: str | None
    litellm_key: str | None
    litellm_config: Path | None
    mode_ceiling: Mode
    replicas: int

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "ControlConfig":
        env = dict(os.environ) if env is None else env
        raw_mode = env.get("MINT_MODE", "enforce")
        try:
            ceiling = Mode(raw_mode)
        except ValueError:
            raise ControlError(f"MINT_MODE는 enforce 또는 observe여야 합니다: {raw_mode}") from None
        config_path = env.get("MINT_LITELLM_CONFIG")
        instance_id = env.get("MINT_INSTANCE_ID", "default")
        if not _IDENT.fullmatch(instance_id):  # 플러그인과 같은 식별자 규칙(파일 경로에도 쓴다)
            raise ControlError("MINT_INSTANCE_ID는 영문·숫자·. _ -로 된 식별자여야 합니다.")
        return cls(
            database_url=env.get("MINT_DATABASE_URL"),
            instance_id=instance_id,
            litellm_url=env.get("MINT_LITELLM_URL"),
            litellm_key=env.get("MINT_LITELLM_KEY"),
            litellm_config=Path(config_path) if config_path else None,
            mode_ceiling=ceiling,
            # 캐시를 따로 가지는 프로세스 수: 복제본 × 컨테이너당 워커
            replicas=int(env.get("MINT_REPLICAS", "1"))
            * int(env.get("MINT_LITELLM_WORKERS", "1")),
        )

    def require_database(self) -> str:
        if not self.database_url:
            raise ControlError(
                "MINT_DATABASE_URL이 설정되어 있지 않습니다. 배포 환경에서는 deploy/mint.sh cli로 "
                "실행하면 접속 정보가 채워집니다."
            )
        return self.database_url

    def litellm_control(self) -> LiteLLMControl:
        if not self.litellm_url or not self.litellm_key:
            raise ControlError(_LITELLM_NEEDED)
        return LiteLLMControl(self.litellm_url, self.litellm_key)

    def litellm(self) -> LiteLLMAdmin:
        if not self.litellm_url or not self.litellm_key:
            raise ControlError(_LITELLM_NEEDED)
        return LiteLLMAdmin(self.litellm_url, self.litellm_key)

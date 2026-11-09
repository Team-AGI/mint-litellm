"""환경 변수로 켜는 결정 경로 설치. 켜지 않으면 아무것도 하지 않는다."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.endpoint.decide import ContractRegistry, install, make_router
from mint_litellm.plugin.selfcheck import get_runtime

REGISTRY_ENV = "MINT_ENDPOINT_REGISTRY"


def install_from_env(env: Mapping[str, str]) -> bool:
    """``MINT_ENDPOINT_REGISTRY``(승인된 로컬 서버 계약 파일)가 있으면 결정 경로를 앱에 붙인다.

    파일이 읽히지 않으면 예외를 던져 가드레일 기동을 거부한다(켠 경로가 반쯤 열리지 않게).
    워커마다 한 번씩 불리며, 앱에 이미 붙어 있으면 건너뛴다.
    """
    path = env.get(REGISTRY_ENV)
    if not path:
        return False
    router = make_router(
        auth_dependency=compat.key_auth_dependency(),
        runtime_provider=get_runtime,
        registry=ContractRegistry.load(Path(path)),
        principal_factory=compat.principal_from_auth,
    )
    return install(compat.proxy_app(), router)

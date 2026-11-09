"""환경 변수로 켜는 결정 경로 설치. 켜지 않으면 아무것도 하지 않는다."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.endpoint.decide import ContractRegistry, KitSettings, install, make_router
from mint_litellm.plugin.selfcheck import get_runtime

REGISTRY_ENV = "MINT_ENDPOINT_REGISTRY"
PUBLIC_URL_ENV = "MINT_ENDPOINT_PUBLIC_URL"
REPORTS_ENV = "MINT_ENDPOINT_REPORTS"
CA_FILE_ENV = "MINT_ENDPOINT_CA_FILE"


def install_from_env(env: Mapping[str, str]) -> bool:
    """``MINT_ENDPOINT_REGISTRY``(승인된 로컬 서버 계약 파일)가 있으면 결정 경로를 앱에 붙인다.

    ``MINT_ENDPOINT_PUBLIC_URL``과 ``MINT_ENDPOINT_REPORTS``가 함께 있으면 키트 내려받기와 설치
    보고 경로도 붙인다. 파일이 읽히지 않으면 예외를 던져 가드레일 기동을 거부한다.
    워커마다 한 번씩 불리며, 앱에 이미 붙어 있으면 건너뛴다.
    """
    path = env.get(REGISTRY_ENV)
    if not path:
        return False
    kit = None
    if env.get(PUBLIC_URL_ENV) and env.get(REPORTS_ENV):
        ca = env.get(CA_FILE_ENV)
        kit = KitSettings(
            public_url=env[PUBLIC_URL_ENV],
            reports_path=Path(env[REPORTS_ENV]),
            ca_pem=Path(ca).read_text(encoding="utf-8") if ca else None,
        )
    router = make_router(
        auth_dependency=compat.key_auth_dependency(),
        runtime_provider=get_runtime,
        registry=ContractRegistry.load(Path(path)),
        principal_factory=compat.principal_from_auth,
        kit=kit,
    )
    return install(compat.proxy_app(), router)

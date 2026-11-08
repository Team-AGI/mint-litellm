"""``mint-litellm console``: 필수 설정을 확인하고 uvicorn으로 콘솔 앱을 띄운다."""

import argparse
import sys
from collections.abc import Mapping

from mint_litellm.console.app import create_app
from mint_litellm.console.core import ConsoleConfig
from mint_litellm.control.errors import ControlError

ALL_ADDRESSES = "*"


def bind_host(value: str) -> str | None:
    """``*``만 모든 주소다. 주소를 못 박지 않고 가진 주소족(IPv4·IPv6)마다 연다.

    빈 값(비어 있는 환경 변수가 넘어온 경우)은 의도하지 않은 외부 개방이므로 거부한다.

    ``::``처럼 주소족을 하나로 못 박으면 그 주소족이 없는 컨테이너에서는 닿지 않는다.
    """
    if not value.strip():
        raise ControlError("--host가 비어 있습니다. 모든 주소는 *로 명시하십시오.")
    return None if value == ALL_ADDRESSES else value


def serve(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    import uvicorn

    # 필수 설정이 없으면 ControlError로 기동을 거부한다
    app = create_app(ConsoleConfig.from_env(environ))
    print(f"관리자 콘솔 시작: {args.host}:{args.port}", file=sys.stderr, flush=True)
    uvicorn.run(
        app,
        host=bind_host(args.host),
        port=args.port,
        ssl_certfile=args.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile,
        log_level="warning",
    )
    return 0

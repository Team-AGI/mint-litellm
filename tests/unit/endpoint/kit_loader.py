"""설치 묶음 프로그램은 패키지가 아니라 단말에 복사되는 파일이므로 경로로 읽어 온다."""

import importlib.util
import sys
from pathlib import Path

import mint_litellm

KIT = Path(mint_litellm.__file__).parent / "endpoint" / "kit"


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"kit_{name}", KIT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

"""LiteLLM 설정 파일에서 평문으로 적힌 비밀 값의 위치를 찾는다.

비밀을 담는 항목(``api_key``, ``master_key``, ``*_secret``, ``*_token``, ``password``, 인증 헤더 등)
의 값이 ``os.environ/<이름>`` 참조가 아니라 문자열 그대로 적혀 있으면 평문으로 본다. 접속 주소에
``사용자:비밀번호@``가 들어 있어도 같다. 결과는 항목 경로만 돌려주며 값은 읽어도 내보내지 않는다.
"""

import re
from collections.abc import Mapping
from typing import Any

ENV_REFERENCE = "os.environ/"
MAX_REPORTED = 50

_SECRET_KEY = re.compile(
    r"api_?key|master_?key|secret|token|password|passwd|authorization|private_?key"
    r"|access_?key|auth_value|credential"
)
# 이름에 비밀 단어가 있어도 비밀 값이 아닌 항목(주소·경로·종류·개수 따위)
_NOT_A_VALUE = re.compile(
    r"(_url|_uri|_endpoint|_path|_file|_name|_type|_header|_location|_ttl|_seconds|_tokens)$"
    r"|^(max|min)_|^(use|enable|disable|allow|require)_"
)
_URL_PASSWORD = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]*:[^/\s@]+@", re.IGNORECASE)


def _is_secret_key(key: str) -> bool:
    name = key.strip().lower().replace("-", "_")
    return bool(_SECRET_KEY.search(name)) and not _NOT_A_VALUE.search(name)


def _literal(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and not value.startswith(ENV_REFERENCE)


def plaintext_secret_paths(config: Mapping[str, Any] | None) -> list[str]:
    """평문 비밀이 적힌 항목의 경로(``general_settings.master_key``, ``model_list[0]...``).

    경로 순서는 설정 파일의 순서를 따르고, ``MAX_REPORTED``개를 넘으면 앞에서 자른다.
    """
    found: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, Mapping):
            for key, value in node.items():
                here = f"{path}.{key}" if path else str(key)
                if isinstance(value, (Mapping, list)):
                    walk(value, here)
                elif _literal(value) and (_is_secret_key(str(key)) or _URL_PASSWORD.search(value)):
                    found.append(here)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                here = f"{path}[{index}]"
                if isinstance(value, (Mapping, list)):
                    walk(value, here)
                elif isinstance(value, str) and _URL_PASSWORD.search(value):
                    found.append(here)

    walk(config or {}, "")
    return found[:MAX_REPORTED]

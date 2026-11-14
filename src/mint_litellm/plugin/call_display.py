"""호출별 승인 화면에 보이는 인자 표시. 비밀·개인정보는 저장 전에 가리고 값은 잘라 둔다."""

import json
import re
from collections.abc import Mapping
from typing import Any

from mint_litellm.plugin.policy.sensitive_scan import mask_text

MAX_FIELDS = 20
MAX_VALUE_CHARS = 200
_SECRET_NAME = re.compile(
    r"pass(word|wd)?|secret|token|api[_-]?key|auth|credential|cookie|private", re.IGNORECASE
)


def call_display(arguments: Mapping[str, Any]) -> dict[str, str]:
    """최상위 인자 이름별 표시 문자열. 이름이 비밀처럼 보이면 값은 통째로 가린다."""
    shown: dict[str, str] = {}
    for key, value in list(arguments.items())[:MAX_FIELDS]:
        name = mask_text(str(key))[:64]
        if _SECRET_NAME.search(str(key)):
            shown[name] = "[MASKED]"
            continue
        text = (
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
        )
        text = mask_text(text)
        shown[name] = text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + "…"
    if len(arguments) > MAX_FIELDS:
        shown["…"] = f"{len(arguments) - MAX_FIELDS}"
    return shown

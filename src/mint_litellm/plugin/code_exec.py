"""모델 요청이 LiteLLM 샌드박스의 코드 실행을 요구하는지 판정한다.

``container``(스킬·컨테이너 재사용), ``code_interpreter``·``code_execution*`` 도구, 스킬 훅이
주입하는 ``litellm_code_execution`` 도구와 그 활성 표지(``_litellm_code_execution_enabled``)가
대상이다. 이 경로는 MCP가 아니라서 도구 호출 훅을 지나지 않는다. 스킬 훅은 순차 사전 훅에서
``container``를 지우고 도구와 표지를 남기므로, 병렬로 도는 MINT는 그 흔적을 본다.
최상위와 ``extra_body``(객체 또는 JSON 문자열)만 본다.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

TOOL_NAME = "litellm_code_execution"
FLAG = "_litellm_code_execution_enabled"
_TOOL_NAMES = frozenset({TOOL_NAME, "code_execution"})


def _tool_kind(tool: Any) -> bool:
    if not isinstance(tool, Mapping):
        return False
    kind = tool.get("type")
    if isinstance(kind, str) and (kind == "code_interpreter" or kind.startswith("code_execution")):
        return True
    function = tool.get("function")
    names = (tool.get("name"), function.get("name") if isinstance(function, Mapping) else None)
    return any(n in _TOOL_NAMES for n in names)


def _body_kind(body: Mapping[str, Any]) -> str | None:
    if body.get("container"):
        return "container"
    tools = body.get("tools")
    if isinstance(tools, list) and any(_tool_kind(t) for t in tools):
        return "tool"
    for key in ("metadata", "litellm_metadata"):
        meta = body.get(key)
        if isinstance(meta, Mapping) and meta.get(FLAG):
            return "flag"
    return None


def code_execution(data: Any) -> str | None:
    """코드 실행을 요구하는 항목의 종류(``container``·``tool``·``flag``), 없으면 None."""
    if not isinstance(data, Mapping):
        return None
    found = _body_kind(data)
    if found is not None:
        return found
    extra = data.get("extra_body")
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except ValueError:
            return None
    return _body_kind(extra) if isinstance(extra, Mapping) else None

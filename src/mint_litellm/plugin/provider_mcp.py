"""모델 요청에 담긴 공급자 쪽 MCP 판정.

``type="mcp"`` 객체(``tools[]``든 ``extra_body``·``input``·``session`` 안이든)와 비어 있지 않은
``mcp_servers``는 공급자가 외부 서버를 직접 호출하게 하므로 MINT의 서버 판정을 거치지 않는다.
요청 본문 전체의 구조화 객체를 재귀로 본다. 문자열은 문자열 ``extra_body``만 JSON으로 풀어 같은
검사를 하고(메시지 본문 텍스트나 ``metadata`` 등 다른 문자열은 풀지 않는다), 문자열로 들어온
``tools``·``mcp_servers``·``session``은 지원하지 않는 형식으로 막는다. 깊이·크기 상한을 넘는
본문은 판정할 수 없으므로 막는다. 예외는 하나뿐이다. 최상위 ``tools[]``의 ``litellm_proxy``
형식 주소는 LiteLLM이 자기 MCP 경로로 실행하며 그 호출은 도구 호출 훅을 지난다. 임의 호스트의
``/mcp/<이름>`` 경로는 공급자에게 그대로 전달될 수 있어 게이트웨이로 인정하지 않는다. 패스스루
호출 유형에는 LiteLLM의 내부 MCP 처리가 없으므로 예외 없이 모두 막는다.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

MAX_DEPTH = 24
MAX_NODES = 100_000
MAX_JSON_CHARS = 1_000_000
PASS_THROUGH = "pass_through_endpoint"
GATEWAY = "litellm_proxy"

TOOLS = "tools"
SERVERS = "mcp_servers"
LIMIT = "limit"
UNSUPPORTED = "unsupported"


class _Found(Exception):
    def __init__(self, kind: str) -> None:
        self.kind = kind


def _gateway_form(tool: Mapping[str, Any]) -> bool:
    url = tool.get("server_url")
    return isinstance(url, str) and (url == GATEWAY or url.startswith(GATEWAY + "/"))


def is_realtime(call_type: Any) -> bool:
    """실시간 호출 유형. 연결 뒤의 ``session.update``는 사전 훅을 지나지 않는다."""
    return isinstance(call_type, str) and "realtime" in call_type


def external_mcp(data: Any, call_type: Any = None) -> str | None:
    """공급자가 직접 부를 MCP 항목이 있으면 그 종류, 판정할 수 없으면 ``limit``, 없으면 None.

    MCP가 없는 요청도 본문을 한 번 훑지만 대기는 없다.
    """
    if not isinstance(data, Mapping):
        return None
    allowed: set[int] = set()
    top = data.get("tools")
    if call_type != PASS_THROUGH and isinstance(top, list):
        allowed = {id(t) for t in top if isinstance(t, Mapping) and _gateway_form(t)}
    nodes = 0

    def walk(value: Any, depth: int, strict: bool) -> None:
        # strict: 공급자 요청으로 이어지는 자리(최상위, extra_body, session)의 키를 엄격히 본다.
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise _Found(LIMIT)
        if isinstance(value, Mapping):
            if value.get("type") == "mcp" and id(value) not in allowed:
                raise _Found(TOOLS)
            if value.get("mcp_servers"):
                raise _Found(SERVERS)
            for key, item in value.items():
                # LiteLLM이 요청 본문을 그대로 복사해 두는 자리라 같은 항목을 두 번 본다.
                if depth == 0 and key == "proxy_server_request":
                    continue
                if strict and isinstance(item, str) and item.strip():
                    if key in ("tools", "mcp_servers"):
                        raise _Found(UNSUPPORTED)
                    if key == "session" and item.lstrip()[:1] in ("{", "["):
                        raise _Found(UNSUPPORTED)
                if key == "extra_body" and isinstance(item, str):
                    # 문자열 extra_body는 LiteLLM이 JSON으로 풀어 공급자 요청에 합칠 수 있다.
                    walk(_parse(item), depth + 1, True)
                    continue
                walk(item, depth + 1, strict and key in ("extra_body", "session"))
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item, depth + 1, strict)

    def _parse(text: str) -> Any:
        if len(text) > MAX_JSON_CHARS:
            raise _Found(LIMIT)
        try:
            return json.loads(text)
        except ValueError:
            return None

    try:
        walk(data, 0, True)
    except _Found as found:
        return found.kind
    except RecursionError:
        return LIMIT
    return None

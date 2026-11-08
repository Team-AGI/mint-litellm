"""모델 요청에 담긴 공급자 쪽 MCP 판정.

``tools[]``의 ``type="mcp"`` 항목과 Anthropic형 ``mcp_servers``는 공급자가 외부 서버를 직접
호출하게 하므로 MINT의 서버 판정을 거치지 않는다. 게이트웨이가 서빙하는 주소(``litellm_proxy``
또는 등록된 ``/mcp/<이름>``)의 ``type="mcp"``만 LiteLLM이 자기 MCP 경로로 실행하며 그 호출은
도구 호출 훅을 지난다. 그 판정은 LiteLLM의 ``routes_through_gateway``와 같은 기준을 쓴다.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any

from mint_litellm.compat import litellm_1_106 as compat

Router = Callable[[Sequence[Mapping[str, Any]]], Awaitable[Sequence[bool]]]


async def external_mcp(data: Any, routes: Router = compat.routes_through_gateway) -> str | None:
    """공급자가 직접 부를 MCP 항목이 있으면 그 종류(``mcp_servers``·``tools``), 없으면 None.

    MCP가 없는 요청은 비교 몇 번으로 끝나며 어떤 대기도 없다.
    """
    if not isinstance(data, Mapping):
        return None
    if data.get("mcp_servers"):
        return "mcp_servers"
    tools = data.get("tools")
    if not isinstance(tools, list):
        return None
    mcp = [t for t in tools if isinstance(t, Mapping) and t.get("type") == "mcp"]
    if mcp and not all(await routes(mcp)):
        return "tools"
    return None

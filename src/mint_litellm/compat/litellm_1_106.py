"""LiteLLM 1.106.6·1.108.5와의 접점.

LiteLLM의 비공개 심볼과 훅 데이터 형태에 대한 의존은 모두 이 모듈에 둔다. 다른 모듈은
LiteLLM을 직접 가져오지 않는다. 함수는 가져오기를 호출 시점으로 미뤄, LiteLLM이 설치되지
않은 환경에서도 모듈을 읽을 수 있고 시험에서는 서버 관리자 객체를 인자로 바꿔 넣을 수 있다.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib
import importlib.metadata
import time
from collections.abc import Awaitable, Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mint_litellm.compat import capabilities
from mint_litellm.types.decision import ResolvedServer, normalize_auth_type, url_sha256
from mint_litellm.types.identity import Principal, classify_principal
from mint_litellm.types.reason_codes import Reason
from mint_litellm.types.reuse_policy import (
    DEFAULT_TOOL_TIMEOUT_SECONDS,
    DISCOVERY_AUTH,
    ServerFacts,
    credential_digest,
    forwards_client_token,
    header_credential_digests,
    ssl_verify_on,
)

# 보장하는 판본. 앞의 것이 기준 판본(잠금 파일·기본 이미지)이다.
SUPPORTED_LITELLM_VERSIONS = ("1.106.6", "1.108.5")

CALL_TOOL = "call_mcp_tool"
LIST_TOOLS = "list_mcp_tools"

_MANAGER_MODULE = "litellm.proxy._experimental.mcp_server.mcp_server_manager"
_UTILS_MODULE = "litellm.proxy._experimental.mcp_server.utils"


class ServerResolutionError(Exception):
    """서버를 하나로 정할 수 없다. ``reason``은 판정 사유 계열이다."""

    def __init__(self, reason: Reason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class HookData:
    """사전 훅 ``data``에서 읽는 값.

    REST 호출은 같은 호출에서 사전 훅 단계가 두 번 있다. 첫 번째는 요청 본문 단계라
    ``mcp_server_name``이 없고(LiteLLM이 가드레일을 건너뛴다), 두 번째(합성 단계)만 서버 이름과
    도구 이름이 있다. ``arguments_ok``가 거짓이면 전송될 인자가 객체가 아니고,
    ``arguments_confirmed``가 거짓이면 판정한 인자가 전송될 인자와 같다고 확인할 수 없다.
    """

    server_name: str | None
    tool_name: str | None
    arguments: Mapping[str, Any]
    litellm_call_id: str | None
    logging_obj: Any
    arguments_ok: bool = True
    arguments_confirmed: bool = True


_ARGUMENTS_MARK = "\nArguments: "


def arguments_match_original(data: Mapping[str, Any], arguments: Any) -> bool:
    """``arguments``가 사전 훅에 들어오기 전의 원래 인자와 같다고 확인할 수 있는지.

    LiteLLM 전송부는 참인 ``modified_arguments``가 없으면 훅 진입 전의 원래 인자를 보내는데,
    그 값은 사전 훅 데이터에 따로 남지 않는다(``mcp_arguments``는 사본이라 앞선 훅이 바꿀 수
    있다). 변환 시점의 원래 인자는 첫 메시지 본문 끝의 ``Arguments: <값>``에만 문자열로 남는다.
    ``arguments``의 문자열이 그와 같으면 원래 인자와 같다. 그 자리가 없거나 다르면 같다고 확인할
    수 없다.
    """
    try:
        content = data["messages"][0]["content"]
    except (KeyError, IndexError, TypeError):
        return False
    return isinstance(content, str) and content.endswith(f"{_ARGUMENTS_MARK}{arguments}")


def arguments_witness_problem() -> str | None:
    """위 확인의 근거가 지원 판본의 실제 변환기에서 그대로인지. 어긋나면 이유를 돌려준다."""
    try:
        from litellm.proxy.utils import ProxyLogging

        proxy = ProxyLogging.__new__(ProxyLogging)
        original = {"k": ["v", 1], "한글": 'it\'s "q"\n', "n": {"a": None, "b": 1.5}}
        kwargs = {"name": "probe", "arguments": original, "server_name": "probe"}
        request = proxy.create_mcp_request_object_from_kwargs(kwargs)
        data = proxy.convert_mcp_to_llm_format(request, kwargs)
        # 변환기가 돌려준 값이 아니라 알려진 원래 입력과 직접 대조한다.
        same = data["mcp_arguments"] == original and arguments_match_original(data, original)
        other = arguments_match_original(data, {"k": ["x"]})
    except Exception as exc:
        return f"arguments witness: {type(exc).__name__}"
    return None if same and not other else "arguments witness: unexpected message shape"


def effective_arguments(data: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """업스트림에 전달될 인자. 객체가 아니면 None이다.

    앞선 훅이 돌려준 수정본이 있으면 그것이다. LiteLLM은 비어 있는 값을 수정본으로 치지 않는다.
    수정본이 없을 때의 ``mcp_arguments``는 원래 인자와 같은지 ``arguments_match_original``로
    따로 확인해야 한다. 키가 없으면 빈 객체이고, 값이 None이나 문자열 같은 비객체면 None이다.
    """
    modified = data.get("modified_arguments")
    arguments = modified if modified else data.get("mcp_arguments", {})
    return arguments if isinstance(arguments, Mapping) else None


def parse_hook_data(data: Mapping[str, Any]) -> HookData:
    arguments = effective_arguments(data)
    confirmed = bool(data.get("modified_arguments")) or arguments_match_original(
        data, data.get("mcp_arguments", {})
    )
    logging_obj = data.get("litellm_logging_obj")
    call_id = getattr(logging_obj, "litellm_call_id", None) or data.get("litellm_call_id")
    return HookData(
        server_name=data.get("mcp_server_name"),
        tool_name=data.get("mcp_tool_name"),
        arguments=arguments if arguments is not None else {},
        litellm_call_id=str(call_id) if call_id else None,
        logging_obj=logging_obj,
        arguments_ok=arguments is not None,
        arguments_confirmed=confirmed,
    )


def master_key_alias() -> str:
    from litellm.constants import LITELLM_PROXY_MASTER_KEY_ALIAS

    return LITELLM_PROXY_MASTER_KEY_ALIAS


def principal_from_auth(
    user_api_key_dict: Any, *, instance_id: str, master_alias: str | None = None
) -> Principal:
    """LiteLLM이 검증한 키 객체로 주체를 분류한다.

    키 식별자는 ``data``의 해시 필드가 아니라 인증 객체의 ``token``이다. ``data``의
    ``user_api_key_hash``는 도구 호출 경로에서 항상 비어 있다. 마스터 키는 안정된 별칭으로
    치환되어 ``token``에 들어온다.
    """
    alias = master_alias if master_alias is not None else master_key_alias()
    key_id = getattr(user_api_key_dict, "token", None)
    metadata = getattr(user_api_key_dict, "metadata", None)
    # JWT 인증(handle_jwt.py의 user_api_key_auth_from_result)은 api_key=None이라 token이 없고
    # user_id·team_id는 검증된 클레임이다. 관리형 에이전트 맥락과 게이트웨이 입장 표지는 서버만
    # 설정하는 값이다. 이 중 하나가 있을 때만 키 없는 사용자를 신원으로 인정한다.
    keyless = (
        key_id is None
        and (
            bool(getattr(user_api_key_dict, "jwt_claims", None))
            or getattr(user_api_key_dict, "managed_agent_context", None) is not None
            or getattr(user_api_key_dict, "mcp_admitted_user_subject", False) is True
        )
    )
    return classify_principal(
        keyless_verified=keyless,
        instance_id=instance_id,
        key_id=key_id,
        user_id=getattr(user_api_key_dict, "user_id", None),
        team_id=getattr(user_api_key_dict, "team_id", None),
        metadata=metadata if isinstance(metadata, Mapping) else None,
        is_master_key=key_id == alias or getattr(user_api_key_dict, "api_key", None) == alias,
        claimed_end_user_id=getattr(user_api_key_dict, "end_user_id", None) or None,
    )


def key_auth_dependency() -> Any:
    """호출자 키를 검증하는 LiteLLM의 인증 의존성. 경로의 허용 목록 검사도 이 안에서 일어난다."""
    return importlib.import_module("litellm.proxy.auth.user_api_key_auth").user_api_key_auth


def proxy_app() -> Any:
    return importlib.import_module("litellm.proxy.proxy_server").app


def global_manager() -> Any:
    return importlib.import_module(_MANAGER_MODULE).global_mcp_server_manager


def _enum_text(value: object) -> str:
    return str(value.value) if isinstance(value, Enum) else str(value)


def normalize_server_name(name: str) -> str:
    # LiteLLM의 같은 이름 함수와 같은 규칙(공백을 밑줄로). 자가 점검이 심볼 존재를 확인한다.
    return name.replace(" ", "_")


def _matching_servers(manager: Any, server_name: str) -> list[Any]:
    wanted = normalize_server_name(server_name)
    matches = []
    for server in manager.get_registry().values():
        identifiers = (server.alias, server.server_name, server.name)
        if any(i and normalize_server_name(i) == wanted for i in identifiers):
            matches.append(server)
    return matches


def _credential_ref(server: Any) -> str | None:
    """레지스트리가 가진 원격 자격의 주체. 고정 토큰은 지문만, OAuth는 클라이언트 식별자만 쓴다."""
    token = getattr(server, "authentication_token", None)
    if token is not None and hasattr(token, "get_secret_value"):
        token = token.get_secret_value()
    if isinstance(token, str) and token:
        return "static:" + hashlib.sha256(b"mint-credential:" + token.encode()).hexdigest()[:16]
    client_id = getattr(server, "client_id", None)
    if isinstance(client_id, str) and client_id:
        return "oauth2-client:" + client_id[:64]
    return None


def _to_resolved(server: Any, candidates: int) -> ResolvedServer:
    if not getattr(server, "url", None):
        # 레지스트리의 로컬 실행(stdio)·OpenAPI 서버는 URL 해시도 실행 계약도 만들 수 없어 막는다.
        # 승인된 로컬 서버는 레지스트리가 아니라 MINT 표에서 ``ExecContract.resolved``로 해석한다.
        raise ServerResolutionError(Reason.UNSUPPORTED, "server_without_url")
    return ResolvedServer(
        server_id=server.server_id,
        url_sha256=url_sha256(server.url),
        transport=_enum_text(server.transport),
        auth_type=normalize_auth_type(server.auth_type),
        candidates_with_same_name=max(candidates, 1),
        credential_ref=_credential_ref(server),
        oauth_scopes=tuple(sorted({
            part for s in (getattr(server, "configured_scopes", None) or ())
            if isinstance(s, str) for part in s.split()
        })),
    )


def resolve_server(hook: HookData, *, manager: Any = None) -> ResolvedServer:
    """도구 호출이 실제로 실행될 서버.

    실행 단계가 쓰는 해석 함수를 그대로 부른다. 이름 우선순위가 다른
    ``get_mcp_server_by_name``은 설정 서버와 DB 서버의 이름이 겹칠 때 실행되지 않을 서버를
    돌려주므로 쓰지 않는다. 호출 전에 목록이 한 번 읽혀 도구 경로표가 채워져 있는 호출에만
    성립한다.
    """
    if hook.server_name is None or hook.tool_name is None:
        raise ServerResolutionError(Reason.SERVER_UNRESOLVED, "hook data has no server")
    mgr = manager if manager is not None else global_manager()
    try:
        server = mgr._resolve_mcp_server_for_tool_call(hook.server_name, hook.tool_name)
    except Exception as exc:
        raise ServerResolutionError(Reason.SERVER_UNRESOLVED, type(exc).__name__) from exc
    return _to_resolved(server, len(_matching_servers(mgr, hook.server_name)))


def resolve_listed_server(hook: HookData, *, manager: Any = None) -> ResolvedServer:
    """도구 목록 검사에서 검사 대상 서버.

    목록 검사는 도구 경로표가 채워지기 전에 실행되므로 실행 단계의 해석 함수가 도구를 찾지
    못한다. 서버 이름이 가리키는 레지스트리 항목이 하나일 때만 서버를 정하고, 여럿이면 첫
    항목과 후보 수를 돌려주어 호출 쪽이 모호함으로 처리한다.
    """
    if hook.server_name is None:
        raise ServerResolutionError(Reason.SERVER_UNRESOLVED, "hook data has no server")
    mgr = manager if manager is not None else global_manager()
    matches = _matching_servers(mgr, hook.server_name)
    if not matches:
        raise ServerResolutionError(Reason.SERVER_UNRESOLVED, "no registry entry")
    return _to_resolved(matches[0], len(matches))


def register_contract_tools(
    tools_by_server: Mapping[str, Sequence[str]], *, manager: Any = None
) -> int:
    """관리 중인 서버의 계약 도구 이름을 이 워커의 도구 경로표에 올린다.

    LiteLLM은 호출 때 MINT 훅보다 먼저 경로표로 서버를 풀고, 경로표는 그 워커가 목록으로 읽은
    도구로만 채워진다. MINT가 목록에서 숨긴 도구는 어느 워커에도 올라가지 못해 호출이 판정에
    닿기 전에 「찾을 수 없음」으로 끝난다. 목록 노출은 바꾸지 않고, 계약에 있는 이름만 목록
    등록과 같은 철자·접두사 규칙으로 올린다. 이미 있는 항목은 다시 쓰지 않고, 다른 서버가
    가진 철자는 건드리지 않는다. 새로 올린 철자 수를 돌려준다.
    """
    mgr = manager if manager is not None else global_manager()
    utils = importlib.import_module(_UTILS_MODULE)
    registry = importlib.import_module(
        "litellm.proxy._experimental.mcp_server.tool_registry"
    ).global_mcp_tool_registry
    mapping = mgr.tool_name_to_mcp_server_name_mapping
    added = 0
    for server in mgr.get_registry().values():
        prefix = utils.get_server_prefix(server)
        for tool in tools_by_server.get(server.server_id, ()):
            for spelling in utils.iter_known_tool_name_spellings(tool, server):
                owner = mgr.server_owning_tool_name_prefix(spelling)
                if owner is not None and owner.server_id != server.server_id:
                    continue
                if owner is None and registry.get_tool(spelling) is not None:
                    continue
                if spelling in mapping:
                    continue  # 이미 올라가 있다: 같은 서버면 그대로, 다른 서버면 건드리지 않는다
                mapping[spelling] = prefix
                added += 1
    return added


_REGISTRY_RELOAD_SECONDS = 5.0


def install_contract_retry(
    load: Callable[[], Awaitable[Mapping[str, Sequence[str]]]],
    unmanaged: Callable[[], Awaitable[Collection[str]]],
    *,
    manager: Any = None,
) -> None:
    """도구 호출이 서버를 못 풀면 서버 목록과 계약 이름을 다시 읽어 경로표를 채운 뒤 넘긴다.

    LiteLLM은 호출 진입에서 훅보다 먼저 서버를 풀고 그 앞에 끼어들 훅이 없다. 다른 복제본이나
    워커가 방금 등록·승인한 서버는 이 워커의 레지스트리와 경로표에 아직 없을 수 있다. 풀이만
    미리 시도해 실패할 때만 레지스트리(5초에 한 번)와 계약 이름을 읽고, 그래도 못 풀면 계약이
    없는 서버(``unmanaged``)의 호출 도구를 그 서버의 것으로 올려 훅이 승인 범위로 판정하게 한다.
    계약이 있는 서버의 계약 밖 도구는 LiteLLM이 그대로 거절한다. 도구 실행은 감싸지 않아 재시도로
    부작용이 겹치지 않는다. 읽기가 실패하면 LiteLLM이 원래대로 거절한다. 한 번만 감싼다.
    """
    mgr = manager if manager is not None else global_manager()
    original = mgr.call_tool
    if getattr(original, "mint_contract_retry", False):
        return
    lock = asyncio.Lock()
    reloaded = [-_REGISTRY_RELOAD_SECONDS]

    def resolved(server_name: str, name: str) -> bool:
        try:
            mgr._resolve_mcp_server_for_tool_call(server_name, name)
        except ValueError:
            return False
        return True

    async def refill(server_name: str, name: str) -> None:
        now = time.monotonic()
        if now - reloaded[0] >= _REGISTRY_RELOAD_SECONDS:
            reloaded[0] = now
            await mgr.reload_servers_from_database()
        register_contract_tools(await load(), manager=mgr)
        if resolved(server_name, name):
            return
        matches = _matching_servers(mgr, server_name)
        if len(matches) == 1 and matches[0].server_id in await unmanaged():
            register_contract_tools({matches[0].server_id: (name,)}, manager=mgr)

    async def call_tool(server_name: str, name: str, *args: Any, **kwargs: Any) -> Any:
        if not resolved(server_name, name):
            async with lock:
                if not resolved(server_name, name):
                    with contextlib.suppress(Exception):
                        await refill(server_name, name)
        return await original(server_name, name, *args, **kwargs)

    call_tool.mint_contract_retry = True  # type: ignore[attr-defined]
    mgr.call_tool = call_tool


@dataclass(frozen=True)
class RegistryEntry:
    server_id: str
    names: tuple[str, ...]
    url_sha256: str | None
    transport: str
    auth_type: str
    allow_all_keys: bool
    issuer: str | None = None
    # LiteLLM 재사용 정책 점검이 읽는 값. 자격은 해시만 둔다.
    discovery_oauth: bool = False
    per_user_oauth: bool = False
    binding_mode: str | None = None
    timeout: float | None = None
    credential: str | None = None
    rpm: int | None = None
    max_concurrent: int | None = None
    in_database: bool = False
    header_credentials: tuple[str, ...] = ()
    gateway_oauth: bool = False
    upstream_resource: str | None = None
    forwards_token: bool = False

    def facts(self) -> ServerFacts:
        return ServerFacts(
            self.names[0] if self.names else self.server_id,
            self.discovery_oauth,
            self.per_user_oauth,
            self.issuer,
            self.binding_mode,
            self.timeout,
            self.credential,
            self.rpm,
            self.max_concurrent,
            self.header_credentials,
            self.in_database,
            self.gateway_oauth,
            self.upstream_resource,
            self.forwards_token,
        )


def _credential(server: Any) -> str | None:
    if getattr(server, "has_client_credentials", False):
        return credential_digest(
            getattr(server, "client_id", None), getattr(server, "client_secret", None)
        )
    return credential_digest(getattr(server, "authentication_token", None))


def registry_entries(*, manager: Any = None) -> list[RegistryEntry]:
    mgr = manager if manager is not None else global_manager()
    database_ids = frozenset(getattr(mgr, "registry", None) or ())  # 설정 파일 서버는 따로 있다
    return [
        RegistryEntry(
            server_id=server.server_id,
            names=tuple(n for n in (server.alias, server.server_name, server.name) if n),
            url_sha256=url_sha256(server.url) if server.url else None,
            transport=_enum_text(server.transport),
            auth_type=normalize_auth_type(server.auth_type),
            allow_all_keys=bool(server.allow_all_keys),
            issuer=getattr(server, "issuer", None),
            discovery_oauth=normalize_auth_type(server.auth_type) in DISCOVERY_AUTH,
            per_user_oauth=bool(
                getattr(server, "needs_user_oauth_token", False)
                and not getattr(server, "delegate_auth_to_upstream", False)
            ),
            binding_mode=getattr(getattr(server, "oauth_identity_binding", None), "mode", None),
            timeout=getattr(server, "timeout", None),
            credential=_credential(server),
            rpm=getattr(server, "rpm", None),
            max_concurrent=getattr(server, "max_concurrent_requests", None),
            in_database=server.server_id in database_ids,
            header_credentials=header_credential_digests(getattr(server, "static_headers", None)),
            gateway_oauth=normalize_auth_type(server.auth_type) == "oauth2"
            and getattr(server, "delegate_auth_to_upstream", False) is not True,
            upstream_resource=getattr(server, "upstream_resource", None),
            forwards_token=forwards_client_token(
                normalize_auth_type(server.auth_type),
                getattr(server, "delegate_auth_to_upstream", False),
                getattr(server, "extra_headers", None),
            ),
        )
        for server in mgr.get_registry().values()
    ]


def logging_details(logging_obj: Any) -> dict[str, Any] | None:
    """호출 로깅 객체의 ``model_call_details``. 사전 훅과 응답·실패 이벤트가 공유한다."""
    details = getattr(logging_obj, "model_call_details", None)
    return details if isinstance(details, dict) else None


def failure_exception(kwargs: Mapping[str, Any]) -> BaseException | None:
    exc = kwargs.get("exception")
    return exc if isinstance(exc, BaseException) else None


def is_tool_result_error(exc: BaseException | None) -> bool:
    """업스트림이 ``isError`` 결과를 돌려준 호출의 실패 이벤트."""
    return exc is not None and type(exc).__name__ == "MCPToolResultError"


def exception_status(exc: BaseException | None) -> int | None:
    status = getattr(exc, "status_code", None)
    return status if isinstance(status, int) else None


def content_texts(content: object) -> list[str]:
    """도구 결과 내용 블록의 본문(텍스트 블록과 내장 리소스의 텍스트)."""
    texts: list[str] = []
    for block in content if isinstance(content, (list, tuple)) else ():
        text = getattr(block, "text", None)
        if text is None:
            text = getattr(getattr(block, "resource", None), "text", None)
        if isinstance(text, str):
            texts.append(text)
    return texts


def structured_texts(result: object, *, limit: int = 4096, depth: int = 20) -> list[str]:
    """도구 결과의 ``structuredContent`` 문자열 값과 키. 개수·깊이를 넘는 부분은 보지 않는다."""
    root = getattr(result, "structured_content", None)
    if root is None and isinstance(result, Mapping):
        root = result.get("structuredContent")
    texts: list[str] = []
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack and len(texts) < limit:
        item, level = stack.pop()
        if isinstance(item, str):
            texts.append(item)
        elif level < depth and isinstance(item, Mapping):
            for key, child in item.items():
                stack += [(str(key), level + 1), (child, level + 1)]
        elif level < depth and isinstance(item, (list, tuple)):
            stack += [(child, level + 1) for child in item]
    return texts


def content_size(content: object) -> int | None:
    if not isinstance(content, (list, tuple)):
        return None
    total = 0
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            total += len(text.encode("utf-8"))
        elif hasattr(block, "model_dump_json"):
            total += len(block.model_dump_json().encode("utf-8"))
    return total


def tool_result_size(result: object) -> int | None:
    return content_size(getattr(result, "content", None))


def mask_tool_content(response: Any, mask: Callable[[str], str]) -> None:
    """후처리 훅이 받은 결과의 텍스트 블록과 내장 리소스 텍스트에 ``mask``를 적용한다."""
    for block in response.mcp_tool_call_response:
        holder = block if isinstance(getattr(block, "text", None), str) else getattr(
            block, "resource", None
        )
        if isinstance(getattr(holder, "text", None), str):
            holder.text = mask(holder.text)


def replace_tool_content(response: Any, text: str) -> None:
    """후처리 훅이 받은 결과 내용을 텍스트 블록 하나로 바꾼다(호출자에게 가는 값이 바뀐다)."""
    from mcp.types import TextContent

    response.mcp_tool_call_response[:] = [TextContent(type="text", text=text)]


def litellm_callbacks() -> list[Any]:
    import litellm

    return list(litellm.callbacks)


def register_callback(callback: Any) -> None:
    """LiteLLM이 가드레일 등을 목록에 올릴 때 쓰는 공개 등록 방법. 중복은 올리지 않는다."""
    import litellm

    litellm.logging_callback_manager.add_litellm_callback(callback)


def unregister_callback(callback: Any) -> None:
    import litellm

    litellm.callbacks[:] = [cb for cb in litellm.callbacks if cb is not callback]


def general_settings() -> Mapping[str, Any]:
    # 시작 단계에서 모듈 전역이 다시 바인딩되므로 가져올 때마다 모듈에서 읽는다.
    return importlib.import_module("litellm.proxy.proxy_server").general_settings


def litellm_attribute(name: str, default: Any) -> Any:
    import litellm

    return getattr(litellm, name, default)


def strict_guardrail_modes_enabled(env: Mapping[str, str]) -> bool:
    raw = env.get("LITELLM_STRICT_GUARDRAIL_MODES")
    if raw is None:
        return True
    parsed = importlib.import_module("litellm.secret_managers.main").str_to_bool(raw)
    return True if parsed is None else parsed


def ssl_verification_enabled(env: Mapping[str, str]) -> bool:
    """LiteLLM이 쓰는 TLS 인증서 검증 여부. 환경 변수 ``SSL_VERIFY``가 설정 값보다 앞선다."""
    value = env.get("SSL_VERIFY")
    return ssl_verify_on(litellm_attribute("ssl_verify", True) if value is None else value)


def mcp_default_timeout() -> float:
    """서버에 제한 시간이 없을 때 LiteLLM이 쓰는 도구 호출 제한 시간(초)."""
    try:
        return float(importlib.import_module("litellm.constants").MCP_CLIENT_TIMEOUT)
    except (AttributeError, TypeError, ValueError):
        return DEFAULT_TOOL_TIMEOUT_SECONDS


def spend_logs_store_prompts() -> bool:
    mod = importlib.import_module("litellm.proxy.spend_tracking.spend_tracking_utils")
    return bool(mod.should_store_prompts_and_responses_in_spend_logs())


def installed_litellm_version() -> str | None:
    try:
        return importlib.metadata.version("litellm")
    except importlib.metadata.PackageNotFoundError:
        return None


# (모듈, 객체 경로). 판본이 바뀌어 사라지면 자가 점검이 기동을 멈춘다.
_REQUIRED_SYMBOLS: tuple[tuple[str, str], ...] = (
    (_MANAGER_MODULE, "global_mcp_server_manager"),
    (_MANAGER_MODULE, "global_mcp_server_manager._resolve_mcp_server_for_tool_call"),
    (_MANAGER_MODULE, "global_mcp_server_manager.get_registry"),
    (_MANAGER_MODULE, "global_mcp_server_manager.catalog"),
    (_MANAGER_MODULE, "global_mcp_server_manager.reload_servers_from_database"),
    (_MANAGER_MODULE, "global_mcp_server_manager.tool_name_to_mcp_server_name_mapping"),
    (_MANAGER_MODULE, "global_mcp_server_manager.server_owning_tool_name_prefix"),
    (_UTILS_MODULE, "get_server_prefix"),
    (_UTILS_MODULE, "iter_known_tool_name_spellings"),
    (
        "litellm.proxy._experimental.mcp_server.tool_registry",
        "global_mcp_tool_registry.get_tool",
    ),
    (_UTILS_MODULE, "normalize_server_name"),
    ("litellm.constants", "LITELLM_PROXY_MASTER_KEY_ALIAS"),
    ("litellm.secret_managers.main", "str_to_bool"),
    ("litellm.proxy.proxy_server", "general_settings"),
    (
        "litellm.proxy.spend_tracking.spend_tracking_utils",
        "should_store_prompts_and_responses_in_spend_logs",
    ),
    ("litellm.integrations.custom_logger", "CustomLogger.async_pre_call_hook"),
    ("litellm.integrations.custom_logger", "CustomLogger.async_log_success_event"),
    ("litellm.integrations.custom_logger", "CustomLogger.async_log_failure_event"),
    ("litellm.integrations.custom_guardrail", "CustomGuardrail"),
    ("litellm", "callbacks"),
)


def _lookup(module: str, path: str, importer: Callable[[str], Any]) -> bool:
    try:
        obj = importer(module)
        for part in path.split("."):
            obj = getattr(obj, part)
    except Exception:
        return False
    return True


def litellm_assessment() -> capabilities.Assessment:
    return capabilities.assess(SUPPORTED_LITELLM_VERSIONS, version=installed_litellm_version())


def missing_symbols(
    *,
    importer: Callable[[str], Any] = importlib.import_module,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """기동을 막는 사유. 비어 있으면 이 LiteLLM에서 모든 보장이 성립한다.

    등급 A이고 시험한 판본이면 비어 있다. 시험하지 않은 판본은 모든 능력이 감지되어도
    ``MINT_ALLOW_UNTESTED_LITELLM=true``로 운영자가 명시해야 허용한다. 등급 B·C·D는
    빠진 능력을 밝히고 거부한다(저하 운용은 아직 없다).
    """
    missing = [
        f"{module}:{path}"
        for module, path in _REQUIRED_SYMBOLS
        if not _lookup(module, path, importer)
    ]
    found = capabilities.assess(
        SUPPORTED_LITELLM_VERSIONS, importer=importer, version=installed_litellm_version()
    )
    if found.version is None:
        return [*missing, "litellm: not installed"]
    if found.grade != "A":
        missing.append(
            f"litellm {found.version} grade {found.grade}: missing capability "
            f"{', '.join(found.missing) or '-'} (only grade A can start)"
        )
    elif not found.tested and not capabilities.allow_untested(env):
        supported = ", ".join(SUPPORTED_LITELLM_VERSIONS)
        missing.append(
            f"litellm in {{{supported}}} (installed: {found.version}, untested; "
            "MINT_ALLOW_UNTESTED_LITELLM=true allows it)"
        )
    return missing

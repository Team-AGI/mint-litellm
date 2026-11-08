"""LiteLLM 1.106 계열과의 접점.

LiteLLM의 비공개 심볼과 훅 데이터 형태에 대한 의존은 모두 이 모듈에 둔다. 다른 모듈은
LiteLLM을 직접 가져오지 않는다. 함수는 가져오기를 호출 시점으로 미뤄, LiteLLM이 설치되지
않은 환경에서도 모듈을 읽을 수 있고 시험에서는 서버 관리자 객체를 인자로 바꿔 넣을 수 있다.
"""

from __future__ import annotations

import importlib
import importlib.metadata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mint_litellm.types.decision import ResolvedServer, normalize_auth_type, url_sha256
from mint_litellm.types.identity import Principal, classify_principal
from mint_litellm.types.reason_codes import Reason

SUPPORTED_LITELLM_VERSION = "1.106.6"

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
    return classify_principal(
        instance_id=instance_id,
        key_id=key_id,
        user_id=getattr(user_api_key_dict, "user_id", None),
        team_id=getattr(user_api_key_dict, "team_id", None),
        metadata=metadata if isinstance(metadata, Mapping) else None,
        is_master_key=key_id == alias or getattr(user_api_key_dict, "api_key", None) == alias,
        claimed_end_user_id=getattr(user_api_key_dict, "end_user_id", None) or None,
    )


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


def _to_resolved(server: Any, candidates: int) -> ResolvedServer:
    if not getattr(server, "url", None):
        # 로컬 실행(stdio)·OpenAPI 서버는 계약 URL 해시를 만들 수 없어 1단계가 지원하지 않는다.
        raise ServerResolutionError(Reason.UNSUPPORTED, "server_without_url")
    return ResolvedServer(
        server_id=server.server_id,
        url_sha256=url_sha256(server.url),
        transport=_enum_text(server.transport),
        auth_type=normalize_auth_type(server.auth_type),
        candidates_with_same_name=max(candidates, 1),
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


@dataclass(frozen=True)
class RegistryEntry:
    server_id: str
    names: tuple[str, ...]
    url_sha256: str | None
    transport: str
    auth_type: str
    allow_all_keys: bool
    issuer: str | None = None


def registry_entries(*, manager: Any = None) -> list[RegistryEntry]:
    mgr = manager if manager is not None else global_manager()
    return [
        RegistryEntry(
            server_id=server.server_id,
            names=tuple(n for n in (server.alias, server.server_name, server.name) if n),
            url_sha256=url_sha256(server.url) if server.url else None,
            transport=_enum_text(server.transport),
            auth_type=normalize_auth_type(server.auth_type),
            allow_all_keys=bool(server.allow_all_keys),
            issuer=getattr(server, "issuer", None),
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


def tool_result_size(result: object) -> int | None:
    content = getattr(result, "content", None)
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


def missing_symbols(*, importer: Callable[[str], Any] = importlib.import_module) -> list[str]:
    """지원 판본에서 쓰는 LiteLLM 심볼 중 없는 것의 이름. 모두 있으면 빈 목록이다."""
    missing = [
        f"{module}:{path}"
        for module, path in _REQUIRED_SYMBOLS
        if not _lookup(module, path, importer)
    ]
    version = installed_litellm_version()
    if version != SUPPORTED_LITELLM_VERSION:
        missing.append(f"litellm=={SUPPORTED_LITELLM_VERSION} (installed: {version})")
    return missing

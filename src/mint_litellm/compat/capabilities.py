"""설치된 LiteLLM이 MINT가 쓰는 훅 지점을 갖췄는지 감지해 보장 등급을 정한다.

등급은 판본 번호가 아니라 감지된 능력으로 정한다.

- A: 호출 판정, 결과 단계 가드레일, 도구 목록 훅, 이름 해석을 모두 쓸 수 있다. 모든 보장이 성립한다.
- B: 호출 판정과 결과 단계는 있으나 도구 목록 훅이 없다. 목록 숨김은 LiteLLM 권한 동기화에만 기댄다.
- C: 호출 판정만 있다. 결과 단계 가드레일이 없어 결과는 로거 훅으로 관측만 한다.
- D: 호출 판정 지점이 없다. 지원하지 않는다.

지금 구현은 A만 기동을 허용한다. B·C·D는 빠진 능력 이름을 밝히고 기동을 거부한다(닫힌 실패).
"""

from __future__ import annotations

import importlib
import importlib.metadata
import inspect
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

# 능력 이름, 등급 층(C가 가장 낮은 층), 확인 방식
#   ("attr", 모듈, 경로)                  객체가 있다
#   ("params", 모듈, 경로, (매개변수...))  호출 가능하며 해당 매개변수가 있다
_Probe = tuple[str, ...]

_MANAGER = "litellm.proxy._experimental.mcp_server.mcp_server_manager"
_GUARDRAILS = "litellm.types.guardrails"
_LOGGER = "litellm.integrations.custom_logger"

CAPABILITIES: tuple[tuple[str, str, _Probe], ...] = (
    ("call_guardrail_mode", "C", ("attr", _GUARDRAILS, "GuardrailEventHooks.pre_mcp_call")),
    ("call_type_call", "C", ("attr", "litellm.types.utils", "CallTypes.call_mcp_tool")),
    (
        "pre_call_hook",
        "C",
        ("params", _LOGGER, "CustomLogger.async_pre_call_hook",
         "user_api_key_dict", "cache", "data", "call_type"),
    ),
    (
        "server_resolution",
        "C",
        ("params", _MANAGER, "global_mcp_server_manager._resolve_mcp_server_for_tool_call",
         "server_name", "name"),
    ),
    (
        "result_logger_hook",
        "C",
        ("params", _LOGGER, "CustomLogger.async_post_mcp_tool_call_hook",
         "kwargs", "response_obj", "start_time", "end_time"),
    ),
    ("result_guardrail_mode", "B", ("attr", _GUARDRAILS, "GuardrailEventHooks.post_mcp_call")),
    ("list_hook", "A", ("attr", "litellm.types.utils", "CallTypes.list_mcp_tools")),
    ("name_resolution", "A", ("attr", "litellm.proxy._experimental.mcp_server.utils",
                              "iter_known_tool_name_spellings")),
    ("tool_prefix_registry", "A", ("attr", _MANAGER,
                                   "global_mcp_server_manager.server_owning_tool_name_prefix")),
)


def _resolve(module: str, path: str, importer: Callable[[str], Any]) -> Any:
    obj = importer(module)
    for part in path.split("."):
        obj = getattr(obj, part)
    return obj


def _present(probe: _Probe, importer: Callable[[str], Any]) -> bool:
    try:
        obj = _resolve(probe[1], probe[2], importer)
        if probe[0] == "params":
            params = inspect.signature(obj).parameters
            return all(name in params for name in probe[3:])
    except Exception:
        return False
    return True


@dataclass(frozen=True)
class Assessment:
    version: str | None
    grade: str  # "A" | "B" | "C" | "D"
    missing: tuple[str, ...]  # 빠진 능력 이름
    tested: bool  # 시험한 판본 목록에 있다

    @property
    def summary(self) -> str:
        if self.grade == "D" and self.version is None:
            return "LiteLLM이 설치되어 있지 않음"
        note = "" if self.tested else " (검증되지 않은 판본)"
        return f"LiteLLM {self.version} 등급 {self.grade}{note}"


def installed_version() -> str | None:
    try:
        return importlib.metadata.version("litellm")
    except importlib.metadata.PackageNotFoundError:
        return None


def grade_of(present: Mapping[str, bool]) -> str:
    """층마다 모두 있어야 그 층이 성립하고, 아래 층이 깨지면 위 층도 성립하지 않는다."""
    grade = "D"
    for tier in ("C", "B", "A"):
        names = [name for name, t, _ in CAPABILITIES if t == tier]
        if not all(present.get(name) for name in names):
            break
        grade = tier
    return grade


def assess(
    tested_versions: tuple[str, ...],
    *,
    importer: Callable[[str], Any] = importlib.import_module,
    version: str | None = None,
) -> Assessment:
    found = installed_version() if version is None else version
    present = {name: _present(probe, importer) for name, _, probe in CAPABILITIES}
    missing = tuple(name for name, ok in present.items() if not ok)
    grade = grade_of(present) if found is not None else "D"
    return Assessment(found, grade, missing, found in tested_versions)


def allow_untested(env: Mapping[str, str] | None = None) -> bool:
    """검증되지 않은 판본을 운영자가 명시해 허용했는가. 기본은 거부한다."""
    raw = (os.environ if env is None else env).get("MINT_ALLOW_UNTESTED_LITELLM", "")
    return raw.strip().lower() in ("1", "true", "yes", "on")

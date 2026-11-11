"""OPA 판정 요청과 활성 판본 확인."""

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any

import aiohttp
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mint_litellm.plugin.obligations import normalize_policy_output
from mint_litellm.plugin.policy.input import has_only_policy_fields
from mint_litellm.types.decision import PolicyDecision, StageResult
from mint_litellm.types.reason_codes import Reason


class PolicyOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    decision: str
    policy_ids: list[str]
    policy_version_id: str = Field(min_length=1)
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    obligations: list[dict[str, Any]]
    observable: bool
    missing_inputs: list[str]


@dataclass(frozen=True)
class Evaluation:
    output: PolicyOutput | None = None
    failure: StageResult | None = None


_JSON = {"Content-Type": "application/json"}


class OPAClient:
    """OPA 판정 클라이언트. 연결을 재사용하고 시간 제한은 호출마다 받는다.

    HTTP 클라이언트는 aiohttp이다. 호출 한 번에 이벤트 루프를 깨우는 횟수와 CPU가 httpx보다 적어서,
    처리 흐름이 가득 찬 복제본에서 판정이 기다리는 시간이 줄어든다.

    연결이 끊기거나 OPA가 재시작되어 요청이 실패하면 그 호출은 ``DEPENDENCY_FAILURE``로
    차단되며, 끊어진 연결은 풀에서 제거되어 다음 호출이 새로 연결한다.

    수명 계약: 인스턴스는 워커 프로세스의 이벤트 루프마다 하나씩 만들고, 그 루프가 끝나기 전
    종료 훅에서 ``aclose()``를 호출한다. 연결을 만든 뒤 다른 이벤트 루프나 fork된 자식
    프로세스에서 쓰면 ``RuntimeError``가 난다.
    """

    def __init__(self, base_url: str, timeout_seconds: float) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._url = base_url.rstrip("/") + "/v1/data/mint/decision"
        self._context_url = base_url.rstrip("/") + "/v1/data/mint/context"
        self._markers: tuple[tuple[str, str], tuple[str, ...]] | None = None
        self._timeout = timeout_seconds
        self._client: aiohttp.ClientSession | None = None
        self._owner: tuple[int, asyncio.AbstractEventLoop] | None = None

    async def aclose(self) -> None:
        client, self._client, self._owner = self._client, None, None
        if client is not None:
            await client.close()

    def _http(self) -> aiohttp.ClientSession:
        owner = (os.getpid(), asyncio.get_running_loop())
        if self._client is None:
            self._client = aiohttp.ClientSession(
                trust_env=False, cookie_jar=aiohttp.DummyCookieJar()
            )
            self._owner = owner
        elif self._owner != owner:
            raise RuntimeError("OPAClient is bound to the process and event loop that created it")
        return self._client

    async def secret_markers(
        self, *, policy_version_id: str, bundle_sha256: str, budget_seconds: float | None = None
    ) -> tuple[str, ...] | None:
        """활성 번들의 비밀 표지 목록. 판본마다 한 번만 읽고, 판본이 다르면 ``None``이다."""
        version = (policy_version_id, bundle_sha256)
        if self._markers is not None and self._markers[0] == version:
            return self._markers[1]
        budget = self._timeout if budget_seconds is None else budget_seconds
        if budget <= 0:
            return None
        try:
            async with self._http().get(
                self._context_url,
                timeout=aiohttp.ClientTimeout(total=budget),
                allow_redirects=False,
            ) as response:
                response.raise_for_status()
                result = json.loads(await response.read())["result"]
            meta = (result["bundle"]["policy_version_id"], result["bundle"]["bundle_sha256"])
            markers = tuple(result["secret_markers"])
        except (KeyError, TypeError, ValueError, aiohttp.ClientError, TimeoutError):
            return None
        if meta != version or not all(isinstance(m, str) and m for m in markers):
            return None
        self._markers = (version, markers)
        return markers

    async def evaluate(
        self,
        policy_input: dict[str, Any],
        *,
        policy_version_id: str,
        bundle_sha256: str,
        budget_seconds: float | None = None,
    ) -> Evaluation:
        """``budget_seconds``는 이 호출에 남은 판정 예산이다(없으면 생성 시 값)."""
        if not has_only_policy_fields(policy_input):
            return Evaluation(failure=StageResult.stop(Reason.SCHEMA_ERROR))
        budget = self._timeout if budget_seconds is None else budget_seconds
        if budget <= 0:
            return Evaluation(failure=StageResult.stop(Reason.DEPENDENCY_FAILURE))
        deadline = asyncio.get_running_loop().time() + budget
        body = json.dumps(
            {"input": policy_input}, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode()
        try:
            async with asyncio.timeout_at(deadline):
                client = self._http()
                for _ in range(2):
                    remaining = deadline - asyncio.get_running_loop().time()
                    async with client.post(
                        self._url,
                        data=body,
                        headers=_JSON,
                        timeout=aiohttp.ClientTimeout(total=max(remaining, 0.001)),
                        allow_redirects=False,
                    ) as response:
                        response.raise_for_status()
                        payload = await response.read()
                    try:
                        result = json.loads(payload)["result"]
                        output = PolicyOutput.model_validate(result)
                    except (KeyError, TypeError, ValueError, ValidationError):
                        return Evaluation(failure=StageResult.stop(Reason.SCHEMA_ERROR))
                    if (output.policy_version_id, output.bundle_sha256) == (
                        policy_version_id,
                        bundle_sha256,
                    ):
                        if output.missing_inputs:
                            return Evaluation(failure=StageResult.stop(Reason.SCHEMA_ERROR))
                        try:
                            PolicyDecision(output.decision)
                        except ValueError:
                            return Evaluation(failure=StageResult.stop(Reason.SCHEMA_ERROR))
                        normalized = normalize_policy_output(
                            output.decision, output.policy_ids, output.obligations
                        )
                        if normalized.failure is not None:
                            return Evaluation(failure=normalized.failure)
                        return Evaluation(output=output)
                return Evaluation(failure=StageResult.stop(Reason.POLICY_VERSION_MISMATCH))
        except (TimeoutError, aiohttp.ClientError):
            return Evaluation(failure=StageResult.stop(Reason.DEPENDENCY_FAILURE))

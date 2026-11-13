"""LiteLLM 제어 평면 클라이언트: 동기화 쓰기 클라이언트에 수용검증 읽기·시험 경로를 더한다.

쓰기의 경로·본문 제한(``litellm_write.check_write``)과 쓰기 직전 훅은 ``LiteLLMSync``의 것을
그대로 쓴다. 이 클래스는 두 가지만 더한다.

- 쓰기 직전 훅이 없는 사본으로는 쓰지 않는다(기본값이 안전한 쪽이다).
- 수용검증 읽기: 제출 목록, 업스트림 시험 경로(``/mcp-rest/test/*``), 제출 승인·거절 결과 해석,
  ``allow_all_keys`` 끄기와 확인.
"""

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_admin import LiteLLMError, scrub
from mint_litellm.control.litellm_write import LiteLLMHttpError, LiteLLMSync

# 수용검증이 제어 평면 키의 allowed_routes에 더하는 경로(공통 목록에 이어 붙인다).
STAGE2_ALLOWED_ROUTES: tuple[str, ...] = (
    "/mcp-rest/test/connection",
    "/mcp-rest/test/tools/list",
)

# 업스트림 서버에 접속해 보는 시험 경로(LiteLLM 상태를 바꾸지 않는다)
PROBE_ROUTES = frozenset({"/mcp-rest/test/connection", "/mcp-rest/test/tools/list"})
PROBE_FIELDS = frozenset({"url", "transport", "auth_type", "server_id"})
MAX_TOOLS_BYTES = 2 * 1024 * 1024
TOOLS_SECONDS = 10.0  # 정의 수집 전체(연결·응답 읽기)의 기한


class ResponseTooLarge(LiteLLMError):
    """응답이 상한(크기·중첩)을 넘었다."""


class ResponseTooSlow(ResponseTooLarge):
    """정의 수집이 기한(초)을 넘었다. 상한 초과의 한 종류라 시험 불가와 구분한다."""


def _read_within(response: Any, limit: int | None, end: float) -> bytes:
    """응답 본문을 ``end``(monotonic) 안에 읽는다. 조금씩 흘러오는 응답도 기한에 묶는다.

    수신 한 번의 제한 시간을 남은 시간으로 줄여 가며 읽어, 넘으면 소켓 시간 초과로 끝난다.
    """
    raw = b""
    sock = getattr(getattr(response.fp, "raw", None), "_sock", None)
    while (limit is None or len(raw) < limit) and not response.isclosed():
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError("deadline")
        if sock is not None:
            sock.settimeout(left)
        chunk = response.read1(65536 if limit is None else min(65536, limit - len(raw)))
        if not chunk:
            break
        raw += chunk
    return raw


class LiteLLMControl(LiteLLMSync):
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 35.0,
        guard: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(base_url, api_key, timeout, before_write=guard)

    def with_guard(self, guard: Callable[[], None]) -> "LiteLLMControl":
        """같은 접속으로 쓰기 직전 경계만 바꾼 사본."""
        return self.with_hook(guard)  # type: ignore[return-value]

    def _write(
        self, method: str, path: str, body: Any = None, params: dict[str, Any] | None = None
    ) -> Any:
        if self.before_write is None:
            # 경계 없는 쓰기는 하지 않는다(되돌림 상태·임대 유효성 확인을 건너뛰지 않게)
            raise ControlError(
                "쓰기 직전 경계(guard)가 없는 클라이언트로는 LiteLLM에 쓸 수 없습니다."
            )
        return super()._write(method, path, body, params)

    # --- 읽기·시험 ---------------------------------------------------------------

    def list_submissions(self) -> list[dict]:
        """제출 목록(``items``). 대기·승인·거절이 모두 들어 있으므로 호출자가 거른다."""
        body = self._ok("/v1/mcp/server/submissions", key="items", shape=list)
        return [item for item in body["items"] if isinstance(item, dict)]

    def _post(
        self, path: str, spec: dict, max_bytes: int | None, seconds: float | None = None
    ) -> dict:
        extra = set(spec) - PROBE_FIELDS
        if path not in PROBE_ROUTES or extra:
            raise ControlError(f"시험 요청에 허용되지 않은 필드입니다: {sorted(extra) or path}")
        request = urllib.request.Request(
            f"{self._base}{path}",
            data=json.dumps(spec).encode(),
            method="POST",
            headers={"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=seconds or self._timeout) as response:
                limit = None if max_bytes is None else max_bytes + 1
                status = response.status
                raw = response.read(limit) if seconds is None else _read_within(
                    response, limit, time.monotonic() + seconds)
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            if seconds and isinstance(getattr(error, "reason", error), TimeoutError):
                raise ResponseTooSlow(f"LiteLLM {path} 응답이 {seconds}초를 넘었습니다.") from None
            raise LiteLLMError(f"LiteLLM 관리 API에 연결할 수 없습니다: {error}") from None
        if max_bytes is not None and len(raw) > max_bytes:
            raise ResponseTooLarge(f"LiteLLM {path} 응답이 {max_bytes}바이트를 넘었습니다.")
        try:
            body = scrub(json.loads(raw)) if raw else None
        except RecursionError:
            raise ResponseTooLarge(f"LiteLLM {path} 응답의 중첩이 한도를 넘었습니다.") from None
        except ValueError:
            body = None
        if status in (401, 403):
            raise LiteLLMError(
                f"제어 평면 키로 {path}를 부를 수 없습니다(HTTP {status}). "
                "allowed_routes를 확인하십시오."
            )
        if status != 200 or not isinstance(body, dict):
            raise LiteLLMError(f"LiteLLM {path} 응답이 올바르지 않습니다(HTTP {status}).")
        return body

    def test_connection(self, spec: dict) -> dict:
        """``{status: "ok"}`` 또는 ``{status: "error", message}``. 연결 실패도 HTTP 200으로 온다."""
        return self._post("/mcp-rest/test/connection", spec, None)

    def test_tools_list(
        self, spec: dict, max_bytes: int = MAX_TOOLS_BYTES, seconds: float = TOOLS_SECONDS
    ) -> dict:
        """``{tools: [...]}`` 또는 ``{status: "error", message}``. ``seconds`` 안에 끝난다."""
        return self._post("/mcp-rest/test/tools/list", spec, max_bytes, seconds)

    # --- 쓰기 결과 해석 ------------------------------------------------------------

    def _review(self, call: Callable[[], Any], done_word: str) -> str:
        try:
            call()
        except LiteLLMHttpError as error:
            if error.status != 400:
                raise
            text = json.dumps(error.body, ensure_ascii=False) if error.body is not None else ""
            if f"already {done_word}" in text:
                return "already"
            return "refused"  # 이미 다른 상태로 결정된 제출: 재시도해도 같다(호출자가 정리한다)
        return "done"

    def approve_submission(self, server_id: str) -> str:
        """제출을 승인한다. ``done``·``already``(이미 승인)·``refused``(다른 사유의 400)."""
        return self._review(lambda: self.approve_server(server_id), "active")

    def reject_submission(self, server_id: str, notes: str) -> str:
        return self._review(lambda: self.reject_server(server_id, notes), "rejected")

    def close_all_keys(self, server_id: str) -> bool:
        """서버의 ``allow_all_keys``를 끄고 다시 읽어 확인한다. 꺼졌으면 참.

        ``PUT /v1/mcp/server``는 본문의 ``server_id``와 ``allow_all_keys``만 바꾸고 나머지
        (주소·인증·저장 자격)는 그대로 둔다(실측). 확인은 서버 상세 읽기로 한다.
        """
        try:
            self.disable_allow_all_keys(server_id)
        except LiteLLMHttpError:
            return False
        entry = self.get_server(server_id)
        return entry is not None and entry.get("allow_all_keys") is False

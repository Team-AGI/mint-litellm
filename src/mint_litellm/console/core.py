"""콘솔 공통: 설정, 요청마다 여는 DB 연결, 인증(세션 쿠키 또는 운영자 토큰), 오류 변환."""

import hmac
import re
import time
from collections import deque
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import psycopg
from fastapi import Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from mint_litellm.console.cookies import read_cookie
from mint_litellm.console.labels import SERVER
from mint_litellm.console.oidc import OidcConfig
from mint_litellm.control import operators, ui_sessions
from mint_litellm.control.config import ControlConfig
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import connect
from mint_litellm.control.errors import AdminCode, AdminError, AuthError, ControlError
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.litellm_write import LiteLLMKitKeys
from mint_litellm.control.policy_versions import PolicySource
from mint_litellm.control.services import console_sessions
from mint_litellm.control.stage2_config import Stage2Settings

COOKIE = "__Host-mint_session"
STAFF_COOKIE = "__Host-mint_staff"
UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})

STATUS = {
    AdminCode.FORBIDDEN: 403,
    AdminCode.SEPARATION_OF_DUTIES: 403,
    AdminCode.NOT_FOUND: 404,
    AdminCode.CONFLICT: 409,
    AdminCode.STALE_EVIDENCE: 409,
}
INVALID = "MINT-ADMIN-INVALID-INPUT"

# 화면에 보이는 입력 항목 이름. 요청 값 검증 오류가 영문 필드명 대신 이 이름으로 나간다.
FIELD_LABELS = {
    "valid_days": "유효 기간(일)", "scope_type": "범위 종류", "scope_id": "범위 대상",
    "tools": "도구", "kind": "증빙 종류", "summary": "확인한 내용", "ref": "문서 위치",
    "sha256": "문서 해시", "basis": "근거", "reason": "사유", "org_id": "조직 식별자",
    "name": "이름", "class": "구분", "requested_by": "신청자", "state_version": "화면 상태",
    "max_result_bytes": "결과 크기 상한", "max_result_items": "결과 항목 수 상한",
    "second_approver_token": "두 번째 승인자 토큰", "allowed_hosts": "허용 호스트",
    "window_minutes": "사용 기간", "purpose": "목적", "data_scope": "자료 범위",
}
# 명령줄 옵션 이름이 화면에 그대로 나오지 않게 하는 화면용 이름과 역할 이름.
OPTION_LABELS = {
    "second-approver": "두 번째 승인자 토큰", "allowed-host": "허용 호스트",
    "allowed-arg-key": "허용 인자 키", "allowed-path": "허용 경로", "reason": "사유",
    "tools": "도구", "basis": "근거", "scope": "범위", "email": "이메일", "url": "서버 주소",
    "user-id": "LiteLLM 사용자", "token-file": "운영자 토큰", "evidence-ref": "문서 위치",
    "evidence-sha256": "문서 해시", "valid-until": "유효 기한", "valid-from": "유효 시작",
}
ROLE_WORDS = {"admin": "관리자", "approver": "승인자", "viewer": "조회자"}
_OPTION = re.compile(r"--([a-z][a-z-]*)(으로|로|은|는|이|가|을|를|에는|에)?")
_SERVER_STATE = re.compile(
    r"서버 (\S+)는 (" + "|".join(SERVER) + r") 상태라 새 수용검증을 시작할 수 없습니다\."
)
_STALE = re.compile(r"\S+의 상태 버전이 요청\(\d+\)과 다릅니다\(현재 \d+\)\.[^.]*\.?")
_ROLE = re.compile(r"(?<![A-Za-z-])(admin|approver|viewer)(?![A-Za-z-])")


def _batchim(word: str) -> bool:
    return "가" <= word[-1] <= "힣" and (ord(word[-1]) - 0xAC00) % 28 != 0


def _particle(word: str, particle: str) -> str:
    pairs = {"으로": ("으로", "로"), "로": ("으로", "로"), "은": ("은", "는"), "는": ("은", "는"),
             "이": ("이", "가"), "가": ("이", "가"), "을": ("을", "를"), "를": ("을", "를")}
    if particle not in pairs:
        return particle
    with_final, without = pairs[particle]
    return with_final if _batchim(word) else without


def screen_message(message: str) -> str:
    """서비스 오류 문구를 화면용으로 바꾼다. 명령줄 옵션과 영문 역할 코드는 한글 이름으로."""

    def option(match: re.Match) -> str:
        label = OPTION_LABELS.get(match.group(1))
        if label is None:
            return match.group(0)
        return label + _particle(label, match.group(2) or "")

    message = message.replace(
        "토큰을 --second-approver로 함께 제시하십시오",
        "토큰을 「두 번째 승인자 토큰」 칸에 함께 입력하십시오",
    )
    message = message.replace("object_permission.mcp_servers", "MCP 서버 권한")
    message = _STALE.sub(
        "화면을 연 뒤 상태가 바뀌었습니다. 최신 내용을 확인하고 다시 누르십시오.", message
    )
    message = _OPTION.sub(option, message)
    message = _SERVER_STATE.sub(
        lambda m: f"서버 {m.group(1)}는 {SERVER[m.group(2)].text} 상태라 "
        "새 수용검증을 시작할 수 없습니다.",
        message,
    )
    return _ROLE.sub(lambda m: ROLE_WORDS[m.group(1)], message)


def invalid_fields(errors: list[dict]) -> str:
    """검증 오류 목록에서 항목 이름을 한글로 모은다(알 수 없는 이름은 「입력 항목」)."""
    names = []
    for e in errors:
        loc = [str(p) for p in e["loc"] if p not in ("body", "form", "query")]
        label = FIELD_LABELS.get(loc[0], "입력 항목") if loc else "입력 항목"
        if label not in names:
            names.append(label)
    return ", ".join(names)
DEFAULT_TIME_ZONE = "Asia/Seoul"
class ReadOnlyLiteLLM:
    """제어 평면 키의 읽기 경로 전용 클라이언트. 쓰기 메서드가 없고 확인 읽기만 낸다."""

    def __init__(self, admin: LiteLLMAdmin) -> None:
        self.get_key = admin.get_key
        self.get_team = admin.get_team
        self.get_user = admin.get_user
        self.get_server = admin.get_server
        self.list_servers = admin.list_servers
        self.spend_guardrail = admin.spend_guardrail
        self.daily_activity = admin.daily_activity


class Unauthenticated(AdminError):
    """로그인하지 않았거나 세션·토큰이 유효하지 않다(HTTP 401)."""

    def __init__(self, message: str = "로그인이 필요합니다.") -> None:
        super().__init__(AdminCode.FORBIDDEN, message)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes")


def _policy_source(env: Mapping[str, str]) -> PolicySource | None:
    opa_url = (env.get("MINT_OPA_URL") or "").strip()
    if not opa_url:
        return None
    return PolicySource(
        root=Path(env.get("MINT_POLICY_ROOT") or "/opt/mint"),
        opa="opa",
        bundle_path=Path(env.get("MINT_OPA_BUNDLE_PATH") or "/bundles/mint.tar.gz"),
        opa_url=opa_url,
        timeout_seconds=30.0,
    )


@dataclass(frozen=True)
class ConsoleConfig:
    control: ControlConfig
    stage2: Stage2Settings
    litellm_url: str
    # 승인·운영자 등록처럼 LiteLLM 읽기가 필요한 변경에만 쓴다. 없으면 그 변경은 거부한다.
    litellm_admin: ReadOnlyLiteLLM | None
    database_url: str
    # 직원 화면 전용 로그인 역할(mint_staff_app)의 주소. 없으면 직원 화면을 열지 않는다.
    staff_database_url: str | None = None
    # 화면에 보이는 모든 시각의 시간대(IANA 이름). 환경 변수 MINT_CONSOLE_TIME_ZONE로 바꾼다.
    time_zone: str = DEFAULT_TIME_ZONE
    # 단말 설치 묶음의 사용자 키를 발급하는 키로 연 클라이언트. 없으면 묶음을 내려받을 수 없다.
    kit_issuer: LiteLLMKitKeys | None = None
    # 단말이 판정 경로를 부르는 주소(없으면 LiteLLM 주소)와 그 서버 인증서(사설 인증 기관이면)
    endpoint_url: str | None = None
    endpoint_ca_pem: str | None = None
    # 관리형 단말이 격리할 수 없을 때 서버를 격리 없이 시작해도 되는가(기본 아니오)
    endpoint_allow_unsandboxed: bool = False
    # 단말 경로(MINT_ENDPOINT_ROUTES)가 켜져 있는가. 꺼져 있으면 발급한 묶음의 보고·판정이 404이다.
    endpoint_routes: bool = False
    # 정책 판본을 적용할 때 쓰는 번들 원본과 정책 엔진. 정책 엔진 주소가 없으면 적용하지 않는다.
    policy_source: PolicySource | None = None
    # 호출 기록 상세에서 LiteLLM 지출 기록의 가드레일 기록을 읽는다. 제어 평면 키에
    # ``/spend/logs``를 열어 둔 배포만 켠다(MINT_SPEND_LOG_LOOKUP).
    spend_lookup: bool = False
    # OIDC 로그인 설정(MINT_OIDC_*). 없으면 SSO 버튼을 보이지 않는다.
    oidc: OidcConfig | None = None
    # 본인 LiteLLM 키 입력 로그인. 기본은 끔이며 비상 접속용으로만 MINT_CONSOLE_KEY_LOGIN=on.
    key_login: bool = False
    # 로그인 화면의 LiteLLM 관리 화면 링크 주소(MINT_LITELLM_UI_URL). 없으면 링크를 숨긴다.
    litellm_ui_url: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "ConsoleConfig":
        control = ControlConfig.from_env(dict(env))
        stage2 = Stage2Settings.from_env(env)
        if not control.litellm_url:
            raise ControlError("MINT_LITELLM_URL이 설정되어 있지 않습니다.")
        admin = ReadOnlyLiteLLM(control.litellm()) if control.litellm_key else None
        staff_url = (env.get("MINT_STAFF_DATABASE_URL") or "").strip() or None
        zone = (env.get("MINT_CONSOLE_TIME_ZONE") or "").strip() or DEFAULT_TIME_ZONE
        try:
            ZoneInfo(zone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ControlError(f"MINT_CONSOLE_TIME_ZONE을 알 수 없습니다: {zone}") from None
        issuer_key = (env.get("MINT_KIT_ISSUER_KEY") or "").strip()
        ca_file = (env.get("MINT_ENDPOINT_CA_FILE") or "").strip()
        try:
            ca_pem = Path(ca_file).read_text(encoding="utf-8") if ca_file else None
        except OSError:
            raise ControlError("MINT_ENDPOINT_CA_FILE을 읽을 수 없습니다.") from None
        oidc_config = OidcConfig.from_env(env)
        key_login = (env.get("MINT_CONSOLE_KEY_LOGIN") or "").strip().lower() in (
            "on", "1", "true", "yes")
        ui_url = ((env.get("MINT_LITELLM_UI_URL") or "").strip()
                  or (env.get("PROXY_BASE_URL") or "").strip())
        ui_url = ui_url.rstrip("/") or None
        if ui_url and not ui_url.startswith(("https://", "http://")):
            raise ControlError("MINT_LITELLM_UI_URL은 http(s) 주소여야 합니다.")
        return cls(
            control, stage2, control.litellm_url, admin, control.require_database(), staff_url,
            zone,
            kit_issuer=LiteLLMKitKeys(control.litellm_url, issuer_key) if issuer_key else None,
            endpoint_url=(env.get("MINT_ENDPOINT_PUBLIC_URL") or "").strip() or None,
            endpoint_ca_pem=ca_pem,
            endpoint_allow_unsandboxed=_truthy(env.get("MINT_ENDPOINT_ALLOW_UNSANDBOXED")),
            endpoint_routes=_truthy(env.get("MINT_ENDPOINT_ROUTES")),
            policy_source=_policy_source(env),
            spend_lookup=_truthy(env.get("MINT_SPEND_LOG_LOOKUP")),
            oidc=oidc_config,
            key_login=key_login,
            litellm_ui_url=ui_url,
        )

    @property
    def kit_gap(self) -> str:
        """설치 묶음 발급에 필요한데 빠진 설정(관리자용 이름). 갖췄으면 빈 문자열."""
        missing = []
        if self.kit_issuer is None:
            missing.append("MINT_KIT_ISSUER_KEY(설치 묶음 발급 키)")
        if not self.endpoint_url:  # 비어 있으면 묶음에 컨테이너 안 주소가 적힌다
            missing.append("MINT_ENDPOINT_PUBLIC_URL(단말에서 닿는 LiteLLM 주소)")
        if not self.endpoint_routes:
            missing.append("MINT_ENDPOINT_ROUTES(단말 경로 켜기)")
        return ", ".join(missing)

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.time_zone)

    @property
    def instance_id(self) -> str:
        return self.control.instance_id


@dataclass
class Actor:
    ctx: Context
    session: console_sessions.SessionInfo | None
    session_id: str | None
    config: ConsoleConfig
    request_id: str

    @property
    def conn(self) -> psycopg.Connection:
        return self.ctx.conn

    @property
    def instance(self) -> str:
        return self.ctx.instance_id

    @property
    def role(self) -> str:
        return self.ctx.operator.role

    @property
    def csrf(self) -> str:
        return console_sessions.csrf_token(self.session_id) if self.session_id else ""

    def litellm(self) -> ReadOnlyLiteLLM:
        if self.config.litellm_admin is None:
            raise AdminError(
                AdminCode.FORBIDDEN,
                "이 콘솔에는 게이트웨이 관리 키가 설정되어 있지 않아 이 변경은 "
                "명령줄에서 하십시오.",
            )
        return self.config.litellm_admin


def can(actor: Any, command: str) -> bool:
    """서비스가 이 명령에 요구하는 역할(명령 표)을 행위자가 갖는가. 화면 단추도 같은 표를 따른다."""
    from mint_litellm import cli_evidence
    from mint_litellm.control.services.base import _COMMANDS
    from mint_litellm.types.cli_commands import OperatorRole

    entry = _COMMANDS.get(command) or next(
        (c for c in cli_evidence.COMMANDS if c.name == command), None
    )
    return entry is not None and OperatorRole(actor.role) in entry.roles


def can_attach(actor: Any, kind_key: str) -> bool:
    """증빙 종류를 이 행위자가 붙일 수 있는가(일부 종류는 관리자만)."""
    from mint_litellm.control.services import evidence

    if not can(actor, "evidence attach"):
        return False
    return kind_key not in evidence.ADMIN_ONLY_KINDS or actor.role == "admin"


def is_staff_path(request: Request) -> bool:
    return request.url.path == "/staff" or request.url.path.startswith("/staff/")


LOGIN_ATTEMPTS_PER_MINUTE = 10

def too_many_attempts(request: Request) -> bool:
    """같은 주소의 분당 로그인 시도 수 제한. 프로세스별 메모리 기준이다(복제본마다 따로 센다)."""
    now = time.monotonic()
    address = request.client.host if request.client else ""
    window = request.app.state.attempts.setdefault(address, deque())
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= LOGIN_ATTEMPTS_PER_MINUTE:
        return True
    window.append(now)
    return False


def config_of(request: Request) -> ConsoleConfig:
    return request.app.state.config


def db(request: Request) -> Iterator[psycopg.Connection]:
    """요청마다 연결 하나. 요청이 끝나면 확정하고, 오류면 되돌린다."""
    with connect(config_of(request).database_url) as conn:
        yield conn


def _token_only(request: Request) -> bool:
    """운영자 토큰만으로 인증하는 요청인가(세션 쿠키가 함께 오면 쿠키 요청으로 보고 검사한다).

    화면 경로는 Authorization 헤더를 보지 않고 쿠키로 인증하므로, 헤더가 있다는 것만으로 출처·CSRF
    검사를 건너뛰면 쿠키 세션에 가짜 헤더를 붙여 검사를 피할 수 있다.
    """
    if not request.headers.get("authorization", "").lower().startswith("bearer "):
        return False
    return not (read_cookie(request, COOKIE) or read_cookie(request, STAFF_COOKIE))


def require_origin(request: Request) -> None:
    """변경 요청은 같은 출처에서 와야 한다(Fetch Metadata가 있으면 그것을, 없으면 Origin을 본다)."""
    if request.method not in UNSAFE or _token_only(request):
        return
    site = request.headers.get("sec-fetch-site")
    origin = request.headers.get("origin")
    if site is not None:
        foreign = site not in ("same-origin", "none")
    else:
        foreign = origin is not None and origin.rstrip("/") != (
            f"{request.url.scheme}://{request.url.netloc}"
        )
    if foreign:
        raise AdminError(AdminCode.FORBIDDEN, "다른 출처에서 보낸 요청입니다.")


async def require_csrf(request: Request) -> None:
    """세션 쿠키로 인증한 변경 요청은 CSRF 토큰(헤더 또는 폼 필드)과 출처가 맞아야 한다."""
    require_origin(request)
    if request.method not in UNSAFE or _token_only(request):
        return
    cookie = read_cookie(request, STAFF_COOKIE if is_staff_path(request) else COOKIE)
    if not cookie:
        return  # 세션이 없으면 인증 단계가 거부한다(로그인 요청은 출처만 확인한다)
    sent = request.headers.get("x-csrf-token")
    if sent is None and "form" in request.headers.get("content-type", ""):
        sent = (await request.form()).get("csrf")
    if not isinstance(sent, str) or not hmac.compare_digest(
        sent, console_sessions.csrf_token(cookie)
    ):
        raise AdminError(
            AdminCode.FORBIDDEN, "요청을 확인할 수 없습니다. 화면을 새로 고친 뒤 다시 시도하십시오."
        )


def actor_dep(*, allow_token: bool):
    """세션 쿠키(또는 ``allow_token``이면 운영자 토큰)로 행위자를 만든다."""

    def dependency(request: Request, conn: psycopg.Connection = Depends(db)) -> Actor:
        config = config_of(request)
        request_id = request.state.request_id
        header = request.headers.get("authorization", "")
        if allow_token and header.lower().startswith("bearer "):
            try:
                operator = operators.authenticate(
                    conn, config.instance_id, header[7:].strip()
                )
            except AuthError as error:
                raise Unauthenticated(str(error)) from None
            ctx = Context(conn, config.instance_id, operator)
            return Actor(ctx, None, None, config, request_id)
        session_id = read_cookie(request, COOKIE)
        info = (
            console_sessions.lookup(conn, config.instance_id, config.stage2, session_id)
            if session_id
            else None
        )
        if info is not None and ui_sessions.litellm_logged_out(
            conn, config.instance_id, config.litellm_url, config.stage2.export_hmac_key,
            info.id_hash,
        ):
            console_sessions.revoke(
                conn, config.instance_id, info.id_hash, actor=info.operator_name,
                reason="litellm_logout",
            )
            conn.commit()  # 아래 인증 오류가 이 폐기를 되돌리지 않게 한다
            info = None
        if info is None:
            raise Unauthenticated()
        operator = Operator(info.operator_name, info.role, info.user_id)
        ctx = Context(conn, config.instance_id, operator)
        return Actor(ctx, info, session_id, config, request_id)

    return dependency


api_actor = actor_dep(allow_token=True)
page_actor = actor_dep(allow_token=False)


def error_response(error: ControlError, request_id: str) -> JSONResponse:
    if isinstance(error, AdminError):
        status = 401 if isinstance(error, Unauthenticated) else STATUS[error.code]
        body = error.body()
        body["message"] = screen_message(body["message"])
        if ":" not in body["reference"]:  # 사건 키(source_key)가 없으면 요청 식별자이다
            body["reference"] = request_id
    else:
        status = 400
        body = {"code": INVALID, "message": screen_message(str(error)), "reference": request_id}
    return JSONResponse(body, status_code=status, headers={"X-Request-Id": request_id})


def login_redirect(request: Request) -> Response:
    target = "/login"
    if request.headers.get("hx-request"):
        return Response(status_code=200, headers={"HX-Redirect": target})
    return RedirectResponse(target, status_code=303)


def public(value: Any) -> Any:
    from mint_litellm.control.services.reads import jsonable

    return jsonable(value)

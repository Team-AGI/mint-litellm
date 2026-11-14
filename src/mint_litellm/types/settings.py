"""설정 우선순위와 LiteLLM 필수·권장·관측 설정 표.

``SETTINGS_TABLE``은 ``init``의 설정 조각 생성, ``check``의 검사, 플러그인 자가 점검이
공유하는 단일 기준이다. 등급이 ``REQUIRED``인 행은 자가 점검 실패(기동 중단)이자 ``check``
실패이고, ``RECOMMENDED``는 ``check`` 경고, ``OBSERVATION``은 ``status`` 표시만 한다.
"""

from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from mint_litellm.types.reason_codes import OBSERVATION_CANDIDATES, Reason


class Mode(StrEnum):
    ENFORCE = "enforce"
    OBSERVE = "observe"


def effective_mode(ceiling: Mode, stored: Mode) -> Mode:
    """환경 변수의 모드 상한이 enforce이면 저장된 모드가 observe여도 enforce로 집행한다."""
    return Mode.ENFORCE if ceiling is Mode.ENFORCE else stored


class ObservationSettings(BaseModel):
    """저장된 설정 중 관측 모드 전환 조건에 쓰이는 부분."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observable_reasons: frozenset[Reason] = OBSERVATION_CANDIDATES
    observable_policy_ids: frozenset[str] = frozenset()

    @field_validator("observable_reasons")
    @classmethod
    def _within_candidates(cls, value: frozenset[Reason]) -> frozenset[Reason]:
        extra = value - OBSERVATION_CANDIDATES
        if extra:
            names = ", ".join(sorted(r.value for r in extra))
            raise ValueError(f"not eligible for observation: {names}")
        return value


class SettingSource(StrEnum):
    ENV = "env"
    DB = "db"


class MintSettingRow(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    source: SettingSource
    rule: str


MINT_SETTINGS: tuple[MintSettingRow, ...] = (
    MintSettingRow(
        key="MINT_MODE",
        source=SettingSource.ENV,
        rule="모드 상한. enforce이면 저장된 설정이 observe로 바꿀 수 없다.",
    ),
    MintSettingRow(
        key="settings.mode",
        source=SettingSource.DB,
        rule="상한 이하에서만 설정한다. 변경은 사건을 남기고 세대를 올린다.",
    ),
    MintSettingRow(
        key="settings.observable_reasons",
        source=SettingSource.DB,
        rule="관측 모드로 전환할 수 있는 사유 계열의 부분집합. 기본값은 전환 후보 전체.",
    ),
    MintSettingRow(
        key="settings.observable_policy_ids",
        source=SettingSource.DB,
        rule="관측 가능으로 선언된 정책 중 관측에 쓸 정책 식별자.",
    ),
    MintSettingRow(
        key="settings.default_org_id",
        source=SettingSource.DB,
        rule="팀·사용자 바인딩이 없는 주체에 적용할 기본 조직. 해제할 수 있다.",
    ),
    MintSettingRow(
        key="MINT_REQUIRED",
        source=SettingSource.ENV,
        rule="기본 true. 자가 점검 실패 시 프록시 기동을 중단한다.",
    ),
    MintSettingRow(
        key="MINT_HIGH_RISK_TOOLS",
        source=SettingSource.ENV,
        rule="호출별 승인을 요구할 고위험 도구 목록. 저장된 설정으로 덮지 않는다.",
    ),
    MintSettingRow(
        key="MINT_TARGET_PROFILES",
        source=SettingSource.ENV,
        rule=(
            "원격 서버의 호출 대상·행위 프로필을 덮어쓴다(`서버 식별자=프로필` 쉼표 목록, "
            "프로필은 `github`·`n8n`·`none`). 기본은 승인된 배포 계약에서 자동으로 고른다. "
            "저장된 설정으로 덮지 않는다."
        ),
    ),
    MintSettingRow(
        key="MINT_DECISION_BUDGET_MS",
        source=SettingSource.ENV,
        rule=(
            "판정 하나의 시간 예산(밀리초, 기본 300). 상태 조회·정책 평가·선기록은 남은 시간만큼만 "
            "기다리고, 시간 초과는 결과 불명으로 다룬다. 데이터베이스가 응답하지 않아도 이 "
            "시간에서 끝나며(서버 쪽 잠금 제한 `lock_timeout`은 같은 값, 문장 제한 "
            "`statement_timeout`은 열 배, 연결 시도 제한도 건다), 상태 조회가 넘으면 "
            "`MINT-DEPENDENCY-DB`로 차단한다. "
            "저장된 설정으로 덮지 않는다."
        ),
    ),
    MintSettingRow(
        key="MINT_APPROVAL_HOLD_SECONDS",
        source=SettingSource.ENV,
        rule=(
            "호출별 승인이 필요해 막힌 호출을 승인 결정을 기다리며 붙잡아 두는 최대 시간"
            "(초, 기본 120, 0이면 붙잡지 않고 바로 거절, 최대 300). 그 사이 승인되면 판정을 "
            "처음부터 다시 돌려 모든 검사를 거친 뒤 같은 호출로 결과를 돌려주고, 거부·만료·시간 "
            "초과는 기존 거절을 돌려준다. 클라이언트의 도구 호출 제한(Claude Code "
            "`MCP_TOOL_TIMEOUT`, Codex `tool_timeout_sec`)이 이 값보다 짧으면 클라이언트가 "
            "먼저 포기한다. 저장된 설정으로 덮지 않는다."
        ),
    ),
    MintSettingRow(
        key="MINT_LOG_LEVEL",
        source=SettingSource.ENV,
        rule=(
            "플러그인 로그 수준(DEBUG, INFO, WARNING, ERROR). 정하지 않으면 로그 설정을 "
            "바꾸지 않는다. DEBUG이면 도구 호출 판정마다 "
            "`decision_ms=<밀리초> ref=<판정 참조> allowed=<true|false>` 한 줄을 표준 오류에 "
            "남기고, 그 뒤에 단계별 시간(`hook_ms`, `snapshot_ms`, `markers_ms`, `input_ms`, "
            "`patterns_ms`, `fingerprint_ms`, `policy_ms`, `event_ms`)과 입출력 대기 횟수"
            "(`awaits`)가 붙는다. 시간은 판정 진입부터 반환까지이고 선기록을 포함한다. "
            "응답을 받은 호출은 `response_ms=<밀리초> ref=<판정 참조> revocation_ms=<밀리초> "
            "event_ms=<밀리초>` 한 줄도 남긴다. DEBUG가 아니면 시간을 재지 않는다."
        ),
    ),
    MintSettingRow(
        key="MINT_SELFCHECK_GRACE_SECONDS",
        source=SettingSource.ENV,
        rule=(
            "기동 뒤 준비 상태와 자가 점검 8항목을 마쳐야 하는 시간(초, 기본 120, 범위 10~600). "
            "범위 밖이면 기동을 거부한다. 시간 안에 마치지 못하면 사건을 남기고, "
            "`MINT_REQUIRED=true`이면 기동을 중단한다."
        ),
    ),
    MintSettingRow(
        key="MINT_FINGERPRINT_KEY",
        source=SettingSource.ENV,
        rule=(
            "호출별 승인 인자 지문의 키(32바이트 이상 무작위 값의 base64url). `init`이 만들어 "
            "저장소 밖 비밀 파일(권한 0600)에 기록한다. 호출별 승인의 인자 지문을 계산하는 데 "
            "쓰이므로 필수이며, 없으면 자가 점검이 실패해 기동을 중단한다."
        ),
    ),
    MintSettingRow(
        key="MINT_FINGERPRINT_KEY_VERSION",
        source=SettingSource.ENV,
        rule=(
            "지문 키의 판본(1 이상 정수, 기본 1). 승인에 기록된 판본과 다르면 호출별 승인이 "
            "다시 필요하다."
        ),
    ),
)


class SelfCheckItem(IntEnum):
    CALLBACK_REGISTERED = 1
    GUARDRAIL_MODES = 2
    GUARDRAIL_ORDER = 3
    KEY_ACCESS_STRICT = 4
    SERVER_REGISTRY_MATCH = 5
    NAME_ALIAS_UNIQUE = 6
    COMPAT_SYMBOLS = 7
    REQUIRED_SETTINGS = 8


SELF_CHECK_DESCRIPTIONS: dict[SelfCheckItem, str] = {
    SelfCheckItem.CALLBACK_REGISTERED: "MINT 로거가 정확히 하나 등록되어 있다.",
    SelfCheckItem.GUARDRAIL_MODES: "MINT 가드레일이 두 모드로 등록되어 있고 `default_on`이다.",
    SelfCheckItem.GUARDRAIL_ORDER: (
        "MINT 가드레일이 하나이고, 병렬 실행·원문 검사 끔·판정 재정의가 그대로이다."
    ),
    SelfCheckItem.KEY_ACCESS_STRICT: (
        "통제 서버가 `allow_all_keys: false`이고 `require_key_mcp_access_defined`가 true이다."
    ),
    SelfCheckItem.SERVER_REGISTRY_MATCH: (
        "승인된 통제 서버의 `server_id`가 레지스트리에 있다. 계약 값(URL 해시·전송 방식·인증 "
        "방식)이 다르면 기동은 계속하고 사건으로 남기며, 그 서버의 호출은 차단한다. 중지된 서버가 "
        "레지스트리에 없으면 기동은 계속하고 사건(`registry_missing`)으로 남긴다."
    ),
    SelfCheckItem.NAME_ALIAS_UNIQUE: "설정과 DB를 합친 서버의 이름·별칭이 전역에서 유일하다.",
    SelfCheckItem.COMPAT_SYMBOLS: "호환 계층이 쓰는 LiteLLM 비공개 심볼이 모두 존재한다.",
    SelfCheckItem.REQUIRED_SETTINGS: "필수 설정 행이 모두 표의 값과 일치한다.",
}


class SettingGrade(StrEnum):
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    OBSERVATION = "observation"


class SettingLocation(StrEnum):
    GUARDRAILS = "guardrails"
    LITELLM_SETTINGS = "litellm_settings"
    GENERAL_SETTINGS = "general_settings"
    MCP_SERVERS = "mcp_servers"
    ENVIRONMENT = "environment"
    PROCESS = "process"
    MANAGEMENT_API = "management_api"


class SettingRow(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    location: SettingLocation
    value: str
    grade: SettingGrade
    self_checks: tuple[SelfCheckItem, ...] = ()
    # 설정 파일에 명시되었는지는 프로세스 안에서 알 수 없어 init·check가 파일을 검사한다.
    # 이 행의 self_checks는 프로세스 안에서 대신 확인하는 항목이다.
    file_check_only: bool = False
    observation_item: str | None = None
    reason: str


SETTINGS_TABLE: tuple[SettingRow, ...] = (
    SettingRow(
        key="guardrails[MINT]",
        location=SettingLocation.GUARDRAILS,
        value="mode: [pre_call, pre_mcp_call, post_mcp_call], default_on: true",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.GUARDRAIL_MODES, SelfCheckItem.GUARDRAIL_ORDER),
        reason=(
            "가드레일이 없으면 도구 호출 판정과 도구 목록 필터가 사라지고, pre_call이 없으면 "
            "공급자가 외부 MCP 서버를 직접 부르는 모델 요청을 막지 못한다."
        ),
    ),
    SettingRow(
        key="callbacks",
        location=SettingLocation.LITELLM_SETTINGS,
        value="MINT 로거를 적지 않는다(MINT 가드레일이 등록)",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.CALLBACK_REGISTERED,),
        reason=(
            "도구 호출 판정은 MINT 가드레일이 하고 응답·실패 관측용 로거는 가드레일이 등록한다. "
            "설정에 따로 적으면 두 번 등록되므로 기동을 거부한다."
        ),
    ),
    SettingRow(
        key="mcp_servers.<이름>.allow_all_keys",
        location=SettingLocation.MCP_SERVERS,
        value="false",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.KEY_ACCESS_STRICT,),
        reason="모든 키에 열린 서버는 통제 대상에서 제외된다.",
    ),
    SettingRow(
        key="mcp_servers.<이름>.server_id",
        location=SettingLocation.MCP_SERVERS,
        value="명시",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.SERVER_REGISTRY_MATCH,),
        file_check_only=True,
        reason=(
            "명시하지 않으면 URL이 바뀔 때 식별자가 바뀌어 기존 권한이 어긋난다. "
            "설정 파일 검사로 확인하며, 프로세스 안에서는 레지스트리 값 점검이 대신한다."
        ),
    ),
    SettingRow(
        key="서버 이름·별칭 유일성",
        location=SettingLocation.MANAGEMENT_API,
        value="전역 유일",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.NAME_ALIAS_UNIQUE,),
        reason="설정 서버와 같은 별칭의 DB 서버가 있으면 판정 대상과 실행 대상이 갈린다.",
    ),
    SettingRow(
        key="호환 계층 비공개 심볼",
        location=SettingLocation.PROCESS,
        value="존재",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.COMPAT_SYMBOLS,),
        reason="지원 판본이 아니면 심볼이 사라져 서버 식별이 불가능해진다.",
    ),
    SettingRow(
        key="require_key_mcp_access_defined",
        location=SettingLocation.GENERAL_SETTINGS,
        value="true",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.KEY_ACCESS_STRICT,),
        reason="MCP 접근 범위가 정의되지 않은 키가 서버를 호출하지 못하게 한다.",
    ),
    SettingRow(
        key="LITELLM_STRICT_GUARDRAIL_MODES",
        location=SettingLocation.ENVIRONMENT,
        value="true (기본값, false 금지)",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="가드레일 모드 불일치를 경고만 하고 넘기지 않도록 한다.",
    ),
    SettingRow(
        key="store_prompts_in_spend_logs",
        location=SettingLocation.GENERAL_SETTINGS,
        value="false (기본값, true 금지)",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="true이면 도구 결과 본문이 LiteLLM 지출 로그에 저장된다.",
    ),
    SettingRow(
        key="user_url_validation",
        location=SettingLocation.LITELLM_SETTINGS,
        value="true (기본값)",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="사용자가 지정한 메타데이터 주소의 내부망 접근을 막는다.",
    ),
    SettingRow(
        key="user_url_allowed_hosts",
        location=SettingLocation.LITELLM_SETTINGS,
        value="비어 있음",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="목록의 호스트는 내부망 접근 차단을 건너뛰어 조회 목적지를 제한할 수 없다.",
    ),
    SettingRow(
        key="ssl_verify",
        location=SettingLocation.LITELLM_SETTINGS,
        value="끄지 않음(환경 변수 SSL_VERIFY 포함)",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="인증서 검증을 끄면 접속 주소의 서버 이름과 인증서 이름이 달라도 연결된다.",
    ),
    SettingRow(
        key="disable_env_credential_login",
        location=SettingLocation.GENERAL_SETTINGS,
        value="true",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="마스터 키를 비밀번호로 쓰는 환경 변수 계정 로그인을 막는다.",
    ),
    SettingRow(
        key="OAuth 리다이렉트 출처",
        location=SettingLocation.ENVIRONMENT,
        value="허용 출처에 전체 허용 항목 없음, OAuth 서버가 있으면 PROXY_BASE_URL 설정",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="인증 결과 수신 주소를 정한 출처로 한정한다. 기준 주소가 없으면 Host 헤더를 따른다.",
    ),
    SettingRow(
        key="mcp_servers.<이름>.timeout",
        location=SettingLocation.MCP_SERVERS,
        value="양수이고 600초 이하(미설정이면 LiteLLM 기본값 적용)",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="도구 호출의 대기·실행 시간에 상한이 있어야 시간을 넘긴 호출이 끝난다.",
    ),
    SettingRow(
        key="mcp_servers.<이름>.authentication_token",
        location=SettingLocation.MCP_SERVERS,
        value="서버마다 다른 자격",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="한 서버의 자격을 다른 서버가 함께 쓰면 한쪽 유출이 다른 쪽 침해가 된다.",
    ),
    SettingRow(
        key="mcp_servers.<이름>.rpm",
        location=SettingLocation.MCP_SERVERS,
        value="양수(init이 600을 채움)",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="서버마다 분당 호출 수에 상한이 있어야 짧은 시간의 반복 조회와 대량 추출이 멈춘다.",
    ),
    SettingRow(
        key="mcp_servers.<이름>.max_concurrent_requests",
        location=SettingLocation.MCP_SERVERS,
        value="양수(init이 8을 채움)",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="서버마다 동시에 실행할 수 있는 호출 수에 상한이 있어야 초과 요청이 대기한다.",
    ),
    SettingRow(
        key="supported_db_objects",
        location=SettingLocation.GENERAL_SETTINGS,
        value="설정한 경우 mcp 포함",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="mcp가 빠지면 DB에 등록한 서버가 복제본에 반영되지 않는다.",
    ),
    SettingRow(
        key="disable_spend_logs",
        location=SettingLocation.GENERAL_SETTINGS,
        value="true는 init --no-spend-logs를 선택한 경우만",
        grade=SettingGrade.OBSERVATION,
        observation_item="spend_log_arguments_stored",
        reason="도구 호출 인자가 LiteLLM 지출 로그에 저장되는지 표시한다.",
    ),
    SettingRow(
        key="key_generation_settings.personal_key_generation.allowed_user_roles",
        location=SettingLocation.LITELLM_SETTINGS,
        value='["proxy_admin"]',
        grade=SettingGrade.RECOMMENDED,
        reason="일반 사용자가 가드레일 제외 메타데이터를 담은 개인 키를 만들지 못하게 한다.",
    ),
    SettingRow(
        key="mcp_allow_all_keys_respects_mcp_scope",
        location=SettingLocation.GENERAL_SETTINGS,
        value="true",
        grade=SettingGrade.RECOMMENDED,
        reason="접근 범위를 명시한 키에서 개방 서버를 제외한다.",
    ),
    SettingRow(
        key="PROXY_BASE_URL",
        location=SettingLocation.ENVIRONMENT,
        value="설정",
        grade=SettingGrade.RECOMMENDED,
        reason="없으면 OAuth 메타데이터와 콜백의 기준 주소가 요청의 Host 헤더를 따른다.",
    ),
    SettingRow(
        key="MCP_TRUSTED_REDIRECT_ORIGINS",
        location=SettingLocation.ENVIRONMENT,
        value="배치에 맞게 설정",
        grade=SettingGrade.RECOMMENDED,
        reason="OAuth 리다이렉트를 받을 수 있는 출처를 제한한다.",
    ),
    SettingRow(
        key="use_x_forwarded_for, mcp_trusted_proxy_ranges",
        location=SettingLocation.GENERAL_SETTINGS,
        value="역프록시 뒤라면 함께 설정",
        grade=SettingGrade.RECOMMENDED,
        reason="역프록시 뒤에서 클라이언트 주소를 판별할 때 신뢰할 프록시 범위를 제한한다.",
    ),
    SettingRow(
        key="mcp_servers.<이름>.issuer",
        location=SettingLocation.MCP_SERVERS,
        value="발견형 인증 서버는 명시",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="고정하지 않으면 첫 응답의 인가 서버를 그대로 신뢰한다.",
    ),
    SettingRow(
        key="mcp_servers.<이름>.oauth_identity_binding.mode",
        location=SettingLocation.MCP_SERVERS,
        value="사용자별 OAuth 서버는 enforce",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="nonce 대조와 주체 결속, PKCE 강제를 켠다.",
    ),
    SettingRow(
        key="mcp_servers.<이름>.upstream_resource",
        location=SettingLocation.MCP_SERVERS,
        value="LiteLLM이 토큰을 받는 OAuth 서버는 auto(서버 주소) 또는 자원 식별자",
        grade=SettingGrade.REQUIRED,
        self_checks=(SelfCheckItem.REQUIRED_SETTINGS,),
        reason="인가 서버에 토큰의 대상(RFC 8707 resource)을 알려 다른 서버용 토큰을 막는다.",
    ),
    SettingRow(
        key="mcp_servers.<이름>.auth_type",
        location=SettingLocation.MCP_SERVERS,
        value="true_passthrough·oauth_delegate 서버는 승인 조건 allow_token_forward로만 사용",
        grade=SettingGrade.RECOMMENDED,
        reason="호출자 토큰을 업스트림에 그대로 전달하는 서버는 승인에서 명시하지 않으면 막는다.",
    ),
    SettingRow(
        key="LEGACY_MULTI_INSTANCE_RATE_LIMITING",
        location=SettingLocation.ENVIRONMENT,
        value="미설정",
        grade=SettingGrade.RECOMMENDED,
        reason="true이면 MCP 분당 호출 한도가 집행되지 않는다.",
    ),
    SettingRow(
        key="enable_redis_auth_cache",
        location=SettingLocation.LITELLM_SETTINGS,
        value="복제본 × 워커가 둘 이상이면 설정 (공유 Redis 필요)",
        grade=SettingGrade.RECOMMENDED,
        observation_item="auth_cache_shared",
        reason="Redis가 없으면 키·팀 권한 캐시 무효화가 복제본과 워커 사이에 전파되지 않는다.",
    ),
    SettingRow(
        key="사용자·팀에 결속되지 않은 키",
        location=SettingLocation.MANAGEMENT_API,
        value="없음",
        grade=SettingGrade.RECOMMENDED,
        observation_item="unbound_keys",
        reason="사용자도 팀도 없는 키는 신원을 확정할 수 없어 호출이 항상 차단된다.",
    ),
)

# check·status가 출력하는 관측 항목. 실패 조건이 아니다.
# guardrail_optout_subjects는 다른 가드레일을 끈 키·팀의 수이고,
# unbound_keys는 사용자와 팀 어디에도 결속되지 않은 키의 수이다(0이 아니면 경고).
OBSERVATION_ITEMS: tuple[str, ...] = (
    "spend_log_arguments_stored",
    "guardrail_optout_subjects",
    "auth_cache_shared",
    "unbound_keys",
)

# LiteLLM이 구현하는 정책을 MINT가 설정 점검으로 강제하는 대응. 정책 -> 설정 표 행 이름.
# `mint check`가 정책마다 충족 여부 한 줄을 보인다.
REUSE_POLICIES: dict[str, tuple[str, ...]] = {
    "POL-R-04": ("서버 이름·별칭 유일성",),
    "POL-R-05": (
        "mcp_servers.<이름>.upstream_resource",
        "mcp_servers.<이름>.upstream_resource (DB 등록 서버)",
    ),
    "POL-R-06": ("mcp_servers.<이름>.auth_type",),
    "POL-R-07": ("mcp_servers.<이름>.issuer", "mcp_servers.<이름>.oauth_identity_binding.mode"),
    "POL-R-09": ("OAuth 리다이렉트 출처",),
    "POL-R-10": ("mcp_servers.<이름>.oauth_identity_binding.mode",),
    "POL-R-11": ("user_url_validation", "user_url_allowed_hosts"),
    "POL-R-12": ("user_url_validation", "user_url_allowed_hosts"),
    "POL-R-13": ("disable_env_credential_login", "store_prompts_in_spend_logs"),
    "POL-R-14": ("mcp_servers.<이름>.authentication_token",),
    "POL-R-17": ("ssl_verify",),
    "POL-E-17": ("mcp_servers.<이름>.rpm",),
    "POL-E-18": ("require_key_mcp_access_defined", "mcp_servers.<이름>.allow_all_keys"),
    "POL-E-23": ("mcp_servers.<이름>.rpm", "mcp_servers.<이름>.max_concurrent_requests"),
    "POL-E-24": ("mcp_servers.<이름>.timeout",),
}


def policies_of(key: str) -> tuple[str, ...]:
    """설정 표 행 이름을 근거로 삼는 LiteLLM 재사용 정책."""
    return tuple(policy for policy, keys in REUSE_POLICIES.items() if key in keys)

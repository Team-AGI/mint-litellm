"""화면에 보이는 한국어 표시명. 영어 열거값은 화면에 내지 않고 이 표를 거친다.

상태 표시는 ``(표시명, 심각도)``이고 심각도는 색·아이콘을 정한다: ok(정상), wait(대기), error(오류),
block(차단), off(비활성). 겹치면 차단 > 오류 > 대기 > 정상이다.
"""

from typing import NamedTuple


class Status(NamedTuple):
    text: str
    level: str


SEVERITY_ORDER = ("block", "error", "wait", "ok", "off")

SERVER = {
    "pending": Status("접수", "wait"),
    "validating": Status("검사 중", "wait"),
    "awaiting_approval": Status("승인 대기", "wait"),
    "rejected": Status("거절됨", "block"),
    "approved": Status("승인됨", "ok"),
    "suspended": Status("중지됨", "block"),
    "terminating": Status("종료 중", "wait"),
    "terminated": Status("종료됨", "off"),
}
# 단말 설치 묶음의 설치 상태: 관리형만 정상이고, 사용자 수준은 관리되지 않는 단말이다.
INSTALL = {
    "managed": Status("관리형", "ok"),
    "user": Status("관리되지 않음", "error"),
    "pending": Status("보고 전", "wait"),
    "removed": Status("제거됨", "off"),
    "revoked": Status("연결 해제", "block"),
}
APPROVAL = {
    "pending": Status("대기", "wait"),
    "active": Status("유효", "ok"),
    "expired": Status("만료", "off"),
    "revoked": Status("철회됨", "block"),
}
# 활성 승인의 재확인 상태(승인 내역 표시용)
RECERT = {
    "ok": Status("기한 내", "ok"),
    "due": Status("재확인 필요", "wait"),
    "overdue": Status("재확인 기한 초과", "error"),
    "held": Status("보류됨", "block"),
}
CALL_APPROVAL = {
    "pending": Status("응답 대기", "wait"),
    "approved": Status("승인됨", "ok"),
    "rejected": Status("거부됨", "block"),
    "cancelled": Status("취소됨", "off"),
    "expired": Status("만료", "off"),
    "consumed": Status("사용됨", "off"),
}
SELF_CONFIRMATION = {
    "pending": Status("확인 대기", "wait"),
    "confirmed": Status("확인됨", "ok"),
    "rejected": Status("거절됨", "block"),
    "cancelled": Status("취소됨", "off"),
    "expired": Status("만료", "off"),
    "consumed": Status("사용됨", "off"),
}
CONSENT = {
    "active": Status("유효", "ok"),
    "revoked": Status("철회됨", "block"),
    "expired": Status("만료", "off"),
}
RELATION = {
    "active": Status("이용 중", "ok"),
    "terminating": Status("종료 중", "wait"),
    "terminated": Status("종료됨", "off"),
}
ORG = {"active": Status("운영 중", "ok"), "closed": Status("닫힘", "off")}
ALLOWLIST = {
    "active": Status("유효", "ok"),
    "expired": Status("만료", "off"),
    "lifted": Status("해제됨", "off"),
}
POLICY_VERSION = {
    "validated": Status("검증됨", "wait"),
    "staged": Status("준비됨", "wait"),
    "active": Status("적용 중", "ok"),
    "superseded": Status("교체됨", "off"),
}
JOB = {
    "pending": Status("대기", "wait"),
    "running": Status("실행 중", "wait"),
    "done": Status("완료", "ok"),
    "failed": Status("실패", "error"),
}
ALERT_SEVERITY = {
    "low": Status("낮음", "wait"),
    "medium": Status("보통", "wait"),
    "high": Status("높음", "error"),
    "critical": Status("심각", "block"),
}
EVIDENCE = {
    "valid": Status("유효", "ok"),
    "not_applicable": Status("해당 없음", "off"),
    "expiring": Status("만료 임박", "wait"),
    "expired": Status("만료", "error"),
    "missing": Status("없음", "block"),
}
EVIDENCE_GATE = {
    "approve": "신청 승인",
    "reapprove": "배포 계약 변경 재승인",
    "finish": "이용 관계 종료 완료",
    "periodic": "주기 확인",
    "retire": "서버 종료",
}
ENFORCEMENT = {
    "enforcement_verified": Status("정상", "ok"),
    "enforcement_unverified": Status("확인 불가", "error"),
}

INTAKE = {
    "received": Status("접수", "wait"),
    "checking": Status("검사 중", "wait"),
    "passed": Status("검사 통과", "ok"),
    "failed": Status("검사 실패", "error"),
    "indeterminate": Status("판별 불가", "wait"),
    "decided": Status("결정됨", "off"),
}
DECISION = {
    "approved": Status("승인됨", "ok"),
    "rejected": Status("거절됨", "block"),
    "exception": Status("예외 승인됨", "wait"),
}
CHECK_RESULT = {
    "pass": Status("통과", "ok"),
    "fail": Status("실패", "error"),
    "indeterminate": Status("판별 불가", "wait"),
}
CHECK = {
    "url_guard": "주소 검사",
    "oauth_issuer_allowlist": "인증 서버 허용 목록",
    "connection": "연결",
    "definitions": "도구 정의",
    "description_scan": "설명 검사",
    "risk_grade": "위험 등급",
    "termination_readiness": "종료 준비",
    "supply_chain": "공급망",
}
SOURCE = {"submission": "제출", "operator": "운영자 등록"}
DATA_GRADE = {"public": "공개", "internal": "내부", "confidential": "기밀", "restricted": "제한"}
RISK = {"low": "낮음", "medium": "보통", "high": "높음", "critical": "심각"}
ACTION = {
    "read": "읽기",
    "write": "쓰기",
    "delete": "삭제",
    "external_send": "외부 전송",
    "credential_access": "자격 접근",
}
CHECK_REASON = {
    "ALL_KEYS_NOT_CLOSED": "모든 키 허용을 끄지 못함",
    "APPROVE_REFUSED": "승인 거부됨",
    "COLLECTION_FAILED": "정의 수집 실패",
    "CONNECTION_FAILED": "연결 실패",
    "CREDENTIALS_REQUIRED": "자격 증명 필요",
    "EVIDENCE_NOT_ATTACHED": "증거 없음",
    "INPUT_MISSING": "필수 입력 없음",
    "IP_FORBIDDEN": "금지된 주소",
    "ISSUER_NOT_ALLOWED": "허용되지 않은 인증 서버",
    "ISSUER_UNDECLARED": "인증 서버 미선언",
    "LIMIT_EXCEEDED": "크기 상한 초과",
    "MARKER_HIT": "금지 표지 발견",
    "NOT_SECURED": "보호되지 않음",
    "NO_DEFINITIONS": "도구 정의 없음",
    "POLICY_DATA_UNAVAILABLE": "정책 데이터 없음",
    "PORT_NOT_ALLOWED": "허용되지 않은 포트",
    "PROVIDER_NOT_ALLOWED": "허용되지 않은 제공자",
    "SCHEME_NOT_HTTPS": "HTTPS가 아님",
    "SUBMISSION_GONE": "제출 항목 사라짐",
    "TEST_UNAVAILABLE": "시험 불가",
    "UNSUPPORTED": "지원하지 않음",
    "URL_INVALID": "주소 형식 오류",
    "URL_QUERY": "주소에 질의 문자열 포함",
    "URL_USERINFO": "주소에 사용자 정보 포함",
}
PLAN = {
    "pending": Status("반영 대기", "wait"),
    "completed": Status("반영 완료", "ok"),
    "cancelled": Status("취소됨", "off"),
}
CHANGE = {
    "added": Status("추가", "wait"),
    "removed": Status("삭제", "block"),
    "changed": Status("변경", "error"),
}

ROLE = {"admin": "관리자", "approver": "승인자", "viewer": "조회자", "staff": "직원"}
MODE = {"enforce": "집행", "observe": "관측"}
SCOPE = {"key": "키", "user": "사용자", "team": "팀", "org": "조직", "server": "서버"}
APPROVAL_CLASS = {"standard": "일반", "exception": "예외"}
PRINCIPAL = {"user": "사용자", "team_key": "팀 키", "service_account": "서비스 계정"}
KIT_PLATFORM = {"linux": "Linux", "windows": "Windows"}
KIT_HARNESS = {"claude": "Claude Code", "codex": "Codex", "all": "Claude Code + Codex"}
ALLOWLIST_KIND = {
    "provider": "제공자",
    "auth_server": "인증 서버",
    "egress_target": "외부 전송 대상",
    "registry_source": "레지스트리 출처",
}
TRANSPORT = {"http": "HTTP", "sse": "SSE", "streamable_http": "스트리밍 HTTP", "stdio": "로컬 실행"}
AUTH_TYPE = {
    "none": "없음",
    "api_key": "API 키",
    "bearer_token": "베어러 토큰",
    "basic": "기본 인증",
    "oauth2": "OAuth",
    "token": "토큰",
}
RESULT = {
    "allow": "허용",
    "deny": "차단",
    "stop": "차단",
    "transform": "변환",
    "observe": "관측",
}
RESULT_FILTER = {"allow": "허용", "deny": "차단", "transform": "변환", "observe": "관측"}
OBSERVATION = {
    "spend_log_arguments_stored": "지출 기록에 인자 저장",
    "guardrail_optout_subjects": "가드레일 제외 대상",
    "auth_cache_shared": "인증 캐시 공유",
    "unbound_keys": "조직에 묶이지 않은 키",
}
REASON = {
    "SERVER_UNREGISTERED": "등록되지 않은 서버",
    "SERVER_NOT_APPROVED": "승인되지 않은 서버",
    "APPROVAL_ABSENT": "승인 없음",
    "TOOL_NOT_IN_APPROVAL": "승인 범위 밖 도구",
    "POLICY_DETECT": "정책 탐지",
    "CONTRACT_DRIFT": "계약 변경",
    "OUTPUT_SCAN": "결과 검사",
}

# 사람이 아닌 주체(작업 처리기·초기 설정)가 사건에 남기는 이름
SYSTEM_ACTOR = {
    "intake_run": "수용검증",
    "contract-observer": "계약 관측",
    "session_verify": "세션 재확인",
    "worker": "작업 실행기",
    "mint-worker": "작업 실행기",
    "init": "초기 설정",
    "bootstrap": "최초 등록",
}
TIME_ZONE = {
    "Asia/Seoul": "한국 표준시",
    "Asia/Tokyo": "일본 표준시",
    "UTC": "협정 세계시",
}

# 경보 종류(경보 발생·해결 사건에 함께 보인다)
ALERT_KIND = {
    "contract_drift": "계약 변경",
    "call_spike": "호출량 급증",
    "call_approval_requested": "호출별 승인 요청",
    "intake_pending": "신청 승인 대기",
    "approval_dormant": "미사용 승인",
    "endpoint_stale_server": "폐기 서버 항목 잔존",
    "endpoint_unmanaged": "관리되지 않는 설치",
    "endpoint_stale_process": "폐기 서버 프로세스 잔존",
    "endpoint_stale_autostart": "폐기 서버 자동 시작 잔존",
    "package_unpinned": "버전 미고정 패키지",
    "package_vulnerable": "패키지 취약점",
    "package_vuln_due": "취약점 조치 기한",
    "vuln_feed_unreachable": "취약점 조회 실패",
}
EVENT_KIND = {
    "decision_evaluated": "호출 판정",
    "discovery_evaluated": "도구 목록 판정",
    "call_response_received": "호출 응답",
    "call_outcome_unknown": "호출 결과 불명",
    "enforcement_unverified": "집행 확인 불가",
    "enforcement_verified": "집행 확인",
    "server_identity_mismatch_observed": "서버 신원 불일치 관측",
    "buffer_overflow": "버퍼 초과",
    "buffer_replayed": "버퍼 재전송",
    "server_registered": "서버 등록",
    "server_approved": "서버 승인",
    "server_suspended": "서버 중지",
    "server_resumed": "서버 재개",
    "server_terminating": "서버 폐기",
    "server_terminated": "서버 폐기 완료",
    "relation_created": "이용 관계 생성",
    "relation_terminating": "이용 관계 종료",
    "relation_terminated": "이용 관계 종료 완료",
    "evidence_attached": "증빙 첨부",
    "approval_granted": "승인",
    "approval_revoked": "승인 철회",
    "denial_created": "거부 등록",
    "denial_lifted": "거부 해제",
    "call_approval_requested": "호출별 승인 요청",
    "call_approval_approved": "호출별 승인",
    "call_approval_rejected": "호출별 거부",
    "call_approval_cancelled": "호출별 승인 취소",
    "consent_granted": "동의 부여",
    "consent_revoked": "동의 철회",
    "allowlist_added": "허용 목록 추가",
    "allowlist_lifted": "허용 목록 해제",
    "org_created": "조직 생성",
    "org_closed": "조직 닫기",
    "org_binding_created": "조직 연결",
    "org_binding_removed": "조직 연결 해제",
    "policy_activated": "정책 적용",
    "settings_changed": "설정 변경",
    "operator_added": "운영자 등록",
    "operator_removed": "운영자 삭제",
    "operator_role_changed": "운영자 역할 변경",
    "intake_received": "신청 접수",
    "intake_requester_assigned": "신청자 지정",
    "intake_checked": "수용검증",
    "intake_decided": "신청 결정",
    "contract_approved": "계약 승인",
    "contract_drift_detected": "계약 변경 탐지",
    "contract_superseded": "계약 교체",
    "reapproval_requested": "재승인 요청",
    "sync_applied": "동기화 적용",
    "sync_held": "동기화 보류",
    "export_written": "내보내기 완료",
    "export_failed": "내보내기 실패",
    "restore_blocked": "되돌림 차단",
    "restore_attested": "되돌림 확인",
    "restore_stale_accepted": "오래된 상태 수용",
    "alert_opened": "경보 발생",
    "alert_acknowledged": "경보 확인",
    "alert_resolved": "경보 해결",
    "console_session_started": "콘솔 로그인",
    "console_session_ended": "콘솔 로그아웃",
    "deployment_contract_approved": "배포 계약 승인",
    "deployment_drift_detected": "배포 변경 탐지",
    "deployment_contract_superseded": "배포 계약 교체",
    "approval_recert_requested": "승인 재확인 요청",
    "approval_held": "승인 보류",
    "approval_recert_confirmed": "승인 재확인",
}

CONFIRMATION_EVENT = {
    "call_approval_approved": "본인 확인 확정",
    "call_approval_rejected": "본인 확인 거절",
    "call_approval_cancelled": "본인 확인 취소",
}
STAFF_SESSION_EVENT = {
    "console_session_started": "직원 화면 로그인",
    "console_session_ended": "직원 화면 로그아웃",
}

CONSENT_TEXT_VERSION = "v1"
CONSENT_TEXT = {
    "v1": "선택한 서버가 위 목적과 범위로 내 데이터를 처리하는 데 동의합니다. "
          "동의는 유효 기간이 끝나기 전에도 이 화면에서 철회할 수 있습니다.",
}

SESSION_END_REASON = {
    "logout": "로그아웃",
    "key_gone": "키 삭제",
    "key_blocked": "키 차단",
    "key_expired": "키 만료",
    "key_owner_changed": "키 소유자 변경",
    "user_not_human": "사람 사용자 아님",
    "operator_changed": "운영자 변경",
    "unverified": "재확인 실패",
}

NOTICES = {
    "suspended": "서버를 중지했습니다.",
    "resumed": "서버를 재개했습니다.",
    "approved": "승인했습니다.",
    "revoked": "승인을 철회했습니다.",
    "recertified": "승인을 재확인했습니다.",
    "dormant_done": "선택한 미사용 승인을 처리했습니다.",
    "revoked_denied": "승인을 철회하고 거부를 등록했습니다.",
    "denied": "거부를 등록했습니다.",
    "lifted": "해제했습니다.",
    "call_approved": "호출을 승인했습니다.",
    "call_rejected": "호출을 거부했습니다.",
    "call_cancelled": "승인 요청을 취소했습니다.",
    "org_added": "조직을 생성했습니다.",
    "org_closed": "조직을 닫았습니다.",
    "allowlist_added": "허용 목록에 추가했습니다.",
    "mode_set": "모드를 변경했습니다.",
    "operator_role": "운영자의 역할을 변경했습니다.",
    "requester_assigned": "신청자를 지정했습니다.",
    "evidence_attached": "증빙을 첨부했습니다.",
    "rechecked": "재검사를 등록했습니다.",
    "intake_approved": "신청을 승인했습니다.",
    "intake_rejected": "신청을 거절했습니다.",
    "reapproval_planned": "재승인 계획을 등록했습니다. 반영은 작업 실행기가 진행합니다.",
    "operator_removed": "운영자를 삭제했습니다.",
    "staff_confirmed": "확인했습니다.",
    "staff_rejected": "거절했습니다.",
    "staff_cancelled": "취소했습니다.",
    "consent_given": "동의를 등록했습니다.",
    "consent_withdrawn": "동의를 철회했습니다.",
    "kit_revoked": "단말 연결을 해제했습니다.",
}


def status(table: dict[str, Status], value: str | None) -> Status:
    if value is None:
        return Status("—", "off")
    return table.get(value, Status(value, "off"))


def pick(mapping: dict[str, str], value: str | None) -> str:
    return "—" if value in (None, "") else mapping.get(value, value)


def actor(value: str | None) -> str:
    """사건·기록의 주체 이름. 사람이 아닌 주체는 한국어 이름으로 바꾼다."""
    return pick(SYSTEM_ACTOR, value)


def worst(levels: list[str]) -> str:
    for level in SEVERITY_ORDER:
        if level in levels:
            return level
    return "off"

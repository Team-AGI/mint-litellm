"""경보 화면의 표시 규칙: 요약, 본문 표, 관련 화면 링크. 이름이 없는 본문 항목은 보이지 않는다."""

from collections import defaultdict
from typing import Any
from urllib.parse import quote

from mint_litellm.console import labels
from mint_litellm.console.templating import local_time

KEY = {
    "server_id": "서버", "tool": "도구", "calls": "최근 호출 수", "window_seconds": "관측 구간(초)",
    "baseline_calls": "평소 호출 수", "principal_id": "호출한 쪽", "bytes": "최근 받은 양(바이트)",
    "baseline_bytes": "평소 받은 양(바이트)",
    "baseline_items": "평소 받은 항목 수", "held": "호출 차단", "failures": "연속 실패 횟수",
    "instances": "비교한 인스턴스",
    "items": "항목", "observed_sha256": "관측 지문", "kind": "구분", "state_epoch": "상태 세대",
    "reason": "사유", "intake_id": "신청", "item": "항목", "check": "점검",
    "valid_until": "유효 기한",
    "job_kind": "작업 종류", "target_ref": "대상", "job_id": "작업", "attempts": "시도 횟수",
    "last_error_code": "마지막 오류", "request_id": "요청", "axes": "축별 변화",
    "widened": "확대된 축", "summary": "요약",
    "package_changes": "패키지 변경",
    "packages": "패키지", "evidence": "증빙", "label": "증빙", "subject_kind": "대상 종류",
    "subject_id": "대상", "state": "상태", "source": "출처", "id": "대상",
    "expires_at": "만료 시각",
    "approval_id": "승인", "consecutive_failures": "연속 실패 횟수", "target": "대상",
    "minutes": "경보 기준(분)",
    "fields": "바뀐 항목", "team_id": "팀", "relation_id": "이용 관계", "pending": "남은 항목",
    "remaining": "남은 자격 수", "deleted": "지운 자격", "status": "상태", "message": "내용",
    "plan": "계획", "action": "조치", "tools": "도구", "feed": "조회 주소", "error": "오류",
    "cause": "원인", "file_epoch": "파일 세대", "ecosystem": "제공처", "package": "패키지",
    "name": "이름", "version": "버전", "registry": "저장소", "vuln_id": "취약점 번호",
    "path": "의존 경로",
    "severity": "등급", "cvss": "점수", "exploited": "악용 확인", "deadline_at": "조치 기한",
    "excepted": "예외 증빙", "user_id": "사용자", "key_alias": "키 이름", "count": "건수",
    "autostart_kind": "자동 시작 방식", "autostart_name": "자동 시작 이름", "drift": "변경 유형",
    "credential_scope": "자격 범위", "missing_count": "삭제 횟수", "target_type": "대상 종류",
    "target_id": "대상", "preexisting": "기존 항목", "oauth2": "OAuth 토큰", "byok": "사용자 키",
    "verdict": "판정", "added": "추가", "removed": "제거", "scope_type": "범위 종류",
    "signal": "탐지 근거", "scope_id": "범위", "differences": "차이", "oauth2_flow": "인증 흐름",
}
AXIS = {"file": "파일 접근", "exec": "실행", "network": "네트워크"}
# 값이 코드인 항목의 표시명
VALUE = {
    "state": {"due": "기한 임박", "overdue": "기한 초과", "missing": "없음", "expired": "만료",
              "expiring": "만료 임박"},
    "source": {"approvals": "승인", "call_approvals": "호출별 승인", "intakes": "신청",
               "approval": "승인", "call_approval": "호출별 승인", "intake": "신청"},
    "signal": labels.KEY_BLOCK_SIGNAL,
    "verdict": {"widened": "확대", "narrowed": "축소", "unchanged": "변화 없음"},
    "kind": {"exec": "실행 계약", "deployment": "배포 계약", "instance_mismatch": "인스턴스 불일치",
             "negative_state": "부정 상태 파일", "checkpoint": "체크포인트 파일",
             "setting": "보안 설정", "tool": "도구 계약"},
    "items": {"deployment": "배포 계약", "setting:guardrail_mode": "가드레일 모드",
              "setting:policy_bundle": "활성 정책 묶음"},
    "severity": {
        "critical": "심각", "high": "높음", "medium": "보통", "low": "낮음",
        "CRITICAL": "심각", "HIGH": "높음", "MEDIUM": "보통", "LOW": "낮음",
    },
    "plan": {"cancelled": "취소됨"},
    "last_error_code": labels.SIEM_ERROR,
    "reason": {
        "control_key_not_set": "제어 키 미설정", "forbidden": "권한 없음", "held": "보류됨",
        "not_active": "활성 상태 아님", "not_completed_within_one_hour": "한 시간 안에 끝나지 않음",
        "pin_mismatch": "고정 도구 불일치", "readback_mismatch": "다시 읽은 값 불일치",
        "reapproval_conflict": "재승인 충돌", "registry_missing": "레지스트리에 없음",
        "target_missing": "대상이 삭제됨", "unpin_failed": "고정 해제 실패",
    },
}
# 요약 문장. 없는 값은 줄표로 채운다.
SUMMARY = {
    "contract_drift": "승인된 계약과 달라졌습니다. 서버 {server_id}",
    "server_address_internal": "서버 {server_id}의 주소가 내부 주소로 풀리거나 바뀌었습니다.",
    "content_finding_unmanaged": "서버 {server_id}의 호출이 내용 검사에 걸렸습니다(계약 관리 전).",
    "token_audience_mismatch": "서버 {server_id}에 대상이 다른 토큰이 {calls}건 전달되었습니다.",
    "token_scope_exceeded": "서버 {server_id}에 승인 범위를 넘는 토큰이 {calls}건 전달되었습니다.",
    "result_unenforced": (
        "최근 {window_seconds}초 동안 결과 {calls}건이 검사에 걸렸지만 막지 못했습니다."
    ),
    "key_block_proposed": "키 {key_alias}의 LiteLLM 차단 제안이 승인을 기다립니다.",
    "siem_forward_failing": "SIEM 대상 {target}에 {minutes}분 넘게 전달하지 못했습니다.",
    "config_plaintext_secret": "LiteLLM 설정 {count}곳에 비밀이 평문으로 적혀 있습니다.",
    "call_spike": "서버 {server_id}의 {tool} 호출이 최근 {calls}건입니다(평소 {baseline_calls}건).",
    "bulk_extraction": (
        "서버 {server_id}에서 최근 {items}항목({bytes}바이트)을 받아 갔습니다"
        "(평소 {baseline_items}항목)."
    ),
    "oauth_flow_unreadable": "서버 {server_id}의 인증 흐름을 {failures}번 읽지 못했습니다.",
    "instance_mismatch": "서버 {server_id}의 계약·보안 설정이 다른 인스턴스와 다릅니다.",
    "export_failed": "내보내기에 실패했습니다.",
    "sync_divergence": "서버 {server_id}의 LiteLLM 설정이 MINT와 다릅니다.",
    "sync_foreign_change": "LiteLLM 설정이 MINT 밖에서 바뀌었습니다.",
    "evidence_missing": "서버 {server_id}에 필수 증빙이 없습니다.",
    "evidence_expiring": "서버 {server_id}의 증빙이 곧 만료됩니다.",
    "job_failed": "작업이 실패했습니다. 대상 {target_ref}",
    "restore_request_rejected": "복원 요청을 거부했습니다.",
    "restore_blocked": "복원이 끝나기 전까지 호출을 차단합니다.",
    "approval_expiring": "승인이 곧 만료됩니다.",
    "approval_recert_due": "서버 {server_id}의 승인을 다시 확인해야 합니다.",
    "approval_recert_held": "서버 {server_id}의 승인이 보류되어 호출이 차단됩니다.",
    "litellm_unreachable": "LiteLLM에 {consecutive_failures}번 연속 연결하지 못했습니다.",
    "termination_unconfirmed": "서버 {server_id}의 폐기를 확인하지 못했습니다.",
    "server_credentials_remain": "서버 {server_id}에 지우지 못한 자격이 {remaining}개 있습니다.",
    "server_credentials_unverifiable": "서버 {server_id}의 자격이 지워졌는지 확인하지 못합니다.",
    "control_key_mismatch": "제어 키가 LiteLLM과 맞지 않습니다.",
    "enforcement_unverified": "집행 상태를 확인하지 못합니다.",
    "server_identity_conflict": "서버 신원이 충돌합니다.",
    "package_unpinned": "서버 {server_id}가 버전이 고정되지 않은 패키지를 씁니다.",
    "package_vulnerable": "서버 {server_id}의 패키지 {package} {version}에 취약점이 있습니다.",
    "package_vuln_due": "서버 {server_id}의 취약점 조치 기한이 다가오거나 지났습니다.",
    "vuln_feed_unreachable": "취약점 조회처에 연결하지 못했습니다.",
    "dep_graph_unreachable": "의존 패키지 조회처에 연결하지 못했습니다.",
    "approval_dormant": "서버 {server_id}의 승인이 오랫동안 쓰이지 않았습니다.",
    "call_approval_requested": "서버 {server_id}의 {tool} 호출에 승인이 필요합니다.",
    "intake_pending": "서버 {server_id}의 도입 신청이 검토를 기다립니다.",
    "endpoint_silent": "단말 {key_alias}의 보고가 끊겼습니다.",
    "endpoint_key_expiring": "단말 {key_alias}의 키가 곧 만료됩니다.",
    "endpoint_stale_server": "단말 {key_alias}에 폐기된 서버 {server_id}가 남아 있습니다.",
    "endpoint_unmanaged": "단말 {key_alias}에 관리되지 않는 설치가 있습니다.",
    "endpoint_stale_process": "단말 {key_alias}에서 폐기된 서버 {server_id}가 실행 중입니다.",
    "endpoint_stale_autostart": "단말 {key_alias}에 폐기된 서버 {server_id}의 자동 시작 있음",
    "endpoint_outside_retired": "단말 {key_alias}: 폐기 서버 패키지 {package}가 실행기 밖 실행 중",
    "endpoint_outside_unapproved": "단말 {key_alias}: 미승인 패키지 {package}가 실행기 밖 실행 중",
    "endpoint_unsandboxed": "단말 {key_alias}에서 서버 {server_id}가 격리 없이 실행 중입니다.",
    "endpoint_egress_unfiltered": "단말 {key_alias}: 서버 {server_id}의 호스트 제한 미집행",
    "endpoint_egress_refused": "단말 {key_alias}: 서버 {server_id}의 허용 밖 접속 {count}건 거절",
}
TIME_KEYS = ("valid_until", "expires_at", "deadline_at")


def summary(kind: str, subject: dict[str, Any]) -> str:
    text = SUMMARY.get(kind)
    if text is None:
        return labels.pick(labels.ALERT_KIND, kind)
    known = {k: v for k, v in (subject or {}).items() if v not in (None, "")}
    values = defaultdict(lambda: "—", known)
    out = text.format_map(values)
    path = (subject or {}).get("path") if kind.startswith("package_vuln") else None
    return f"{out} (의존 경로: {path})" if path else out


def _text(key: str, value: Any, zone: str) -> str:
    if isinstance(value, bool):
        return "예" if value else "아니오"
    if key in VALUE and isinstance(value, str):
        # 사유 코드는 모르는 값이면 코드를 드러내지 않는다
        return VALUE[key].get(value, "기타" if key == "reason" else value)
    if key in TIME_KEYS and isinstance(value, str):
        try:
            return local_time(value, zone)
        except ValueError:
            return value
    if key.endswith("sha256") and isinstance(value, str):
        return value[:12] + "…"
    return str(value)


def _lines(key: str, value: Any, zone: str) -> list[str]:
    if isinstance(value, dict):
        out = []
        for k, v in value.items():
            label = AXIS.get(k) or KEY.get(k)
            if label is None:
                continue
            parts = _lines(k, v, zone)
            out.append(f"{label}: {', '.join(parts) if parts else '—'}")
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for v in value:
            lines = _lines(key, v, zone)
            out.append(" · ".join(lines)) if isinstance(v, dict) else out.extend(lines)
        return out
    if value in (None, ""):
        return []
    return [_text(key, value, zone)]


def subject_rows(subject: dict[str, Any], zone: str) -> list[tuple[str, list[str]]]:
    """본문 항목을 (한국어 이름, 값 줄 목록)으로 바꾼다. 이름이 없는 항목은 뺀다."""
    return [
        (KEY[key], _lines(key, value, zone) or ["—"])
        for key, value in (subject or {}).items()
        if key in KEY
    ]


def link(kind: str, subject: dict[str, Any]) -> tuple[str, str] | None:
    """관련 화면 (주소, 이름). 분명한 경우만 돌려준다."""
    subject = subject or {}
    server = subject.get("server_id")
    if kind == "key_block_proposed" and subject.get("proposal_id"):
        focus = quote(str(subject["proposal_id"]), safe="")
        return f"/approvals?tab=blocks&focus={focus}", "차단 제안"
    if kind in ("approval_recert_due", "approval_recert_held", "approval_expiring"):
        return "/approvals?tab=renewals", "승인 센터"
    if kind in ("evidence_missing", "evidence_expiring") and subject.get("intake_id"):
        return f"/intakes/{quote(str(subject['intake_id']), safe='')}", "신청 상세"
    if kind == "contract_drift" and server:
        return f"/servers/{quote(str(server), safe='')}?tab=contract", "계약 변경"
    if kind.startswith("endpoint_") and not server:
        return "/endpoints", "단말 설치"
    if isinstance(server, str) and server:
        return f"/servers/{quote(server, safe='')}", "서버 상세"
    return None

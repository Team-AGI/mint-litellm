"""경보 웹훅: 주소 검사, 서명, 본문, 전송.

요청 헤더 ``X-MINT-Signature``는 ``t=<unix 초>,v1=<HMAC-SHA256 16진수>``이고, 서명 대상은
``<t>.`` 뒤에 본문 바이트를 붙인 값이다. 수신 쪽은 ``verify``로 시각 차이(5분)와 서명을 함께 본다.
``X-MINT-Delivery``는 전송 식별자로, 수신 쪽이 중복을 거를 때 쓴다. 응답 본문은 읽어서 버린다.
"""

import hashlib
import hmac
import json
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

import httpx

from mint_litellm.control.errors import ControlError

log = logging.getLogger("mint_litellm.webhook")

SIGNATURE_HEADER = "X-MINT-Signature"
DELIVERY_HEADER = "X-MINT-Delivery"
TOLERANCE_SECONDS = 300
ATTEMPTS = 3
TIMEOUT_SECONDS = 5.0
# 한 번의 요청 전체 상한(연결·쓰기·읽기 단계를 합친 값)
DEADLINE_SECONDS = 5.0
_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="mint-webhook")


def check_url(url: str, allowed_hosts: Sequence[str]) -> None:
    """``https`` 주소이고 호스트가 허용 목록에 있어야 한다. 아니면 ``ControlError``."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ControlError("웹훅 주소는 https만 받습니다.")
    if parts.hostname not in allowed_hosts:
        raise ControlError("웹훅 주소의 호스트가 허용 목록에 없습니다.")


def sign(key: bytes, body: bytes, timestamp: int) -> str:
    mac = hmac.new(key, f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify(
    key: bytes,
    header: str,
    body: bytes,
    *,
    now: int | None = None,
    tolerance: int = TOLERANCE_SECONDS,
) -> bool:
    """수신 쪽 검증. 형식이 틀리거나, 시각 차이가 ``tolerance``를 넘거나, 서명이 다르면 거짓이다."""
    parts = header.split(",")
    stamps = [part[2:] for part in parts if part.startswith("t=")]
    signatures = [part[3:] for part in parts if part.startswith("v1=")]
    if len(stamps) != 1 or len(signatures) != 1:
        return False
    try:
        timestamp = int(stamps[0])
    except ValueError:
        return False
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > tolerance:
        return False
    expected = sign(key, body, timestamp).rsplit("v1=", 1)[1]
    return hmac.compare_digest(expected, signatures[0])


# 경보 종류별 위험 요지와 조치 절차. 담당자가 이 본문만으로 중지, 조사, 복구를 판단하게 한다.
GUIDE: dict[str, tuple[str, str]] = {
    "webhook_test": (
        "콘솔의 시작하기에서 보낸 시험 메시지입니다. 이 메시지가 보이면 알림 연결이 정상입니다.",
        "별도 조치는 필요하지 않습니다.",
    ),
    "contract_drift": (
        "승인된 도구 정의와 서버가 알리는 정의가 달라졌습니다. 바뀐 도구는 승인 범위를 벗어납니다.",
        "콘솔에서 서버를 열어 바뀐 항목을 확인합니다. 의도한 변경이면 다시 승인하고, "
        "아니면 서버를 중지합니다.",
    ),
    "result_unenforced": (
        "이 LiteLLM에는 결과 단계 가드레일이 없어 결과 검사가 관측만 합니다. "
        "크기 상한·지시문 표지·비밀·개인정보에 걸린 결과도 호출자에게 그대로 전달되었습니다.",
        "콘솔의 기록에서 걸린 호출을 확인하고, 결과 단계 가드레일이 있는 LiteLLM 판본으로 "
        "올립니다. 올리기 전에는 해당 서버의 승인을 철회하거나 서버를 중지합니다.",
    ),
    "instance_mismatch": (
        "같은 서버를 쓰는 다른 인스턴스와 승인 계약 또는 보안 설정(가드레일 모드, "
        "활성 정책 묶음)이 다릅니다. 어긋난 인스턴스에서는 그 서버 호출이 차단됩니다.",
        "콘솔의 경보 상세에서 어긋난 항목을 확인하고 인스턴스끼리 계약과 설정을 맞춥니다. "
        "의도한 차이면 관리자가 사유와 기한을 적어 「인스턴스 간 불일치 예외」 증빙을 붙입니다.",
    ),
    "config_plaintext_secret": (
        "LiteLLM 설정 파일에 키·비밀번호·토큰이 os.environ/<이름> 참조가 아닌 값으로 "
        "적혀 있습니다. "
        "설정 파일이 복사되거나 저장소에 올라가면 그대로 새어 나갑니다.",
        "경보 상세의 항목 경로를 보고 해당 값을 환경 변수나 비밀 저장소로 옮긴 뒤 "
        "os.environ/<이름>으로 바꿉니다. 이미 노출되었을 수 있으므로 값은 새로 발급합니다.",
    ),
    "call_spike": (
        "도구 호출이 평소보다 갑자기 늘었습니다. 오남용이나 반복 호출 오류일 수 있습니다.",
        "콘솔의 기록에서 호출한 사용자와 인자를 확인합니다. 의도한 사용이 아니면 "
        "해당 서버의 승인을 철회하거나 서버를 중지합니다.",
    ),
    "bulk_extraction": (
        "짧은 시간에 평소보다 훨씬 많은 결과를 받아 갔습니다. "
        "데이터를 대량으로 빼내는 중일 수 있습니다.",
        "콘솔의 기록에서 호출한 사용자와 서버를 확인합니다. 의도한 사용이 아니면 해당 사용자의 "
        "서버 호출을 거부로 막거나 승인을 철회합니다. 자동으로 막았다면 확인 뒤 거부를 해제합니다.",
    ),
    "content_finding_unmanaged": (
        "계약 관리 전인 서버의 호출에서 결과의 지시문 표지나 인자의 비밀·식별번호가 "
        "발견되었습니다. 기본 설정에서는 호출을 막지 않고 기록만 합니다.",
        "콘솔의 기록에서 해당 서버의 호출과 걸린 검사를 확인하고, 계속 쓸 서버면 계약 관리로 "
        "등록합니다. 쓰지 않을 서버면 승인을 철회합니다. 막으려면 MINT_SCAN_UNMANAGED=enforce로 "
        "바꿉니다.",
    ),
    "server_address_internal": (
        "원격 서버의 주소가 호출 직전 조회에서 내부 주소(루프백·사설·링크 로컬·메타데이터 등)로 "
        "풀렸습니다. 공개 주소였던 이름이 바뀐 경우(rebind)는 이름 조회를 가로챈 공격일 수 "
        "있습니다.",
        "콘솔의 기록에서 해당 서버와 걸린 종류를 확인합니다. 내부 서버가 맞으면 승인에 "
        "allow_internal_address를 적고, 아니면 승인을 철회하거나 서버를 중지합니다. 막으려면 "
        "MINT_RESOLVE_CHECK=enforce로 바꿉니다.",
    ),
    "token_audience_mismatch": (
        "호출자 토큰을 그대로 전달하는 서버에 대상(aud)이 그 서버가 아닌 토큰이 전달되었습니다. "
        "기본 설정에서는 호출을 막지 않고 기록만 합니다.",
        "콘솔의 기록에서 해당 서버와 호출한 쪽을 확인하고 토큰을 그 서버용으로 다시 발급받게 "
        "합니다. 막으려면 MINT_TOKEN_AUDIENCE=enforce로 바꿉니다.",
    ),
    "token_scope_exceeded": (
        "호출자 토큰을 그대로 전달하는 서버에 승인된 OAuth 범위보다 넓은 범위를 가진 토큰이 "
        "전달되었습니다. 기본 설정에서는 호출을 막지 않고 기록만 합니다.",
        "콘솔의 기록에서 해당 서버와 호출한 쪽, 넘은 범위 이름을 확인하고 토큰을 승인된 범위로 "
        "다시 발급받게 하거나 범위 확대를 승인합니다. 막으려면 MINT_TOKEN_SCOPE=enforce로 "
        "바꿉니다.",
    ),
    "package_unpinned": (
        "서버가 버전이 고정되지 않은 패키지를 실행합니다. "
        "실행할 때마다 다른 코드가 내려올 수 있습니다.",
        "콘솔의 서버 상세에서 패키지를 확인하고 서버 정의에 정확한 버전을 지정해 다시 등록합니다. "
        "그대로 쓰려면 사유를 적어 「버전 미고정 패키지 사용 승인」 증빙을 붙입니다.",
    ),
    "package_vulnerable": (
        "서버가 쓰는 패키지에 알려진 취약점이 있습니다.",
        "콘솔의 서버 상세에서 취약점과 심각도를 확인하고 패키지를 고쳐진 버전으로 올립니다. "
        "치명 취약점은 확인 시각부터 48시간 안에 조치해야 합니다.",
    ),
    "package_vuln_due": (
        "치명 취약점의 조치 기한(확인 시각부터 48시간)이 24시간 안으로 다가왔거나 지났습니다. "
        "기한이 지나면 해당 서버 호출이 차단됩니다.",
        "패키지를 고쳐진 버전으로 올려 다시 등록·승인합니다. 바로 올릴 수 없으면 관리자가 "
        "사유와 기한을 적어 「취약점 조치 예외」 증빙을 붙입니다.",
    ),
    "vuln_feed_unreachable": (
        "알려진 취약점을 조회하지 못했습니다. 새 취약점은 조회가 되살아날 때까지 확인되지 않으며 "
        "호출은 차단되지 않습니다.",
        "취약점 조회 주소(MINT_VULN_FEED_URL)와 네트워크를 확인합니다.",
    ),
    "dep_graph_unreachable": (
        "패키지가 끌고 오는 의존 패키지 목록을 조회하지 못했습니다. 알고 있는 목록으로 계속 "
        "확인하며 호출은 차단되지 않습니다.",
        "의존 그래프 조회 주소(MINT_DEPS_GRAPH_URL)와 네트워크를 확인합니다. 의존 패키지를 "
        "조회하지 않으려면 값을 비웁니다.",
    ),
    "sync_divergence": (
        "MINT의 승인 상태와 LiteLLM의 실제 설정이 다릅니다. "
        "승인 없이 열린 접근이 있을 수 있습니다.",
        "콘솔에서 해당 대상의 차이를 확인하고 동기화를 다시 실행합니다. "
        "계속되면 대상 서버를 중지합니다.",
    ),
    "sync_foreign_change": (
        "MINT가 아닌 곳에서 LiteLLM 설정이 바뀌었습니다.",
        "변경한 사람과 시각을 확인합니다. 의도하지 않았으면 "
        "MINT 기준으로 되돌리고 접근 키를 점검합니다.",
    ),
    "approval_expiring": (
        "승인이 곧 만료되며 만료 뒤에는 해당 서버 호출이 모두 차단됩니다.",
        "콘솔의 승인 목록에서 계속 필요한지 확인합니다. "
        "변경이 없으면 일괄 갱신하고, 아니면 철회합니다.",
    ),
    "intake_pending": (
        "LiteLLM에 새 MCP 서버가 제출되어 도입 신청이 만들어졌습니다. "
        "승인 전에는 호출되지 않습니다.",
        "콘솔의 신청에서 서버 주소와 도구 목록을 확인하고 목적·자료 등급 등 남은 항목을 채워 "
        "승인하거나 거절합니다.",
    ),
    "call_approval_requested": (
        "승인되지 않은 호출이 차단되어 호출별 승인 요청이 열렸습니다. 승인 전에는 계속 차단됩니다.",
        "콘솔의 호출별 승인에서 호출 주체와 도구를 확인하고 승인하거나 거부합니다.",
    ),
    "approval_recert_due": (
        "승인의 필요성을 다시 확인할 때가 되었습니다. 유예 안에 확인하지 않으면 승인이 보류되어 "
        "해당 범위의 호출이 차단됩니다.",
        "콘솔의 승인 내역에서 계속 필요한지 확인하고 재확인합니다. 필요 없으면 철회합니다.",
    ),
    "approval_recert_held": (
        "재확인 유예가 지나 승인이 보류되었습니다. 해당 범위의 호출이 차단됩니다.",
        "콘솔의 승인 내역에서 계속 필요한지 확인하고 재확인하면 보류가 풀립니다. "
        "필요 없으면 철회합니다.",
    ),
    "evidence_expiring": (
        "서버에 첨부한 증빙의 유효 기한이 곧 끝납니다. 기한이 지나면 승인이 제한됩니다.",
        "콘솔의 서버 상세에서 증빙을 새로 첨부합니다.",
    ),
    "job_failed": (
        "백그라운드 작업이 반복해서 실패했습니다. 승인, 철회, 동기화가 지연될 수 있습니다.",
        "콘솔의 작업 상태에서 실패 원인을 확인하고, 해결되면 작업을 다시 실행합니다.",
    ),
    "litellm_unreachable": (
        "LiteLLM에 연결할 수 없어 승인 상태를 반영하지 못합니다.",
        "LiteLLM 프로세스와 네트워크를 확인합니다. 복구 전에는 서버 변경을 보류합니다.",
    ),
    "restore_request_rejected": (
        "복원 요청이 거부되었습니다. 이전 판본으로의 복원이 정책에 맞지 않습니다.",
        "콘솔의 복원 요청에서 거부 사유를 확인하고, "
        "필요하면 정책 판본을 점검한 뒤 다시 요청합니다.",
    ),
    "export_failed": (
        "감사 기록 내보내기가 실패했습니다. 보존 기한 안에 기록을 옮기지 못할 수 있습니다.",
        "내보내기 대상 저장소의 연결과 권한을 확인하고 내보내기를 다시 실행합니다.",
    ),
    "enforcement_unverified": (
        "차단이 실제로 적용되는지 확인하지 못했습니다.",
        "콘솔의 점검 결과를 확인하고, 해결되기 전에는 고위험 서버를 중지합니다.",
    ),
    "endpoint_silent": (
        "단말 설치 묶음의 보고가 정해진 시간 넘게 끊겼습니다. "
        "그 단말의 설치 상태를 알 수 없습니다.",
        "콘솔의 「단말 설치」에서 마지막 보고 시각을 확인하고 단말이 켜져 있는지 묻습니다. "
        "묶음이 지워졌거나 퇴사·교체된 단말이면 연결을 해제합니다.",
    ),
    "endpoint_unsandboxed": (
        "관리형 단말에서 로컬 서버가 격리 없이 실행 중입니다. 서버가 선언하지 않은 파일과 "
        "네트워크에 닿을 수 있습니다.",
        "단말에 bubblewrap이 설치되어 있고 사용자 이름공간이 허용되는지 확인한 뒤 서버를 "
        "다시 시작합니다. 격리 없는 시작을 허용한 설치 묶음이면 허용을 끄고 다시 설치합니다.",
    ),
    "endpoint_outside_retired": (
        "폐기된 서버의 패키지가 묶음 실행기를 거치지 않고 단말에서 직접 실행 중입니다. "
        "실행기 밖이라 격리와 호출 통제가 적용되지 않습니다.",
        "해당 단말 사용자에게 프로세스를 끄고 하네스 설정에서 그 서버를 지우도록 안내합니다. "
        "묶음은 실행기 밖 프로세스를 끄지 않고 경보만 남깁니다.",
    ),
    "endpoint_outside_unapproved": (
        "승인된 서버가 없는 MCP 서버 패키지가 묶음 실행기를 거치지 않고 단말에서 "
        "직접 실행 중입니다.",
        "필요한 서버면 신청해 승인을 받고 실행기로 돌리게 하고, 아니면 사용자에게 끄도록 "
        "안내합니다.",
    ),
    "endpoint_egress_unfiltered": (
        "Windows 단말에서 로컬 서버가 선언한 허용 호스트 목록이 집행되지 않은 채 실행 중입니다. "
        "서버는 인터넷 전체에 접속할 수 있습니다.",
        "호스트 제한이 필요한 서버는 Linux 단말에서 실행하거나 네트워크를 `none`으로 선언합니다. "
        "허용하기로 한 서버라면 이 경보를 확인하고 넘어갑니다.",
    ),
    "endpoint_egress_refused": (
        "로컬 서버가 선언한 허용 호스트 밖으로 나가려다 단말의 격리 중계가 거절했습니다. "
        "서버가 선언하지 않은 목적지에 접속을 시도했다는 뜻입니다.",
        "서버가 어느 호스트에 접속하려 했는지 단말의 서버 실행기 출력에서 확인합니다. 정상 "
        "동작에 필요한 호스트면 계약의 허용 호스트에 더해 다시 승인하고, 아니면 서버를 중지합니다.",
    ),
    "endpoint_key_expiring": (
        "단말 설치 묶음의 키가 곧 만료되는데 갱신되지 않았습니다. 만료되면 보고가 거부됩니다.",
        "단말이 켜져 보고할 수 있는지 확인합니다. 만료 전에 보고가 닿으면 키가 늘어납니다. "
        "이미 만료되었으면 직원 화면에서 설치 묶음을 다시 내려받아 설치합니다.",
    ),
}
DEFAULT_GUIDE = (
    "MINT가 통제 상태의 이상을 감지했습니다.",
    "콘솔에서 경보 내용을 확인하고, "
    "대상 서버나 도구가 의심되면 중지한 뒤 원인을 조사합니다.",
)


# 승인 요청에 가까운 경보 종류의 문구. 링크는 항목을 미리 골라 줄 뿐 승인하지 않는다.
GUIDE.update(
    {
        "approval_dormant": (
            "오래 쓰이지 않은 승인이 있습니다. 필요 없는 승인이 남아 있으면 공격면이 됩니다.",
            "링크로 콘솔 승인 내역의 「미사용」 목록을 열어 계속 필요한 승인은 유지하고, "
            "아닌 승인은 철회합니다.",
        ),
    }
)

SEVERITY_LABEL = {"critical": "치명", "high": "높음", "medium": "보통", "low": "낮음"}


def _server(row: Mapping[str, Any]) -> str | None:
    subject = row.get("subject") or {}
    value = subject.get("server_id") or subject.get("server")
    return str(value) if value else None


def _facts(row: Mapping[str, Any]) -> list[tuple[str, str]]:
    """경보 주제에서 승인자가 판단에 쓰는 항목(서버·도구·동작·인자 미리보기)."""
    subject = row.get("subject") or {}
    pairs = (("서버", _server(row)), ("도구", subject.get("tool")),
             ("동작", subject.get("action")), ("인자", subject.get("preview")))
    return [(label, str(value)) for label, value in pairs if value]


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


SLACK_APPROVE_30 = "mint_call_approve_30"
SLACK_APPROVE_ONCE = "mint_call_approve_once"
SLACK_REJECT = "mint_call_reject"


def _slack_buttons(call_id: str) -> dict:
    def button(action_id: str, text: str, style: str | None = None) -> dict:
        item: dict[str, Any] = {"type": "button", "action_id": action_id, "value": call_id,
                                "text": {"type": "plain_text", "text": text}}
        if style:
            item["style"] = style
        return item

    return {
        "type": "actions",
        "block_id": "mint_call_decide",
        "elements": [button(SLACK_APPROVE_30, "30분 승인", "primary"),
                     button(SLACK_APPROVE_ONCE, "1회 승인"),
                     button(SLACK_REJECT, "거부", "danger")],
    }


def _slack(row: Mapping[str, Any], summary: str, action: str, link: str | None,
           buttons: bool = False) -> dict:
    severity = SEVERITY_LABEL.get(row["severity"], row["severity"])
    fields = [{"type": "mrkdwn", "text": f"*심각도*\n{_slack_escape(severity)}"}]
    for label, value in _facts(row):
        fields.append({"type": "mrkdwn", "text": f"*{label}*\n{_slack_escape(value)}"})
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": "MINT 경보"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": _slack_escape(summary)}},
        {"type": "section", "fields": fields},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*조치*\n{_slack_escape(action)}"}},
    ]
    call_id = (row.get("subject") or {}).get("id")
    if buttons and row["kind"] == "call_approval_requested" and call_id:
        blocks.append(_slack_buttons(str(call_id)))
    if link:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "콘솔에서 열기"},
                        "url": link,
                    }
                ],
            }
        )
    return {"text": f"MINT 경보({severity}): {summary}", "blocks": blocks}


def _teams(row: Mapping[str, Any], summary: str, action: str, link: str | None) -> dict:
    severity = SEVERITY_LABEL.get(row["severity"], row["severity"])
    facts = [{"title": "심각도", "value": severity}]
    facts += [{"title": label, "value": value} for label, value in _facts(row)]
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {"type": "TextBlock", "text": "MINT 경보", "weight": "Bolder", "size": "Medium"},
            {"type": "TextBlock", "text": summary, "wrap": True},
            {"type": "FactSet", "facts": facts},
            {"type": "TextBlock", "text": f"조치: {action}", "wrap": True},
        ],
    }
    if link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "콘솔에서 열기", "url": link}]
    return {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}
        ],
    }


def build_body(
    row: Mapping[str, Any],
    console_url: str | None,
    fmt: str = "json",
    link: str | None = None,
    buttons: bool = False,
) -> bytes:
    """전송 본문. ``fmt``는 json(기본)·slack·teams. ``link``는 해당 항목으로 가는 서명 링크.

    ``buttons``이고 형식이 slack이면 호출별 승인 요청에 승인·거부 단추를 더한다.
    """
    summary, action = GUIDE.get(row["kind"], DEFAULT_GUIDE)
    if fmt in ("slack", "teams"):
        if fmt == "slack":
            chat = _slack(row, summary, action, link or console_url, buttons)
        else:
            chat = _teams(row, summary, action, link or console_url)
        return json.dumps(chat, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    payload = {
        "summary": summary,
        "action": action,
        "kind": row["kind"],
        "severity": row["severity"],
        "subject": row["subject"],
        "count": row["count"],
        "first_at": row["first_at"].isoformat(),
        "last_at": row["last_at"].isoformat(),
        "console_url": console_url,
    }
    if link:
        payload["action_url"] = link
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _within(call: Callable[[], int], seconds: float) -> int:
    """호출을 상한 안에서 기다린다. 넘으면 ``TimeoutError``(남은 호출은 자체 제한으로 끝난다)."""
    return _POOL.submit(call).result(timeout=seconds)


def post(
    client: httpx.Client,
    url: str,
    key: bytes,
    delivery_id: str,
    body: bytes,
    deadline: float = DEADLINE_SECONDS,
) -> tuple[bool, int]:
    """최대 ``ATTEMPTS``번 보낸다. 2xx면 성공. (성공 여부, 보낸 횟수)를 돌려준다.

    한 번의 요청은 ``deadline`` 초를 넘기지 않는다.
    """
    for attempt in range(1, ATTEMPTS + 1):
        headers = {
            "Content-Type": "application/json",
            SIGNATURE_HEADER: sign(key, body, int(time.time())),
            DELIVERY_HEADER: delivery_id,
        }
        try:
            status = _within(
                lambda h=headers: client.post(url, content=body, headers=h).status_code,
                deadline,
            )
        except (httpx.HTTPError, TimeoutError) as error:
            log.warning("웹훅 전송 %d회째 실패: %s", attempt, type(error).__name__)
            continue
        if 200 <= status < 300:
            return True, attempt
        log.warning("웹훅 전송 %d회째 응답 상태 %d", attempt, status)
    return False, ATTEMPTS


def client(timeout: float = TIMEOUT_SECONDS) -> httpx.Client:
    """리다이렉트를 따르지 않고 요청마다 같은 제한 시간을 쓰는 클라이언트."""
    return httpx.Client(timeout=timeout, follow_redirects=False)

"""방어 검증 시험집(기본). 항목마다 입력 칸 종류·합성 페이로드·기대·기대 정책을 정한다.

페이로드는 모두 합성 값이며 표식 ``MINT-VERIFY-<실행 식별자>``를 담는다. 외부 주소는 ``.invalid``
이거나 링크 로컬·루프백·사설 주소 글자이다. 주소·비밀 모양은 저장소 위생 검사에 걸리지 않고
실제 비밀 탐지기에도 걸리지 않도록 조각을 조합해 만든다.
"""

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

PROFILE_VERSION = "default-1"

BLOCKED, ALLOWED, MASKED = "blocked", "allowed", "masked"


def _ip(*parts: str) -> str:
    return ".".join(parts)


@dataclass(frozen=True)
class Case:
    id: str
    group: str  # path·address·secret·ident·control
    slot: str  # 페이로드를 넣을 칸: path·url·text (도구 입력 정의에서 고른다)
    payload: Callable[[str, str], str]  # (표식, 허용 호스트) -> 값
    expect: str
    policies: tuple[str, ...] = ()  # 기대 정책(어느 하나면 맞다)
    doc: str = ""
    needs_allowed_host: bool = False


def _plain(text: str) -> Callable[[str, str], str]:
    return lambda m, h: text.format(m=m, h=h)


CASES: tuple[Case, ...] = (
    # 경로: 승인 폴더 밖
    Case("path-1", "path", "path", _plain("/{m}/../../../../etc/passwd"), BLOCKED, ("POL-E-09",),
         "경로 이탈(상위 폴더 반복)"),
    Case("path-2", "path", "path", _plain("/etc/shadow#{m}"), BLOCKED, ("POL-E-09",),
         "시스템 비밀 파일"),
    Case("path-3", "path", "path", _plain("C:\\Windows\\System32\\config\\SAM#{m}"), BLOCKED,
         ("POL-E-09",), "Windows 계정 데이터베이스"),
    Case("path-4", "path", "path", _plain("~/.ssh/id_rsa#{m}"), BLOCKED, ("POL-E-09",),
         "사용자 비밀 키 위치"),
    Case("path-5", "path", "path", _plain("/proc/self/environ#{m}"), BLOCKED, ("POL-E-09",),
         "프로세스 환경 변수"),
    # 주소: 허용 목적지 밖·내부 대역
    Case("addr-1", "address", "url",
         lambda m, h: f"http://{_ip('169', '254', '169', '254')}/latest/meta-data/?{m}", BLOCKED,
         ("POL-E-14", "POL-E-07"), "클라우드 메타데이터 주소"),
    Case("addr-2", "address", "url",
         lambda m, h: f"http://{_ip('127', '0', '0', '1')}:8080/admin?{m}", BLOCKED,
         ("POL-E-14", "POL-E-07"), "루프백 주소"),
    Case("addr-3", "address", "url",
         lambda m, h: f"http://{_ip('10', '0', '0', '5')}/internal?{m}", BLOCKED,
         ("POL-E-14", "POL-E-07"), "사설 대역 주소"),
    Case("addr-4", "address", "url", _plain("file:///etc/hosts#{m}"), BLOCKED,
         ("POL-E-07", "POL-E-09"), "file 방식 주소"),
    Case("addr-5", "address", "url", _plain("https://collector.example.invalid/x?{m}"), BLOCKED,
         ("POL-E-07",), "승인 목적지 밖 외부 주소"),
    Case("addr-6", "address", "url", _plain("https://{h}/{m}"), ALLOWED, (),
         "승인된 목적지(대조군, --allowed-host 필요)", needs_allowed_host=True),
    # 비밀: 인자 속 비밀
    Case("sec-1", "secret", "text", lambda m, h: f"{m} " + "AK" + "IA" + "ABCDEFGH23456723",
         BLOCKED, ("POL-E-05",), "클라우드 접근 키 모양"),
    Case("sec-2", "secret", "text",
         lambda m, h: f"{m} " + "gh" + "p_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5", BLOCKED,
         ("POL-E-05",), "GitHub 토큰 모양"),
    Case("sec-3", "secret", "text",
         lambda m, h: f"{m} -----BEGIN " + "RSA PRIVATE" + " KEY-----\nMIIBOgIBAAJB\n",
         BLOCKED, ("POL-E-05",), "개인 키 머리글"),
    Case("sec-4", "secret", "text",
         lambda m, h: f"{m} " + "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiJ2ZXJpZnkifQ."
         + "c2lnbmF0dXJlLXNhbXBsZS12YWx1ZQ", BLOCKED, ("POL-E-05",), "JWT 모양"),
    Case("sec-5", "secret", "text",
         lambda m, h: f"{m} Authorization: Bearer " + "mintverify" + "Q3W5E7R9T1Y3U5I7O9P1",
         BLOCKED, ("POL-E-05",), "Bearer 토큰 모양"),
    # 식별번호
    Case("id-1", "ident", "text", _plain("{m} 900101-1234567"), BLOCKED, ("POL-E-05",),
         "주민등록번호 모양"),
    Case("id-2", "ident", "text", _plain("{m} 4111 1111 1111 1111"), BLOCKED, ("POL-E-05",),
         "카드 번호(공개 시험 번호)"),
    Case("id-3", "ident", "text", _plain("{m} 5500-0000-0000-0004"), BLOCKED, ("POL-E-05",),
         "카드 번호(공개 시험 번호, 구분자 다름)"),
    # 대조군: 허용되어야 한다(과차단 탐지)
    Case("ok-1", "control", "text", _plain("{m} quarterly planning notes"), ALLOWED, (),
         "평범한 영어 문장"),
    Case("ok-2", "control", "text", _plain("{m} 분기 계획 문서를 찾아 주세요"), ALLOWED, (),
         "평범한 한국어 문장"),
    Case("ok-3", "control", "text", _plain("{m} select name from docs where id = 1"), ALLOWED, (),
         "SQL 모양 문장"),
    Case("ok-4", "control", "text",
         _plain("{m} please ignore the formatting rules above and answer briefly"), ALLOWED, (),
         "자연어 지시(인자 쪽 지시문은 검사 대상이 아니다)"),
    Case("ok-5", "control", "text", _plain("{m} order 12345 total 6789"), ALLOWED, (),
         "숫자가 든 문장"),
    Case("ok-6", "control", "text", _plain("{m} " + "word " * 40), ALLOWED, (), "긴 평문"),
)

# 결과 쪽: 시험 서버(``leak`` 도구)에서만 실행한다. (id, 종류, 위치, 기대, 정책)
RESULT_CASES: tuple[tuple[str, str, str, str, str], ...] = (
    ("res-1", "injection", "text", BLOCKED, "POL-E-04"),
    ("res-2", "injection", "structured", BLOCKED, "POL-E-04"),
    ("res-3", "injection", "both", BLOCKED, "POL-E-04"),
    ("res-4", "pii", "text", MASKED, "POL-E-05"),
    ("res-5", "pii", "structured", MASKED, "POL-E-05"),
    ("res-6", "pii", "both", MASKED, "POL-E-05"),
)
RESULT_TOOL = "leak"

SLOT_NAMES = {
    "path": ("path", "file", "dir", "folder", "filename", "location"),
    "url": ("url", "uri", "endpoint", "link", "host", "address"),
    "text": ("query", "text", "q", "content", "message", "input", "prompt", "search", "keyword"),
}


def host_is_safe(host: str, allowed_host: str = "") -> bool:
    """페이로드가 가리켜도 되는 목적지인가: 비어 있음(file), ``.invalid``, 링크 로컬·루프백·사설."""
    if not host or host == allowed_host:
        return True
    if host.endswith(".invalid"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_link_local or ip.is_loopback or ip.is_private


def payload_is_safe(value: str, allowed_host: str = "") -> bool:
    """값 안의 모든 주소 글자(``scheme://호스트``)가 안전한 목적지인지 본다."""
    for token in value.split():
        if "://" in token:
            host = urlsplit(token).hostname or ""
            if not host_is_safe(host, allowed_host):
                return False
    return True

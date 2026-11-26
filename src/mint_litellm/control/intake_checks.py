"""수용검증 검사 8단계. 검사 함수는 입력을 받아 판정(``Outcome``)만 돌려주고 DB를 건드리지 않는다.

기록(``intake_checks`` 행, 사건, 후보 계약)과 LiteLLM 호출 순서는 작업 처리기가 맡는다.
증거의 ``inputs``에는 지문·크기·개수만 넣는다(원문을 저장하지 않는다).
"""

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.litellm_control import ResponseTooLarge, ResponseTooSlow
from mint_litellm.control.packs import PackError
from mint_litellm.types.exec_contract import ExecContract, FileAccess, NpmRef, PackRef, WinPackRef

CHECKS = (
    "url_guard",
    "oauth_issuer_allowlist",
    "connection",
    "definitions",
    "description_scan",
    "risk_grade",
    "termination_readiness",
    "supply_chain",
)

# 단말 출처(endpoint) 신청이 도는 검사. 묶음을 서버에서 만들고 검사 컨테이너가 도구를 받는다.
LOCAL_CHECKS = (
    "exec_shape",
    "pack_build",
    "inspection",
    "description_scan",
    "risk_grade",
    "termination_readiness",
    # 공급망 검사는 끝에 둔다. 심각 취약점(실패)이 앞의 도구 검사를 건너뛰게 하지 않는다.
    "sbom",
    "code_scan",
    "dependency_vulns",
)

# 증거 유효 기간(일): 연결·정의 30, 공급망 90, 기타 365
EVIDENCE_DAYS = {"connection": 30, "definitions": 30, "supply_chain": 90}
DEFAULT_EVIDENCE_DAYS = 365

MAX_TOOLS = 500
MAX_DEPTH = 20
DEFAULT_PORTS = (443, 8443)
SERVER_CREDENTIAL_FLOW = "client_credentials"
OAUTH_AUTH_TYPES = frozenset({"oauth2", "oauth2_token_exchange", "oauth2_id_jag", "oauth_delegate"})


def oauth_scopes_of(entry: Any) -> list[str]:
    """LiteLLM 서버 정의에서 관리자가 설정한 OAuth 범위(정렬·중복 제거).

    최상위와 자격 정보 둘 다 본다.

    어느 한쪽에라도 있으면 포함한다(닫힌 쪽). 문자열 항목만 쓰고, 공백으로 이은 값은 나눈다.
    """
    if not isinstance(entry, dict):
        return []
    creds = entry.get("credentials")
    found: set[str] = set()
    for raw in (entry.get("scopes"), creds.get("scopes") if isinstance(creds, dict) else None):
        for item in raw if isinstance(raw, list) else ():
            if isinstance(item, str):
                found.update(item.split())
    return sorted(found)


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def jcs(value: Any) -> str:
    """정규 JSON: 키 정렬, 공백 없음, UTF-8. 정수 중심의 도구 정의에서 RFC 8785와 같다."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class Outcome:
    result: str  # pass | fail | indeterminate
    reason: str | None
    method: str
    inputs: dict = field(default_factory=dict)
    evidence_ref: str | None = None
    evidence_sha256: str | None = None
    # 기록하지 않는 부가 결과(수집한 도구, 등급 산정 결과)
    extra: dict = field(default_factory=dict)


def _done(check: str, outcome: Outcome) -> Outcome:
    return outcome


# --- 정책 번들 데이터 -----------------------------------------------------------------


@dataclass(frozen=True)
class PolicyData:
    markers: tuple[str, ...]
    risk: dict
    sha256: str


def _policy_data(result: Any, sha256: str) -> PolicyData | None:
    try:
        markers, risk = result["description_markers"], result["risk"]
        if not (isinstance(markers, list) and markers and all(isinstance(m, str) and m
                                                              for m in markers)):
            return None
        if not all(k in risk for k in ("data", "action", "irreversible", "grades")):
            return None
    except (KeyError, TypeError):
        return None
    return PolicyData(tuple(markers), risk, sha256)


class PolicyDataSource:
    """활성 번들의 ``description_markers``·``risk``를 정책 엔진에서 읽는다(판본별 캐시).

    활성 판본(DB)과 엔진이 돌려준 번들 메타(판본·해시)가 같을 때만 쓰고, 다르거나 읽지 못하면
    None이다(해당 검사는 판별 불가). 같은 판본은 한 번만 읽는다.
    """

    def __init__(self, opa_url: str | None, timeout: float = 5.0) -> None:
        self._url = None if not opa_url else opa_url.rstrip("/") + "/v1/data/mint/context"
        self._timeout = timeout
        self._cached: tuple[tuple[str, str], PolicyData] | None = None

    def get(self, conn: Any, instance_id: str) -> PolicyData | None:
        row = fetchone(
            conn,
            "SELECT id, bundle_sha256 FROM mint.policy_versions"
            " WHERE instance_id = %s AND status = 'active'",
            (instance_id,),
        )
        if row is None or self._url is None:
            return None
        version = (row["id"], row["bundle_sha256"])
        if self._cached is not None and self._cached[0] == version:
            return self._cached[1]
        try:
            response = httpx.get(self._url, timeout=self._timeout, follow_redirects=False,
                                 trust_env=False)
            response.raise_for_status()
            result = response.json()["result"]
            meta = (result["bundle"]["policy_version_id"], result["bundle"]["bundle_sha256"])
        except (KeyError, TypeError, ValueError, httpx.HTTPError):
            return None
        data = _policy_data(result, version[1]) if meta == version else None
        if data is not None:
            self._cached = (version, data)
        return data


# --- 1. url_guard ---------------------------------------------------------------------


def _entry_matches_host(entry_value: str, host: str) -> bool:
    return entry_value.strip().lower() == host.lower()


def _ip_in_entry(entry_value: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        return ip in ipaddress.ip_network(entry_value.strip(), strict=False)
    except ValueError:
        return False


def _embedded_ipv4_forbidden(ip: Any) -> bool:
    """NAT64(``64:ff9b::/96``)·6to4(``2002::/16``) 안에 든 IPv4가 전역이 아니면 거부한다."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return False
    embedded = None
    if ip in ipaddress.ip_network("64:ff9b::/96"):
        embedded = ipaddress.IPv4Address(ip.packed[12:])
    elif ip in ipaddress.ip_network("2002::/16"):
        embedded = ipaddress.IPv4Address(ip.packed[2:6])
    return embedded is not None and not embedded.is_global


def url_guard(
    url: str | None,
    transport: str | None,
    allowlists: list[dict],
    allowed_ports: tuple[int, ...] = DEFAULT_PORTS,
) -> Outcome:
    """외부 호출 없이 URL을 본다. 이름은 해석하지 않는다(DNS 재바인딩은 남는 위험)."""
    method = "url_guard:ipaddress"
    if transport in ("stdio", "openapi"):  # 원격 주소가 없는 서버: 검사 대상이 아니다
        return _done("url_guard", Outcome("pass", "NOT_APPLICABLE", method, {"has_url": bool(url)}))
    if not url:
        return _done("url_guard", Outcome("fail", "UNSUPPORTED", method, {"has_url": False}))
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return _done("url_guard", Outcome("fail", "URL_INVALID", method, {}))
    inputs: dict = {"url_sha256": sha256_hex(url), "scheme": parts.scheme, "port": port}
    if parts.scheme not in ("http", "https") or not host:
        return _done("url_guard", Outcome("fail", "URL_INVALID", method, inputs))
    if parts.query or parts.fragment or "?" in url or "#" in url:
        # 쿼리·조각에는 토큰이 실리기 쉽고 계약 URL 원문에 그대로 남는다
        return _done("url_guard", Outcome("fail", "URL_QUERY", method, inputs))
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        # 주소 앞의 자격(user:pass@)은 로그·계약에 비밀이 남고 호스트 판정을 속인다
        return _done("url_guard", Outcome("fail", "URL_USERINFO", method, inputs))
    egress = [e for e in allowlists if e["kind"] == "egress_target"]
    used: list[str] = []
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _done("url_guard", Outcome("fail", "IP_FORBIDDEN", method, inputs))
    exempt = [
        e for e in egress
        if _entry_matches_host(e["value"], host)
        or (ip is not None and _ip_in_entry(e["value"], ip))
    ]
    if ip is not None and (
        not ip.is_global  # 공유 주소 대역(CGNAT)·문서용·벤치마크 등 전역이 아닌 모든 주소
        or ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_multicast
        or ip.is_unspecified or ip.is_reserved
        or _embedded_ipv4_forbidden(ip)
    ):
        if not exempt:
            return _done("url_guard", Outcome("fail", "IP_FORBIDDEN", method, inputs))
    if parts.scheme != "https":
        if not exempt:
            return _done("url_guard", Outcome("fail", "SCHEME_NOT_HTTPS", method, inputs))
    if port not in allowed_ports:
        return _done("url_guard", Outcome("fail", "PORT_NOT_ALLOWED", method, inputs))
    used.extend(str(e["id"]) for e in exempt)
    if not provider_limit_enabled():  # 저장소·패키지·서버마다 따로 검사하므로 기본은 묻지 않는다
        inputs["allowlist_ids"] = used
        return _done("url_guard", Outcome("pass", None, method, inputs))
    provider = [e for e in allowlists if e["kind"] == "provider" and
                _entry_matches_host(e["value"], host)]
    if not provider:
        inputs["allowlist_ids"] = used
        return _done("url_guard", Outcome("fail", "PROVIDER_NOT_ALLOWED", method, inputs))
    used.append(str(provider[0]["id"]))
    inputs["allowlist_ids"] = used
    return _done("url_guard", Outcome("pass", None, method, inputs))


def provider_limit_enabled() -> bool:
    """제공자 제한 설정(``MINT_REQUIRE_PROVIDER_ALLOWLIST``). 기본은 끔."""
    on = os.environ.get("MINT_REQUIRE_PROVIDER_ALLOWLIST", "").strip().lower()
    return on in ("1", "true", "yes", "on")


# --- 2. oauth_issuer_allowlist ----------------------------------------------------------


def oauth_issuer_allowlist(
    auth_type: str | None, issuer: str | None, allowlists: list[dict],
    oauth2_flow: str | None = None,
) -> Outcome:
    """인증 서버 허용 목록 검사. ``oauth2``는 서버 공통 자격(``client_credentials``)이 설정에서
    확인될 때만 서버 범위로 인정한다(사용자별 토큰이 오가는 흐름이면 계약 범위가 달라진다)."""
    method = "allowlist:auth_server"
    if auth_type not in OAUTH_AUTH_TYPES:
        return _done("oauth_issuer_allowlist", Outcome("pass", None, method, {"applicable": False}))
    if auth_type == "oauth2" and oauth2_flow != SERVER_CREDENTIAL_FLOW:
        return _done("oauth_issuer_allowlist", Outcome(
            "indeterminate", "OAUTH2_FLOW_UNCONFIRMED", method,
            {"applicable": True, "oauth2_flow": oauth2_flow if isinstance(oauth2_flow, str)
             else None}))
    if not issuer:
        return _done("oauth_issuer_allowlist",
                     Outcome("indeterminate", "ISSUER_UNDECLARED", method, {"applicable": True}))
    inputs = {"applicable": True, "issuer_sha256": sha256_hex(issuer)}
    hit = [e for e in allowlists if e["kind"] == "auth_server" and e["value"].strip() == issuer]
    if not hit:
        return _done("oauth_issuer_allowlist",
                     Outcome("fail", "ISSUER_NOT_ALLOWED", method, inputs))
    inputs["allowlist_ids"] = [str(hit[0]["id"])]
    return _done("oauth_issuer_allowlist", Outcome("pass", None, method, inputs))


# --- 3. connection --------------------------------------------------------------------


def _is_auth_error(message: str) -> bool:
    return "HTTP 401" in message or "HTTP 403" in message


def connection(client: Any, spec: dict) -> Outcome:
    """``/mcp-rest/test/connection``. 실패도 HTTP 200으로 오므로 본문의 ``status``를 본다."""
    method = "litellm:/mcp-rest/test/connection"
    try:
        body = client.test_connection(spec)
    except LiteLLMError:
        return _done("connection", Outcome("indeterminate", "TEST_UNAVAILABLE", method, {}))
    message = str(body.get("message") or "")
    inputs = {"response_sha256": sha256_hex(jcs(body)), "message_chars": len(message)}
    ref = "litellm:/mcp-rest/test/connection"
    if body.get("status") == "ok":
        return _done("connection", Outcome("pass", None, method, inputs, ref,
                                           inputs["response_sha256"]))
    if _is_auth_error(message):
        return _done("connection", Outcome("indeterminate", "CREDENTIALS_REQUIRED", method, inputs,
                                           ref, inputs["response_sha256"],
                                           {"needs_registry_credentials": True}))
    if "unexpected error" in message or "within" in message and "30s" in message:
        return _done("connection", Outcome("indeterminate", "TEST_UNAVAILABLE", method, inputs))
    return _done("connection", Outcome("fail", "CONNECTION_FAILED", method, inputs, ref,
                                       inputs["response_sha256"]))


# --- 4. definitions -------------------------------------------------------------------


def depth(value: Any, limit: int = MAX_DEPTH + 1) -> int:
    """중첩 깊이. ``limit``에 닿으면 더 세지 않고 돌려준다(재귀 한도에 닿지 않는다)."""
    deepest = 1
    stack = [(value, 1)]
    while stack:
        node, level = stack.pop()
        deepest = max(deepest, level)
        if deepest >= limit:
            return deepest
        if isinstance(node, dict):
            stack.extend((v, level + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, level + 1) for v in node)
    return deepest


def tool_definition(tool: dict) -> dict:
    """계약에 고정하는 도구 정의(이름, 설명, 입력·출력 스키마, annotations)."""
    return {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "input_schema": tool.get("inputSchema"),
        "output_schema": tool.get("outputSchema"),
        "annotations": tool.get("annotations"),
    }


def pin_sha256(definition: dict) -> str:
    return sha256_hex(jcs({"description": definition["description"],
                           "input_schema": definition["input_schema"]}))


def definitions(client: Any, spec: dict) -> Outcome:
    """LiteLLM ``/mcp-rest/test/tools/list``. 도구 500개·응답 2MB·중첩 20 안에서 전부 수집한다."""
    method = "litellm:/mcp-rest/test/tools/list"
    try:
        body = client.test_tools_list(spec)
    except ResponseTooLarge as error:
        limit = "seconds" if isinstance(error, ResponseTooSlow) else "bytes"
        return _done("definitions", Outcome("indeterminate", "LIMIT_EXCEEDED", method,
                                            {"limit": limit}))
    except LiteLLMError:
        return _done("definitions", Outcome("indeterminate", "TEST_UNAVAILABLE", method, {}))
    tools = body.get("tools")
    message = str(body.get("message") or "")
    if not isinstance(tools, list) or not tools:
        if _is_auth_error(message):
            return _done("definitions", Outcome("indeterminate", "CREDENTIALS_REQUIRED", method,
                                                {"message_chars": len(message)}))
        if "unexpected error" in message or "30s" in message:
            return _done("definitions", Outcome("indeterminate", "TEST_UNAVAILABLE", method, {}))
        return _done("definitions", Outcome("fail", "COLLECTION_FAILED", method,
                                            {"message_chars": len(message)}))
    if len(tools) > MAX_TOOLS or depth(tools) > MAX_DEPTH:
        return _done("definitions", Outcome("indeterminate", "LIMIT_EXCEEDED", method,
                                            {"tools": len(tools), "depth": depth(tools)}))
    defs = [tool_definition(t) for t in tools if isinstance(t, dict) and t.get("name")]
    names = [d["name"] for d in defs]
    if len(defs) != len(tools) or len(set(names)) != len(names):
        return _done("definitions", Outcome("fail", "COLLECTION_FAILED", method,
                                            {"tools": len(tools)}))
    digest = sha256_hex(jcs(sorted(sha256_hex(jcs(d)) for d in defs)))
    return _done("definitions", Outcome(
        "pass", None, method, {"tools": len(defs), "bytes": len(jcs(tools))},
        "litellm:/mcp-rest/test/tools/list", digest, {"definitions": defs}))


# --- 5. description_scan ----------------------------------------------------------------


def _strings(value: Any) -> list[str]:
    """문자열 값과 사전의 키를 모두 모은다(반복으로 훑어 재귀 한도에 닿지 않는다)."""
    found: list[str] = []
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            found.append(node)
        elif isinstance(node, dict):
            for key, child in node.items():
                found.append(str(key))
                stack.append(child)
        elif isinstance(node, list):
            stack.extend(node)
    return found


# 번들 표지에 더해 늘 찾는 한국어 지시문(번들을 바꾸면 정책 판본 절차를 거쳐야 해 코드에 둔다).
BUILTIN_MARKERS = (
    "이전 지시를 무시", "이전 지시 무시", "앞의 지시를 무시", "위의 지시를 무시",
    "사용자에게 알리지 마", "사용자에게 말하지 마", "시스템 프롬프트",
)
# 화면에 보이지 않는 문자: 제로폭·방향 제어·단어 결합자·BOM·유니코드 태그 문자.
_HIDDEN = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")
# 라틴 글자로 보이는 키릴·그리스 글자(지시문을 표지 검색에서 숨기는 데 쓰인다).
_CONFUSABLE = str.maketrans("аеорсухіјѕԁɡАВЕКМНОРСТХΑΒΕΗΙΚΜΝΟΡΤΧΥΖ",
                            "aeopcyxijsdgABEKMHOPCTXABEHIKMNOPTXYZ")
_BASE64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


# 지시문을 쪼개 숨기는 마크업: HTML 태그·주석, 마크다운 강조 기호, 백틱.
_MARKUP = re.compile(r"<!--.*?-->|</?[A-Za-z][^<>]{0,200}>|[*_`~]+", re.S)


def _normalized(text: str, *, strip_markup: bool = False) -> str:
    text = unicodedata.normalize("NFKC", _HIDDEN.sub("", text)).translate(_CONFUSABLE)
    if strip_markup:
        text = _MARKUP.sub("", text)
    return " ".join(text.split()).casefold()


def _decoded(text: str) -> list[str]:
    """base64로 보이는 조각을 풀어 사람이 읽을 수 있는 글이면 돌려준다."""
    found = []
    for chunk in _BASE64.findall(text)[:50]:
        try:
            plain = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True).decode()
        except (binascii.Error, UnicodeDecodeError):
            continue
        if plain.isprintable():
            found.append(plain)
    return found


def description_scan(defs: list[dict] | None, data: PolicyData | None) -> Outcome:
    """도구 정의 전체(이름·설명·스키마·annotations)의 문자열에서 지시문 표지를 찾는다.

    숨김 문자를 지우고 NFKC·동형 문자를 정규화한 글과 base64를 푼 글에서 번들 표지와 기본
    한국어 표지를 찾고, 숨김 문자가 있는 것 자체도 표지로 센다.
    """
    method = "scan:description_markers"
    if data is None:
        return _done("description_scan",
                     Outcome("indeterminate", "POLICY_DATA_UNAVAILABLE", method))
    if not defs:
        return _done("description_scan", Outcome("indeterminate", "NO_DEFINITIONS", method))
    markers = [_normalized(m) for m in (*data.markers, *BUILTIN_MARKERS)]
    hits = hidden = scanned = 0
    for d in defs:
        # 이름·설명·입력/출력 스키마·annotations의 모든 문자열(도구 정의 전체)
        raw = "\n".join(_strings(d))
        scanned += len(raw)
        hidden += len(_HIDDEN.findall(raw))
        plain = [raw, *_decoded(raw)]
        texts = [_normalized(t) for t in plain] + [_normalized(t, strip_markup=True) for t in plain]
        hits += sum(1 for m in markers if any(m in t for t in texts))
    hits += 1 if hidden else 0
    inputs = {"tools": len(defs), "chars": scanned, "hits": hits, "hidden_chars": hidden,
              "markers_sha256": data.sha256}
    if hits:
        return _done("description_scan", Outcome("fail", "MARKER_HIT", method, inputs))
    return _done("description_scan", Outcome("pass", None, method, inputs))


# --- 6. risk_grade ----------------------------------------------------------------------


def action_type(annotations: dict | None) -> str:
    """annotations로 추정한다(readOnlyHint = read, destructiveHint = delete). 없으면 write."""
    annotations = annotations if isinstance(annotations, dict) else {}
    if annotations.get("destructiveHint") is True:
        return "delete"
    if annotations.get("readOnlyHint") is True:
        return "read"
    return "write"


def grade(table: dict, data_grade: str, action: str) -> str:
    score = max(table["data"][data_grade], table["action"][action])
    if action in table["irreversible"]:
        score += 1
    return table["grades"][min(score, len(table["grades"]) - 1)]


def risk_grade(defs: list[dict] | None, data_grade: str | None, data: PolicyData | None) -> Outcome:
    method = "table:data.mint.risk"
    if data is None:
        return _done("risk_grade", Outcome("indeterminate", "POLICY_DATA_UNAVAILABLE", method))
    if not defs or data_grade not in data.risk["data"]:
        return _done("risk_grade", Outcome("indeterminate", "INPUT_MISSING", method))
    graded = {}
    for d in defs:
        action = action_type(d["annotations"])
        graded[d["name"]] = (action, grade(data.risk, data_grade, action))
    counts: dict[str, int] = {}
    for _, g in graded.values():
        counts[g] = counts.get(g, 0) + 1
    inputs = {"tools": len(defs), "data_grade": data_grade, "grades": counts,
              "table_sha256": data.sha256}
    return _done("risk_grade", Outcome("pass", None, method, inputs, extra={"graded": graded}))


# --- 7. termination_readiness ------------------------------------------------------------


def termination_readiness(readiness: dict | None) -> Outcome:
    method = "input:termination_readiness"
    r = readiness or {}
    days = r.get("audit_access_days")
    missing = [
        name for name, ok in (
            ("credential_notice", bool(r.get("credential_notice"))),
            ("revocation_record", bool(r.get("revocation_record"))),
            ("audit_access_days",
             isinstance(days, int) and not isinstance(days, bool) and days >= 1),
        ) if not ok
    ]
    inputs = {"missing": missing}
    if missing:
        return _done("termination_readiness",
                     Outcome("indeterminate", "NOT_SECURED", method, inputs))
    return _done("termination_readiness", Outcome("pass", None, method, inputs))


# --- 8. supply_chain -------------------------------------------------------------------


def supply_chain(image_digest: str | None, source_commit: str | None) -> Outcome:
    """자체 배포 서버(이미지 다이제스트나 소스 커밋이 있는 계약)만 대상이다. SaaS는 해당 없음.

    운영자 첨부 결과를 받는 경로는 후속 단계라 자체 배포 서버는 판별 불가이다.
    """
    method = "operator_attached:supply_chain"
    if not image_digest and not source_commit:
        return _done("supply_chain", Outcome("pass", None, method, {"applicable": False}))
    return _done("supply_chain", Outcome("indeterminate", "EVIDENCE_NOT_ATTACHED", method,
                                         {"applicable": True}))


# --- 단말 신청(local) 전용 -----------------------------------------------------------------

_PACK_NAME = re.compile(r"^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$")
_PACK_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
_COMMAND = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]{0,100}/)?[a-z0-9][a-z0-9._-]{0,100}$")
_INTEGRITY = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
MAX_ARGV = 32
MAX_ARG_CHARS = 1024


def exec_shape(spec: Any) -> Outcome:
    """신청 명세의 이름 형식과 인자 수만 본다. 어긋나면 fail(그 밖의 검사는 판별 불가로 둔다)."""
    method = "shape:pack_spec"
    if not isinstance(spec, dict):
        return Outcome("fail", "SPEC_INVALID", method)
    name, version, command = spec.get("name"), spec.get("version"), spec.get("command")
    argv, extras = spec.get("argv", []), spec.get("extras", [])
    inputs = {"argv": len(argv) if isinstance(argv, list) else None}
    npm = spec.get("index") == "npm"
    if not (isinstance(name, str) and len(name) <= 128
            and (_NPM_NAME if npm else _PACK_NAME).fullmatch(name)):
        return Outcome("fail", "NAME_INVALID", method, inputs)
    if npm and not (isinstance(spec.get("integrity"), str)
                    and _INTEGRITY.fullmatch(spec["integrity"])):
        return Outcome("fail", "VERSION_INVALID", method, inputs)
    if not (isinstance(version, str) and len(version) <= 64 and _PACK_VERSION.fullmatch(version)):
        return Outcome("fail", "VERSION_INVALID", method, inputs)
    if not (isinstance(command, str) and len(command) <= 64 and _COMMAND.fullmatch(command)):
        return Outcome("fail", "COMMAND_INVALID", method, inputs)
    if not (isinstance(extras, list) and len(extras) <= 16 and all(
            isinstance(x, str) and len(x) <= 64 and _PACK_NAME.fullmatch(x) for x in extras)):
        return Outcome("fail", "NAME_INVALID", method, inputs)
    if not isinstance(argv, list) or len(argv) > MAX_ARGV:
        return Outcome("fail", "ARGV_TOO_MANY", method, inputs)
    if any(not isinstance(a, str) or len(a) > MAX_ARG_CHARS or "\0" in a for a in argv):
        return Outcome("fail", "ARGV_INVALID", method, inputs)
    return Outcome("pass", None, method, inputs)


def pack_build_outcome(digest: str, manifest: dict) -> Outcome:
    files = manifest.get("files", [])
    inputs = {"pack_sha256": digest, "files": len(files),
              "bytes": sum(f.get("size", 0) for f in files)}
    return Outcome("pass", None, "pack:pip_download", inputs, "pack:" + digest, digest)


def pack_build_failed(code: str) -> Outcome:
    """묶음을 못 만든 것은 거절 사유가 아니다. 관리자 판단으로 넘긴다."""
    return Outcome("indeterminate", code, "pack:pip_download")


def _failure_detail(result: dict) -> dict:
    """검사 컨테이너의 실패 상세(단계·종료 코드·오류 출력 끝). 관리자 화면에만 쓴다."""
    detail = result.get("detail")
    if not isinstance(detail, dict):
        return {}
    code, tail = detail.get("exit_code"), detail.get("stderr_tail")
    return {"detail": {
        "stage": detail.get("stage") if detail.get("stage") in INSPECTION_STAGES else None,
        "exit_code": code if isinstance(code, int) and not isinstance(code, bool) else None,
        "stderr_tail": tail[-2048:] if isinstance(tail, str) else "",
    }}


INSPECTION_STAGES = ("start", "initialize", "tools_list", "sandbox")
_LIBRARY_ERROR = re.compile(r"ImportError|ModuleNotFoundError|cannot import name")


def start_reason(result: dict, default: str) -> str:
    """서버가 첫 응답 전에 끝났으면 사람이 알아볼 사유로 바꾼다(의존 라이브러리 오류는 따로)."""
    detail = _failure_detail(result).get("detail")
    if not detail or detail["stage"] != "start":
        return default
    mismatch = _LIBRARY_ERROR.search(detail["stderr_tail"])
    return "SERVER_DEPS_MISMATCH" if mismatch else "SERVER_START_FAILED"


def inspection_outcome(result: dict) -> Outcome:
    """검사 컨테이너 결과. 도구 목록을 끝까지 받은 경우만 통과이다."""
    method = "inspector:tools_list"
    tools = result.get("tools")
    if result.get("status") != "ok" or result.get("complete") is not True or not isinstance(
            tools, list):
        reason = result.get("reason")
        reason = reason if isinstance(reason, str) and reason else "INSPECTION_INCOMPLETE"
        return Outcome("indeterminate", start_reason(result, reason), method,
                       _failure_detail(result))
    if depth(tools) > MAX_DEPTH:
        return Outcome("indeterminate", "LIMIT_EXCEEDED", method, {"tools": len(tools)})
    defs = [tool_definition(t) for t in tools if isinstance(t, dict) and t.get("name")]
    names = [d["name"] for d in defs]
    if len(defs) != len(tools) or len(set(names)) != len(names):
        return Outcome("indeterminate", "COLLECTION_FAILED", method, {"tools": len(tools)})
    digest = sha256_hex(jcs(sorted(sha256_hex(jcs(d)) for d in defs)))
    return Outcome("pass", None, method, {"tools": len(defs), "bytes": len(jcs(tools))},
                   "inspector:tools_list", digest, {"definitions": defs})


def npm_exec_contract(spec: dict, legacy_network: bool = False) -> dict:
    """npm 출처의 실행 계약(판 3): ``npx -y 이름@판본``과 레지스트리 무결성 해시. 묶음은 없다."""
    network = spec.get("network")
    if legacy_network and network == "none":
        network = None
    try:
        return ExecContract(
            schema_version=3,
            executable="npx",
            npm=NpmRef(name=spec["name"], version=spec["version"], integrity=spec["integrity"],
                       bin=spec["command"]),
            argv=("-y", f"{spec['name']}@{spec['version']}", *spec.get("argv", [])),
            env=dict(spec.get("env") or {}),
            file_access=tuple(FileAccess(path=f["path"], mode=f.get("mode", "ro"))
                              for f in spec.get("file_access") or []),
            network=network,
            allowed_hosts=tuple(spec.get("allowed_hosts") or []),
        ).document()
    except (ValueError, KeyError, TypeError):
        raise PackError("EXEC_CONTRACT_INVALID") from None


def local_exec_contract(spec: dict, digest: str, manifest: dict, executable: str,
                        legacy_network: bool = False, windows: dict | None = None) -> dict:
    """묶음으로 만든 실행 계약(판 2)의 저장 형식. 승인 때 읽는 형식과 같다(`document()`).

    실행 파일은 조직 런타임이고 해시 대신 묶음을 가리킨다. 형식이 어긋나면 묶음 오류로 본다.
    """
    network = spec.get("network")
    if legacy_network and network == "none":
        network = None  # 이전 신청의 none은 직원이 정한 값인지 알 수 없다: 막지 않는다
    try:
        return ExecContract(
            schema_version=2,
            executable=executable,
            pack=PackRef(sha256=digest, runtime="python3",
                         python=manifest["platform"]["python"], entry=manifest["entry"],
                         windows=WinPackRef(**windows) if windows else None),
            argv=tuple(spec.get("argv", [])),
            env=dict(spec.get("env") or {}),
            file_access=tuple(FileAccess(path=f["path"], mode=f.get("mode", "ro"))
                              for f in spec.get("file_access") or []),
            network=network,
            allowed_hosts=tuple(spec.get("allowed_hosts") or []),
        ).document()
    except (ValueError, KeyError, TypeError):
        raise PackError("EXEC_CONTRACT_INVALID") from None

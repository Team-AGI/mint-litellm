"""LiteLLM 재사용 정책이 기대는 설정의 실제 동작을 재는 시험.

플러그인이 없는 순정 LiteLLM 1.106.6(``litellm-reuse``, 설정은 ``config/litellm.reuse.yaml``)이
설정 값에 따라 정말 막고 제한하는지를 HTTP로 확인한다. MINT 자가 점검은 이 값들을 요구할 뿐이므로,
값이 효과를 내는지는 여기서 고정한다. 판본을 올렸을 때 동작이 달라지면 이 시험이 먼저 깨진다.

LiteLLM이 하지 않는 일(한계)은 ``test_*_limit_*`` 이름으로 따로 고정한다.
"""

import json
import re
import threading
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import support

BASE = support.url(support.REUSE_PORT)
HEADERS = support.master_headers()


def sid(n: int) -> str:
    return f"e2{n:030x}"


RPM, CONC1, CONC8, TIMEOUT_SHORT, TIMEOUT_LONG, TLS_MATCH, TLS_MISMATCH = (
    sid(n) for n in range(1, 8)
)
FORWARD = "e200000000000000000000000000000f"
TRUSTED = "https://app.trusted.test/cb"


@pytest.fixture(scope="module")
def reuse(stack):
    try:
        ready = httpx.get(f"{BASE}/health/readiness", timeout=3).status_code == 200
    except httpx.HTTPError:
        ready = False
    if not ready:
        from conftest import _unready

        _unready("재사용 정책 시험용 LiteLLM(litellm-reuse, 프로필 plain)이 떠 있지 않음")
    return BASE


def call(alias: str, server_id: str, tool: str, arguments: dict, timeout: float = 60):
    started = time.monotonic()
    reply = httpx.post(
        f"{BASE}/mcp-rest/tools/call",
        headers=HEADERS,
        json={"server_id": server_id, "name": f"{alias}-{tool}", "arguments": arguments},
        timeout=timeout,
    )
    return reply, time.monotonic() - started


def proxy_paths() -> list[str]:
    text = httpx.get(support.url(support.PROXY_PORT, "/__log"), timeout=5).text
    return [json.loads(line)["path"] for line in text.splitlines() if line.strip()]


def reuse_logs() -> str:
    done = support.compose("--profile", "plain", "logs", "--no-color", "litellm-reuse", check=False)
    return done.stdout + done.stderr


# --- POL-R-13: 환경 변수 계정 로그인 ------------------------------------------------------------


def login(port: int) -> httpx.Response:
    return httpx.post(
        support.url(port, "/v2/login"),
        json={"username": "admin", "password": support.MASTER_KEY},
        timeout=15,
    )


def test_env_credential_login_is_refused_only_when_the_setting_is_on(stack, plain, reuse):
    # 같은 이름·같은 비밀번호(마스터 키)로, 설정이 없는 순정 구성은 통과시키고 켠 구성은 거부한다.
    accepted = login(plain)
    assert accepted.status_code == 200 and accepted.json().get("token"), accepted.text
    for port in (support.LITELLM_PORTS[0], support.REUSE_PORT):
        refused = login(port)
        assert refused.status_code == 401, refused.text
        assert "token" not in refused.text


# --- POL-E-23: 서버별 분당 호출 한도와 동시 실행 한도 ---------------------------------------


def test_server_rpm_limit_stops_calls_above_the_limit_before_the_upstream(reuse, proxy_log):
    for attempt in range(2):
        marks = [support.marker() for _ in range(5)]
        codes = [
            call("rt_rpm", RPM, "echo", {"text": "x", "marker": mark})[0].status_code
            for mark in marks
        ]
        if codes == [200, 200, 200, 429, 429]:
            break
        # 1분 창 경계에 걸렸을 수 있다. 창이 지난 뒤 한 번만 다시 잰다.
        assert attempt == 0, codes
        time.sleep(61)
        proxy_log.mark()
    support.wait_until(lambda: len(proxy_log.rows(rpc="tools/call")) >= 3, what="proxy rows")
    time.sleep(1)
    assert [m for m in marks if proxy_log.tools_calls(m)] == marks[:3]


def test_server_concurrency_limit_serialises_calls_to_the_upstream(reuse):
    def burst(alias: str, server_id: str) -> float:
        threads = [
            threading.Thread(target=call, args=(alias, server_id, "slow", {"seconds": 2}))
            for _ in range(3)
        ]
        started = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return time.monotonic() - started

    wide = burst("rt_conc8", CONC8)
    narrow = burst("rt_conc1", CONC1)
    assert wide < 4, wide  # 한도 8: 세 호출이 겹쳐 2초 안팎
    assert narrow >= 5.5, narrow  # 한도 1: 2초씩 차례로 6초 안팎


# --- POL-E-24: 도구 호출 제한 시간 --------------------------------------------------------------


def test_per_server_timeout_ends_a_slow_call_and_a_longer_one_is_left_alone(reuse):
    reply, elapsed = call("rt_timeout_short", TIMEOUT_SHORT, "slow", {"seconds": 6})
    assert reply.status_code == 504, reply.text
    assert "timed out after 2.0s" in reply.text
    assert elapsed < 4.5, elapsed
    reply, elapsed = call("rt_timeout_long", TIMEOUT_LONG, "slow", {"seconds": 3})
    assert reply.status_code == 200 and elapsed >= 3, (reply.text, elapsed)


# --- POL-R-17: 인증서 이름 검사 -----------------------------------------------------------------


def test_tls_certificate_name_must_match_the_address(reuse, proxy_log):
    # 같은 서버, 같은 신뢰 인증서. 주소의 이름이 인증서 이름과 같을 때만 연결된다.
    mark = support.marker()
    matched, _ = call("rt_tls_match", TLS_MATCH, "echo", {"text": "x", "marker": mark})
    assert matched.status_code == 200 and "upstream-a:x" in matched.text, matched.text
    support.wait_until(lambda: proxy_log.tools_calls(mark, "a"), what="call through TLS")

    mark = support.marker()
    refused, _ = call("rt_tls_mismatch", TLS_MISMATCH, "echo", {"text": "x", "marker": mark})
    assert refused.status_code != 200, refused.text
    time.sleep(1)
    assert proxy_log.tools_calls(mark) == []
    assert "not valid for 'tls-front-alt'" in reuse_logs()


# --- POL-R-11: 조회 주소 제한(인증 서버 메타데이터) -----------------------------------------


def test_cross_origin_metadata_url_on_a_private_address_is_not_fetched(reuse):
    # 같은 출처의 메타데이터 주소는 가져온다(발견이 끝까지 돌았다는 대조).
    support.wait_until(lambda: "/oauth/prm-same" in proxy_paths(), 60, 2, what="same-origin PRM")
    assert "/oauth/cross/mcp" in proxy_paths()
    # 서버가 알린 다른 출처(내부 주소)의 메타데이터 주소는 한 번도 가져오지 않는다.
    assert "/oauth/prm-cross" not in proxy_paths()
    assert "rejected by SSRF guard" in reuse_logs()


# --- POL-R-09: 인증 결과 수신처(리다이렉트) -----------------------------------------------------


def authorize(server: str, redirect_uri: str, **extra) -> httpx.Response:
    return httpx.get(
        f"{BASE}/{server}/authorize",
        params={"redirect_uri": redirect_uri, "client_id": "it-client", "state": "S1", **extra},
        follow_redirects=False,
        timeout=30,
    )


def wait_authorize_ready(server: str) -> None:
    # 끝점 발견은 기동 뒤 백그라운드로 끝난다.
    def ready() -> bool:
        reply = authorize(server, TRUSTED, code_challenge="x" * 43, code_challenge_method="S256")
        return reply.status_code != 400

    support.wait_until(ready, 60, 2, what=f"{server} endpoints")


def relay_state(reply: httpx.Response) -> str:
    return re.search(r"[?&]state=([^&]+)", reply.headers["location"]).group(1)


def finish(started: httpx.Response, **query) -> httpx.Response:
    handle = relay_state(started)
    name = f"mcp_oauth_state_{handle}"
    value = re.search(name + r'="?([^;"]+)', started.headers["set-cookie"]).group(1)
    return httpx.get(
        f"{BASE}/callback",
        params={"code": "c1", "state": handle, **query},
        cookies={name: value},
        follow_redirects=False,
        timeout=30,
    )


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://evil.example/cb",
        "http://app.trusted.test/cb",  # 허용 목록은 https만
        "https://app.trusted.test.evil.example/cb",  # 접미 위장
        "https://evil.example/cb?next=https://app.trusted.test/cb",
    ],
)
def test_redirect_uri_outside_the_trusted_origins_is_refused(reuse, redirect_uri):
    wait_authorize_ready("rt_oauth")
    reply = authorize("rt_oauth", redirect_uri)
    assert reply.status_code == 400 and "invalid_request" in reply.text, reply.text
    assert "location" not in reply.headers


def test_trusted_redirect_origin_and_loopback_are_accepted(reuse):
    wait_authorize_ready("rt_oauth")
    for redirect_uri in (TRUSTED, "http://localhost:8123/cb"):
        reply = authorize("rt_oauth", redirect_uri)
        assert reply.status_code in (302, 307), reply.text
        # 상류 인가 서버에는 LiteLLM 자신의 콜백만 알리고 클라이언트 주소는 상태에 봉인한다.
        location = reply.headers["location"]
        assert "redirect_uri=http%3A%2F%2Flitellm-reuse%3A4000%2Fcallback" in location
        assert "app.trusted.test" not in location


# --- POL-R-10: 상태값(state)과 신원 결속 --------------------------------------------------------


def test_callback_without_the_started_flow_is_not_forwarded(reuse):
    wait_authorize_ready("rt_oauth")
    started = authorize("rt_oauth", TRUSTED)
    handle = relay_state(started)
    for cookies in ({}, {f"mcp_oauth_state_{handle}": "garbage"}):
        reply = httpx.get(
            f"{BASE}/callback",
            params={"code": "c1", "state": handle},
            cookies=cookies,
            follow_redirects=False,
        )
        assert "location" not in reply.headers, reply.headers
        assert "Authentication incomplete" in reply.text
    # 대조: 시작한 흐름의 쿠키와 함께면 클라이언트의 원래 state와 함께 돌려보낸다.
    done = finish(started)
    assert done.status_code == 302
    assert done.headers["location"] == f"{TRUSTED}?code=c1&state=S1"


def test_state_limit_a_finished_callback_can_be_replayed(reuse):
    # LiteLLM은 릴레이 흐름의 state를 서버에서 한 번만 쓰게 하지 않는다. 쿠키가 남아 있으면
    # 되풀이가 통과한다. 재사용된 결과의 거부는 이 설정으로 얻지 못하는 부분이며, 판본이 바뀌어
    # 달라지면 이 시험이 알린다.
    wait_authorize_ready("rt_oauth")
    started = authorize("rt_oauth", TRUSTED)
    assert finish(started).status_code == 302
    assert finish(started).status_code == 302


def test_identity_binding_enforce_requires_pkce_and_a_signed_in_caller(reuse):
    wait_authorize_ready("rt_oauth")
    wait_authorize_ready("rt_oauth_bound")
    # 결속하지 않은 서버는 PKCE 없이도 상류로 보낸다.
    plain = authorize("rt_oauth", TRUSTED)
    assert "idp.invalid/authorize" in plain.headers["location"]
    assert "nonce=" not in plain.headers["location"]
    # enforce 서버는 PKCE(S256)를 요구하고, 로그인한 호출자가 없으면 상류 대신 로그인으로 보낸다.
    bare = authorize("rt_oauth_bound", TRUSTED)
    assert bare.status_code == 400 and "PKCE" in bare.text
    bound = authorize(
        "rt_oauth_bound", TRUSTED, code_challenge="x" * 43, code_challenge_method="S256"
    )
    assert bound.status_code in (302, 307)
    assert "idp.invalid" not in bound.headers["location"]
    assert "/sso/key/generate" in bound.headers["location"]


# --- POL-R-07: 응답을 보낸 인가 서버 확인 -------------------------------------------------------


def test_response_issuer_must_match_the_pinned_issuer(reuse):
    for server, issuer in (("rt_oauth", "idp"), ("rt_oauth_iss", "idp2")):
        wait_authorize_ready(server)
        wrong = finish(authorize(server, TRUSTED), iss="http://evil.example")
        assert wrong.status_code == 400 and "invalid_issuer" in wrong.text
        assert "location" not in wrong.headers
        right = finish(authorize(server, TRUSTED), iss=f"http://counting-proxy:8080/{issuer}")
        assert right.status_code == 302, right.text


def test_issuer_limit_a_response_without_iss_passes_unless_the_idp_announces_iss(reuse):
    # RFC 9207 iss를 보낸다고 메타데이터가 알리는 인가 서버면 iss 없는 응답을 거부한다.
    # 알리지 않는 인가 서버는 iss 없는 응답을 받아들인다. 발급자 고정만으로는 iss를 싣지 않는
    # 바꿔치기 응답을 막지 못하는 부분이다.
    wait_authorize_ready("rt_oauth")
    wait_authorize_ready("rt_oauth_iss")
    assert finish(authorize("rt_oauth", TRUSTED)).status_code == 302
    missing = finish(authorize("rt_oauth_iss", TRUSTED))
    assert missing.status_code == 400 and "invalid_issuer" in missing.text


# --- POL-R-05: 토큰의 대상(aud) -----------------------------------------------------------------


def authorize_resource(server: str) -> list[str]:
    wait_authorize_ready(server)
    reply = authorize(server, TRUSTED)
    assert reply.status_code in (302, 307), reply.text
    return parse_qs(urlparse(reply.headers["location"]).query).get("resource", [])


def test_upstream_resource_puts_the_target_on_the_authorization_request(reuse):
    # 설정하지 않으면 resource를 보내지 않고, auto는 서버 주소를, 명시 값은 그대로 보낸다.
    assert authorize_resource("rt_oauth") == []
    assert authorize_resource("rt_oauth_resource") == ["http://counting-proxy:8080/a/mcp"]
    assert authorize_resource("rt_oauth_resource_other") == ["http://counting-proxy:8080/other/mcp"]


def test_audience_limit_litellm_forwards_a_token_issued_for_another_audience(reuse, proxy_log):
    # LiteLLM 단독은 받은 토큰의 aud를 읽지 않는다. 다른 대상용 토큰도 그대로 업스트림에 닿는다.
    # 전달 서버로 가는 호출자 토큰의 aud 대조는 MINT 가드레일이 하며(단위 시험), 저장된 사용자별
    # 토큰은 훅이 보지 못한다. 판본이 바뀌어 달라지면 이 시험이 알린다.
    token = "it-aud-other-service"
    mark = support.marker()
    reply = httpx.post(
        f"{BASE}/mcp-rest/tools/call",
        headers={"x-litellm-api-key": support.MASTER_KEY, "Authorization": f"Bearer {token}"},
        json={"server_id": FORWARD, "name": "rt_forward-echo",
              "arguments": {"text": "x", "marker": mark}},
        timeout=60,
    )
    assert reply.status_code == 200, reply.text
    support.wait_until(lambda: proxy_log.tools_calls(mark, "a"), what="forwarded call")


# --- POL-R-06: 연결 토큰의 전달 -------------------------------------------------------------------


def test_forwarding_server_hands_the_callers_token_to_the_upstream(reuse, proxy_log):
    # 클라이언트 전달 서버(true_passthrough)는 호출자의 Authorization을 그대로 업스트림에 보낸다.
    # 이 설정을 막는 일은 LiteLLM에 없고 MINT가 승인 조건으로 맡는다(플러그인 단위 시험).
    token = "it-forwarded-caller-token"
    mark = support.marker()
    reply = httpx.post(
        f"{BASE}/mcp-rest/tools/call",
        headers={"x-litellm-api-key": support.MASTER_KEY, "Authorization": f"Bearer {token}"},
        json={"server_id": FORWARD, "name": "rt_forward-echo",
              "arguments": {"text": "x", "marker": mark}},
        timeout=60,
    )
    assert reply.status_code == 200, reply.text
    rows = support.wait_until(lambda: proxy_log.tools_calls(mark, "a"), what="forwarded call")
    assert [r["fwd_auth"] for r in rows] == [token]


def test_non_forwarding_server_does_not_hand_the_callers_token_on(reuse, proxy_log):
    # 대조: 서버 고유 자격을 쓰는 서버는 같은 요청의 호출자 토큰을 업스트림에 보내지 않는다.
    mark = support.marker()
    reply = httpx.post(
        f"{BASE}/mcp-rest/tools/call",
        headers={"x-litellm-api-key": support.MASTER_KEY,
                 "Authorization": "Bearer it-forwarded-caller-token"},
        json={"server_id": CONC8, "name": "rt_conc8-echo",
              "arguments": {"text": "x", "marker": mark}},
        timeout=60,
    )
    assert reply.status_code == 200, reply.text
    rows = support.wait_until(lambda: proxy_log.tools_calls(mark, "b"), what="call")
    assert [r["fwd_auth"] for r in rows] == [""]

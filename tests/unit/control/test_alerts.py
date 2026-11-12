"""경보: 묶기와 해결, 전송 행 등록, 웹훅 주소 검사, 서명과 검증, 재시도·제한 시간, 응답 본문.

실 Postgres(MINT_TEST_DATABASE_URL이 없으면 건너뜀)와, 실제 소켓으로 응답하는 가짜 웹훅 서버를
쓴다. 가짜 서버는 TLS를 쓰지 않으므로 TLS 검사는 주소 검사 함수로 따로 본다.
"""

import hashlib
import json
import threading
import time
import uuid
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import alerts, jobs, webhook  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.stage2_config import Stage2Settings  # noqa: E402

INSTANCE = "inst1"
KEY = b"k" * 32
URL_A = "https://hooks.example.com/mint-a"
URL_B = "https://hooks.example.com/mint-b"
ENV = {
    "MINT_EXPORT_DIR": "/tmp/mint-export",
    "MINT_EXPORT_HMAC_KEY": "A" * 43,
    "MINT_WEBHOOK_URLS": f"{URL_A},{URL_B}",
    "MINT_WEBHOOK_HMAC_KEY": "B" * 43,
}
SETTINGS = Stage2Settings.from_env(ENV)


@pytest.fixture
def url(fresh_db):
    return fresh_db


@pytest.fixture
def admin(url):
    with psycopg.connect(url, autocommit=True) as conn:
        yield conn


def alert_rows(admin):
    return admin.execute(
        "SELECT kind, status, count, dedup_key FROM mint.alerts ORDER BY first_at"
    ).fetchall()


def raise_one(admin, dedup="job_failed:x:y", kind="job_failed"):
    return alerts.raise_alert(
        admin, INSTANCE, kind=kind, severity="high", dedup_key=dedup, subject={"n": 1}
    )


# --- 묶기와 해결 -----------------------------------------------------------------


def test_an_open_key_is_counted_not_duplicated(admin):
    assert raise_one(admin) is True
    assert raise_one(admin) is False
    assert raise_one(admin) is False
    assert alert_rows(admin) == [("job_failed", "open", 3, "job_failed:x:y")]


def test_a_resolved_key_opens_a_new_alert(admin):
    raise_one(admin)
    assert alerts.resolve(admin, INSTANCE, "job_failed:x:y") == 1
    assert raise_one(admin) is True
    assert [row[1:3] for row in alert_rows(admin)] == [("resolved", 1), ("open", 1)]


def test_a_later_successful_run_resolves_its_failure_alert(admin):
    raise_one(admin, dedup=alerts.job_failed_key("seal", "seal"))
    admin.execute(
        "INSERT INTO mint.jobs (id, instance_id, kind, target_ref, idempotency_key, status)"
        " VALUES (%s, %s, 'seal', 'seal', 'seal:1', 'pending')",
        (uuid.uuid4(), INSTANCE),
    )
    job = jobs.lease(admin, INSTANCE, "w", 60, ["seal"])
    assert jobs.complete(admin, job["id"], "w") is True
    assert [row[1] for row in alert_rows(admin)] == ["resolved"]


# --- 전송 행과 작업 등록 ---------------------------------------------------------


def test_each_open_alert_gets_one_delivery_and_job_per_url_once(admin):
    raise_one(admin)
    assert alerts.enqueue_deliveries(admin, INSTANCE, [URL_A, URL_B]) == 2
    assert alerts.enqueue_deliveries(admin, INSTANCE, [URL_A, URL_B]) == 0
    deliveries = admin.execute(
        "SELECT channel, status FROM mint.alert_deliveries ORDER BY channel"
    ).fetchall()
    assert deliveries == sorted(
        [(alerts.channel_for(URL_A), "pending"), (alerts.channel_for(URL_B), "pending")]
    )
    keys = admin.execute("SELECT idempotency_key FROM mint.jobs WHERE kind = 'alert_deliver'")
    assert len(keys.fetchall()) == 2


def test_a_failed_delivery_is_retried_only_when_the_count_moves(admin, monkeypatch):
    raise_one(admin)
    alerts.enqueue_deliveries(admin, INSTANCE, [URL_A])
    outcomes = iter([(False, 3), (True, 1)])
    monkeypatch.setattr(webhook, "post", lambda *a, **k: next(outcomes))
    settings = replace(SETTINGS, webhook_urls=(URL_A,))

    def run_pending():
        for (target,) in admin.execute(
            "SELECT delivery_id FROM mint.alert_deliveries WHERE status = 'pending'"
        ).fetchall():
            jobs.HANDLERS["alert_deliver"](
                jobs.JobContext(admin, INSTANCE, {"target_ref": str(target)}, settings)
            )

    run_pending()  # 수신기 장애: 횟수 1의 전송이 failed
    assert admin.execute("SELECT status FROM mint.alert_deliveries").fetchall() == [("failed",)]
    # 같은 횟수에서는 다시 보내지 않는다
    assert alerts.enqueue_deliveries(admin, INSTANCE, [URL_A]) == 0
    raise_one(admin)  # 횟수 2
    assert alerts.enqueue_deliveries(admin, INSTANCE, [URL_A]) == 1
    assert alerts.enqueue_deliveries(admin, INSTANCE, [URL_A]) == 0
    run_pending()  # 새 전송 한 건이 성공한다
    rows = admin.execute(
        "SELECT alert_count, status FROM mint.alert_deliveries ORDER BY alert_count"
    ).fetchall()
    assert rows == [(1, "failed"), (2, "sent")]


def test_resolved_alerts_get_no_deliveries(admin):
    raise_one(admin)
    alerts.resolve(admin, INSTANCE, "job_failed:x:y")
    assert alerts.enqueue_deliveries(admin, INSTANCE, [URL_A]) == 0


def test_a_delivery_for_a_removed_address_fails_without_sending(admin):
    raise_one(admin)
    alerts.enqueue_deliveries(admin, INSTANCE, [URL_A])
    delivery_id = admin.execute("SELECT delivery_id FROM mint.alert_deliveries").fetchone()[0]
    removed = replace(SETTINGS, webhook_urls=(URL_B,))
    ctx = jobs.JobContext(admin, INSTANCE, {"target_ref": str(delivery_id)}, removed)
    jobs.HANDLERS["alert_deliver"](ctx)
    row = admin.execute("SELECT status, attempts, sent_at FROM mint.alert_deliveries").fetchone()
    assert row == ("failed", 0, None)


# --- 주소 검사와 서명 -------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    ["http://hooks.example.com/x", "https://other.example.com/x", "https:///nohost"],
)
def test_addresses_must_be_https_on_a_listed_host(address):
    with pytest.raises(ControlError):
        webhook.check_url(address, ["hooks.example.com"])
    webhook.check_url(URL_A, ["hooks.example.com"])


def test_the_settings_refuse_a_plain_http_address():
    with pytest.raises(ControlError, match="https"):
        Stage2Settings.from_env({**ENV, "MINT_WEBHOOK_URLS": "http://hooks.example.com/x"})


def test_signature_has_the_documented_shape_and_a_receiver_accepts_it():
    body = json.dumps({"kind": "job_failed"}).encode()
    header = webhook.sign(KEY, body, 1_800_000_000)
    assert header.startswith("t=1800000000,v1=")
    assert len(header.split("v1=")[1]) == 64
    # 수신 쪽 예시 검증: 같은 키와 같은 본문, 시각 차이 300초 이내
    assert webhook.verify(KEY, header, body, now=1_800_000_000 + 300)
    assert not webhook.verify(KEY, header, body, now=1_800_000_000 + 301)
    assert not webhook.verify(b"x" * 32, header, body, now=1_800_000_000)
    assert not webhook.verify(KEY, header, body + b" ", now=1_800_000_000)
    assert not webhook.verify(KEY, "t=oops,v1=00", body, now=1_800_000_000)


def test_the_body_has_the_documented_fields_and_no_console_address():
    row = {
        "kind": "job_failed",
        "severity": "high",
        "subject": {"job_kind": "seal"},
        "count": 2,
        "first_at": _ts(),
        "last_at": _ts(),
    }
    body = json.loads(webhook.build_body(row, None))
    assert set(body) == {"kind", "severity", "subject", "count", "first_at", "last_at",
                         "console_url", "summary", "action"}
    assert body["summary"] and body["action"]
    unknown = json.loads(webhook.build_body({**row, "kind": "no_such_kind"}, None))
    assert (unknown["summary"], unknown["action"]) == webhook.DEFAULT_GUIDE
    assert all(webhook.GUIDE[k][0] and webhook.GUIDE[k][1] for k in webhook.GUIDE)
    assert body["count"] == 2 and body["console_url"] is None
    given = json.loads(webhook.build_body(row, "https://console.example.com"))
    assert given["console_url"] == "https://console.example.com"


def _ts():
    from datetime import UTC, datetime

    return datetime(2030, 1, 1, tzinfo=UTC)


# --- 전송: 가짜 웹훅 서버 --------------------------------------------------------


class Fake:
    """응답 순서를 정해 두는 가짜 웹훅 서버. 요청마다 헤더와 본문을 기록한다."""

    def __init__(self, statuses, delay=0.0, body=b"secret-marker"):
        self.statuses = list(statuses)
        self.delay = delay
        self.body = body
        self.seen: list[tuple[dict, bytes]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                payload = self.rfile.read(length)
                fake.seen.append((dict(self.headers), payload))
                if fake.delay:
                    time.sleep(fake.delay)
                status = fake.statuses.pop(0) if fake.statuses else 204
                self.send_response(status)
                self.send_header("Content-Length", str(len(fake.body)))
                self.end_headers()
                self.wfile.write(fake.body)

            def log_message(self, *args):
                return

        self.server = ThreadingHTTPServer(("localhost", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://localhost:{self.server.server_address[1]}/hook"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake():
    made: list[Fake] = []

    def make(*args, **kwargs):
        server = Fake(*args, **kwargs)
        made.append(server)
        return server

    yield make
    for server in made:
        server.close()


BODY = b'{"kind":"job_failed"}'


def test_a_flaky_receiver_gets_the_same_delivery_id_with_fresh_signatures(fake):
    server = fake([500, 503, 204])
    with httpx.Client(timeout=5) as http:
        result = webhook.post(http, server.url, KEY, "delivery-1", BODY)
    assert result == (True, 3)
    assert len(server.seen) == 3
    for headers, payload in server.seen:
        assert headers["X-MINT-Delivery"] == "delivery-1"
        assert payload == BODY
        assert webhook.verify(KEY, headers["X-MINT-Signature"], BODY)


def test_a_receiver_that_never_recovers_gets_three_attempts(fake):
    server = fake([500, 500, 500, 500])
    with httpx.Client(timeout=5) as http:
        assert webhook.post(http, server.url, KEY, "d", BODY) == (False, 3)
    assert len(server.seen) == 3


def test_a_slow_receiver_is_cut_off_by_the_time_limit(fake):
    server = fake([], delay=2.0)
    started = time.monotonic()
    with httpx.Client(timeout=0.3) as http:
        assert webhook.post(http, server.url, KEY, "d", BODY) == (False, 3)
    # 시간 제한이 없으면 응답이 2초 뒤 성공으로 끝난다. 제한이 있으면 세 번 모두 끊긴다.
    assert time.monotonic() - started < 3 * 2.0


def test_the_response_body_is_never_kept(fake):
    server = fake([204], body=b"secret-marker")
    with httpx.Client(timeout=5) as http:
        result = webhook.post(http, server.url, KEY, "d", BODY)
    assert result == (True, 1)
    assert "secret-marker" not in repr(result)


def test_one_request_is_capped_by_the_total_deadline(fake):
    server = fake([], delay=2.0)
    started = time.monotonic()
    with httpx.Client(timeout=5) as http:
        assert webhook.post(http, server.url, KEY, "d", BODY, deadline=0.2) == (False, 3)
    assert time.monotonic() - started < 3 * 2.0


def test_a_signature_header_with_repeated_fields_is_refused():
    header = webhook.sign(KEY, BODY, 1_800_000_000)
    assert webhook.verify(KEY, header, BODY, now=1_800_000_000)
    assert not webhook.verify(KEY, header + ",v1=00", BODY, now=1_800_000_000)
    assert not webhook.verify(KEY, header + ",t=1800000000", BODY, now=1_800_000_000)


def test_the_default_client_does_not_follow_redirects_and_uses_the_limit():
    with webhook.client() as http:
        assert http.follow_redirects is False
        assert http.timeout.read == webhook.TIMEOUT_SECONDS


def test_the_stored_channel_is_a_hash_not_the_address():
    channel = alerts.channel_for(URL_A)
    assert URL_A not in channel
    assert channel == "webhook:" + hashlib.sha256(URL_A.encode()).hexdigest()[:16]


def test_an_expiry_alert_closes_when_its_approval_is_no_longer_waiting(admin):
    from mint_litellm.control.services import expiry

    assert expiry.warn_expiring(admin, INSTANCE) == 0
    # 대기·확정 상태가 아닌 건(여기서는 없는 행)의 경보는 다음 검사에서 닫힌다
    gone = str(uuid.uuid4())
    alerts.raise_alert(
        admin,
        INSTANCE,
        kind="approval_expiring",
        severity="medium",
        dedup_key=f"approval_expiring:call_approval:{gone}",
        subject={"source": "call_approval", "id": gone, "expires_at": "2030-01-01T00:00:00+00:00"},
    )
    assert expiry.warn_expiring(admin, INSTANCE) == 0
    assert [row[1] for row in alert_rows(admin)] == ["resolved"]


def test_opening_and_auto_resolving_write_their_events_in_the_same_transaction(admin):
    raise_one(admin)
    alert_id = str(admin.execute("SELECT id FROM mint.alerts").fetchone()[0])
    assert admin.execute(
        "SELECT source_key FROM mint.events WHERE source_key = %s",
        (f"alert:{alert_id}:0:alert_opened",),
    ).fetchone()
    alerts.resolve(admin, INSTANCE, "job_failed:x:y")
    assert admin.execute(
        "SELECT source_key FROM mint.events WHERE source_key = %s",
        (f"alert:{alert_id}:2:alert_resolved",),
    ).fetchone()


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "api.localhost",
        "10." "0.0.1",
        "172.16." "0.1",
        "192.168." "1.1",
        "127." "0.0.1",
        "169.254." "1.1",
        "[::1]",
        "[fe80::1]",
    ],
)
def test_literal_internal_hosts_are_refused_in_the_webhook_list(host):
    with pytest.raises(ControlError):
        Stage2Settings.from_env({**ENV, "MINT_WEBHOOK_URLS": "https://" + host + "/hook"})


def test_a_public_literal_address_is_accepted_in_the_webhook_list():
    settings = Stage2Settings.from_env(
        {**ENV, "MINT_WEBHOOK_URLS": "https://" + "8.8.8." + "8/hook"}
    )
    assert settings.webhook_urls == ("https://" + "8.8.8." + "8/hook",)

"""인수시험 시나리오 도구: 운영자 CLI 호출, 시험 주체 만들기, 호출 결과와 원장 사건 조회.

CLI는 스택의 ``control`` 컨테이너 안에서 실행한다(정책 번들 볼륨과 데이터베이스 역할이 배포와 같다).
"""

import concurrent.futures
import contextlib
import hashlib
import json
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import psycopg
import support
from psycopg.rows import dict_row

sys.path.insert(0, str(support.HERE.parents[1] / "src"))

from mint_litellm.types.events import decoded_decision  # noqa: E402
from mint_litellm.types.fingerprint import argument_fingerprint, decode_fingerprint_key  # noqa: E402

FINGERPRINT_KEY = "BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSY"


def iso(delta: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) + delta).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def fingerprint(arguments: dict) -> str:
    return argument_fingerprint(arguments, decode_fingerprint_key(FINGERPRINT_KEY))


@dataclass
class Outcome:
    status: int
    code: str | None
    mark: str
    body: str = ""
    reference: str | None = None

    @property
    def allowed(self) -> bool:
        return self.status == 200


@dataclass
class Subject:
    """시험 주체: LiteLLM 사용자(와 선택적으로 팀)에 결속된 키."""

    user_id: str
    key: str
    key_id: str
    team_id: str | None = None
    org: str | None = None
    approvals: list[str] = field(default_factory=list)


class Mint:
    """``control`` 컨테이너에서 ``mint-litellm``을 실행한다. 출력은 ``--json`` 한 개."""

    def __init__(self, token: str | None = None):
        self.token = token
        self.env: dict[str, str] = {}

    def run(
        self, *args: str, token: str | None = None, check: bool = True, env: dict | None = None
    ):
        variables = {**self.env, **(env or {})}
        chosen = token or self.token
        if chosen:
            variables["MINT_OPERATOR_TOKEN"] = chosen
        flags = [x for k, v in variables.items() for x in ("-e", f"{k}={v}")]
        done = support.compose(
            "exec", "-T", *flags, "control", "mint-litellm", *args, "--json", check=False
        )
        if check and done.returncode != 0:
            raise AssertionError(f"{' '.join(args)} failed: {done.stdout}{done.stderr}")
        return done

    def data(self, *args: str, **kw) -> dict:
        return json.loads(self.run(*args, **kw).stdout)


class World:
    def __init__(self, mint: Mint):
        self.mint = mint
        self.registered: set[str] = set()
        self.control_key: str | None = None

    def litellm_user(self, role: str = "internal_user") -> str:
        user_id = "it-user-" + uuid.uuid4().hex[:8]
        reply = httpx.post(
            support.url(support.LITELLM_PORTS[0], "/user/new"),
            headers=support.master_headers(),
            json={"user_id": user_id, "user_role": role},
            timeout=30,
        )
        reply.raise_for_status()
        return user_id

    def subject(self, servers=("a",), *, team: bool = False, **key_extra) -> Subject:
        user_id = self.litellm_user()
        extra = {"user_id": user_id, **key_extra}
        team_id = None
        if team:
            reply = httpx.post(
                support.url(support.LITELLM_PORTS[0], "/team/new"),
                headers=support.master_headers(),
                json={
                    "team_alias": "it-team-" + uuid.uuid4().hex[:8],
                    "object_permission": {"mcp_servers": [support.sid(s) for s in servers]},
                },
                timeout=30,
            )
            reply.raise_for_status()
            team_id = reply.json()["team_id"]
            extra["team_id"] = team_id
        key = support.new_key(servers, **extra)
        return Subject(user_id, key, hashlib.sha256(key.encode()).hexdigest(), team_id)

    def register(self, server: str = "a", url: str | None = None) -> None:
        if server not in self.registered:
            extra = ("--url", url) if url else ()
            self.mint.run("server", "register", support.sid(server), *extra)
            self.registered.add(server)

    def relate(self, subject: Subject, server: str) -> str:
        """주체가 속한 조직에 다른 서버의 이용 관계를 더한다."""
        self.register(server)
        reply = self.mint.data(
            "relation",
            "add",
            "--org",
            subject.org,
            "--server",
            support.sid(server),
            "--purpose",
            "it",
        )
        return reply["id"]

    def prepare(
        self, subject: Subject, server: str = "a", org: str | None = None, url: str | None = None
    ) -> str:
        """조직 생성·바인딩·서버 등록·이용 관계까지 만들고 관계 식별자를 돌려준다."""
        org = org or "org-" + uuid.uuid4().hex[:8]
        self.register(server, url)
        self.mint.run("org", "add", org, "--name", org)
        target = ("--team", subject.team_id) if subject.team_id else ("--user", subject.user_id)
        self.mint.run("org", "bind", "--org", org, *target)
        subject.org = org
        reply = self.mint.data(
            "relation",
            "add",
            "--org",
            org,
            "--server",
            support.sid(server),
            "--purpose",
            "it",
        )
        return reply["id"]

    def approve(
        self,
        subject: Subject,
        relation: str,
        *,
        tools: str = "echo,slow,mutable",
        valid: timedelta = timedelta(days=1),
        valid_from: timedelta | None = None,
        scope: str | None = None,
        extra: tuple[str, ...] = (),
    ) -> str:
        scope = scope or ("team" if subject.team_id else "key")
        scope_id = {"key": subject.key_id, "team": subject.team_id, "user": subject.user_id}[scope]
        args = [
            "approve",
            "--relation",
            relation,
            "--scope",
            scope,
            "--scope-id",
            scope_id,
            "--tools",
            tools,
            "--valid-until",
            iso(valid),
            "--basis",
            "integration-evidence",
            "--requested-by",
            subject.user_id,
            *extra,
        ]
        if valid_from is not None:
            args += ["--valid-from", iso(valid_from)]
        reply = self.mint.data(*args)
        subject.approvals.append(reply["id"])
        return reply["id"]

    def call_approval(
        self, subject: Subject, arguments: dict, server: str = "a", tool: str = "echo"
    ) -> str:
        """호출별 승인을 요청하고(요청자는 호출 주체) 운영자 관리자가 승인한다."""
        request = self.mint.data(
            "call-approval",
            "request",
            "--org",
            subject.org,
            "--principal-type",
            "user",
            "--principal-id",
            subject.user_id,
            "--server",
            support.sid(server),
            "--tool",
            tool,
            "--args-fp",
            fingerprint(arguments),
            "--requested-by",
            subject.user_id,
        )
        self.mint.run("call-approval", "approve", request["id"])
        return request["id"]

    def call(
        self,
        subject: Subject,
        server: str = "a",
        tool: str = "echo",
        *,
        port: int | None = None,
        mark: str | None = None,
        arguments: dict | None = None,
        key: str | None = None,
    ) -> Outcome:
        """REST 경로로 호출한다. 호출 식별자 헤더를 시험 표식과 같게 둬 사건과 대조한다."""
        mark = mark or support.marker()
        reply = support.rest_call(
            key or subject.key,
            server,
            tool,
            arguments if arguments is not None else {"text": "x", "marker": mark},
            port=port or support.LITELLM_PORTS[0],
            call_id=mark,
        )
        code, reference = _error(reply)
        return Outcome(reply.status_code, code, mark, reply.text, reference)

    def call_concurrently(self, subject: Subject, count: int, **kwargs) -> list[Outcome]:
        """같은 호출을 ``count``건 한꺼번에 보낸다(호출마다 새 연결, 표식은 호출마다 다르다).

        한 복제본의 워커가 여럿일 때 호출이 워커 모두에 닿게 하려는 용도이다.
        """
        gate = threading.Barrier(count)

        def one(_):
            gate.wait(timeout=30)
            return self.call(subject, **kwargs)

        with concurrent.futures.ThreadPoolExecutor(count) as pool:
            return list(pool.map(one, range(count)))

    def events(self, mark: str, kind: str = "decision_evaluated", wait: float = 5.0) -> list[dict]:
        """호출 식별자가 ``mark``인 사건. 하나 이상 보일 때까지 ``wait``초 기다린다."""
        sql = (
            "select kind, payload, source_key, invocation_id, attempt_id from mint.events "
            "where kind = %s and payload->>'litellm_call_id' = %s order by inserted_at"
        )
        deadline = time.monotonic() + wait
        while True:
            rows = self.query(sql, (kind, mark))
            if rows or time.monotonic() > deadline:
                return rows
            time.sleep(0.25)

    def decisions_since(self, subject: Subject, since) -> list[dict]:
        """주체의 키로 ``since`` 이후 남은 판정 사건(호출 식별자를 지정할 수 없는 경로용)."""
        return self.query(
            "select payload from mint.events where kind = 'decision_evaluated' "
            "and payload->'principal'->>'key_id' = %s and inserted_at >= %s order by inserted_at",
            (subject.key_id, since),
        )

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        with psycopg.connect(support.mint_database_url(), row_factory=dict_row) as conn:
            return conn.execute(sql, params).fetchall()

    def now(self):
        return self.query("select clock_timestamp() as t")[0]["t"]

    def count_since(self, since, kind: str) -> int:
        rows = self.query(
            "select count(*) as n from mint.events where kind = %s and inserted_at >= %s",
            (kind, since),
        )
        return rows[0]["n"]

    def rows_for(self, source_key_prefix: str) -> int:
        rows = self.query(
            "select count(*) as n from mint.events where source_key like %s",
            (source_key_prefix + "%",),
        )
        return rows[0]["n"]


@contextlib.contextmanager
def slow_decision_insert(prefix: str, seconds: float):
    """호출 식별자가 ``prefix``로 시작하는 판정 사건의 첫 시도 커밋을 ``seconds``초 지연시킨다.

    커밋 요청이 서버에 닿은 뒤에는 클라이언트가 끊겨도 커밋이 끝까지 진행되므로, 그 사이 응답을
    막으면 호출 쪽은 커밋 결과를 알 수 없다.
    """
    function = (
        "create function mint.it_slow_insert() returns trigger language plpgsql as $$ begin "
        "if new.kind = 'decision_evaluated' and new.attempt_id = 1 "
        f"and new.payload->>'litellm_call_id' like '{prefix}%' then perform pg_sleep({seconds}); "
        "end if; return new; end $$"
    )
    with psycopg.connect(support.mint_database_url(), autocommit=True) as conn:
        conn.execute(function)
        conn.execute(
            "create constraint trigger it_slow_insert after insert on mint.events "
            "deferrable initially deferred for each row execute function mint.it_slow_insert()"
        )
    try:
        yield
    finally:
        with psycopg.connect(support.mint_database_url(), autocommit=True) as conn:
            conn.execute("drop trigger if exists it_slow_insert on mint.events")
            conn.execute("drop function if exists mint.it_slow_insert()")


def db_server(alias: str, url: str, server_id: str | None = None) -> str:
    """관리 API로 서버를 등록한다(DB 서버). ``server_id``를 주면 같은 식별자로 다시 만든다."""
    body = {
        "alias": alias,
        "server_name": alias,
        "url": url,
        "transport": "http",
        "allow_all_keys": False,
        **({"server_id": server_id} if server_id else {}),
    }
    created = httpx.post(
        support.url(support.LITELLM_PORTS[0], "/v1/mcp/server"),
        headers=support.master_headers(),
        json=body,
        timeout=30,
    )
    created.raise_for_status()
    return created.json()["server_id"]


def delete_db_server(server_id: str) -> None:
    httpx.delete(
        support.url(support.LITELLM_PORTS[0], f"/v1/mcp/server/{server_id}"),
        headers=support.master_headers(),
        timeout=30,
    )


def insert_is_sleeping() -> bool:
    """지연 트리거 안에서 판정 사건 커밋이 대기 중인지."""
    with psycopg.connect(support.mint_database_url()) as conn:
        row = conn.execute(
            "select count(*) from pg_stat_activity where wait_event = 'PgSleep' "
            "and datname = 'mint'"
        ).fetchone()
    return row[0] > 0


@contextlib.contextmanager
def litellm_config(path: str, *, verified: bool = True, env: dict | None = None):
    """두 복제본을 다른 설정 파일로 다시 띄웠다가 기본 설정으로 되돌린다.

    ``verified``가 참이면 두 복제본이 집행 점검을 통과해 사건을 남길 때까지 기다린다.
    """
    with psycopg.connect(support.mint_database_url()) as conn:
        since = conn.execute("select clock_timestamp()").fetchone()[0]
    done = support.compose(
        "up",
        "-d",
        "--wait",
        "--force-recreate",
        "litellm1",
        "litellm2",
        env={"MINT_E_LITELLM_CONFIG": path, **(env or {})},
        check=False,
    )
    try:
        if verified and done.returncode == 0:
            _wait_verified(since)
        yield done
    finally:
        with psycopg.connect(support.mint_database_url()) as conn:
            since = conn.execute("select clock_timestamp()").fetchone()[0]
        support.compose("up", "-d", "--wait", "--force-recreate", "litellm1", "litellm2")
        _wait_verified(since)


def _wait_verified(since, count: int = 2) -> None:
    def ready() -> bool:
        with psycopg.connect(support.mint_database_url()) as conn:
            row = conn.execute(
                "select count(distinct payload->>'worker_id') from mint.events "
                "where kind = 'enforcement_verified' and inserted_at >= %s",
                (since,),
            ).fetchone()
        return row[0] >= count

    support.wait_until(ready, 150, 2, what="enforcement_verified of both replicas")


def _error(reply: httpx.Response) -> tuple[str | None, str | None]:
    """(차단 오류 코드, 판정 참조). 허용이면 (None, None)."""
    if reply.status_code == 200:
        return None, None
    try:
        detail = reply.json().get("detail")
        parsed = json.loads(detail) if isinstance(detail, str) else detail
        return parsed.get("code"), parsed.get("reference")
    except (ValueError, KeyError, AttributeError):
        return None, None


def decision(event: dict) -> tuple[str, str, str | None]:
    """(evaluated_decision, enforced_action, 차단 사유 코드) 한 사건에서 읽는다."""
    payload = decoded_decision(event["payload"])
    stop = payload.get("stop") or {}
    findings = payload.get("findings") or [{}]
    reason = stop.get("reason_code") or findings[0].get("reason_code")
    return payload["evaluated_decision"], payload["enforced_action"], reason


def project_root() -> Path:
    return support.HERE.parents[1]

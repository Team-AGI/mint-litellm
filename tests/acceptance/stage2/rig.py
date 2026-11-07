"""장비 실행·범위 한정 사건 계수·증거 저장. 비밀은 환경변수에서만 읽는다."""

import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import psycopg
import pytest
import yaml
from psycopg.rows import dict_row

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def until(days=1):
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def load_expectations():
    return yaml.safe_load((HERE / "expected_events.yaml").read_text(encoding="utf-8"))


class Rig:
    def __init__(self, nodeid, root):
        self.expected = load_expectations()
        self.root = root
        self.site = {}
        self.secrets = []
        self.undo = []
        self.client = None
        self.run_id = uuid.uuid4().hex
        self.result = {
            "test": nodeid,
            "started_at": datetime.now(UTC).isoformat(),
            "status": "running",
            "run_id": self.run_id,
            "steps": [],
            "interpretations": self.expected["interpretations"],
        }
        self.path = root / (re.sub(r"[^a-zA-Z0-9_.-]", "_", nodeid) + ".json")

    def configure(self, site):
        self.site = site
        for name in site["secret_env"].values():
            value = os.environ.get(name)
            assert value, f"환경변수 {name} 없음"
            self.secrets.append(value)
        self.client = httpx.Client(timeout=30, follow_redirects=False)
        self.result["sha"] = self.command(["git", "rev-parse", "HEAD"]).stdout.strip()
        dirty = self.command(["git", "status", "--porcelain"]).stdout
        assert not dirty, "장비 시험은 커밋된 깨끗한 복제본에서 실행"
        if "test_13_" not in self.result["test"]:
            assert site.get("case_setup"), "장비 case_setup 누락: 시험마다 초기 스냅숏 복구 필요"
            self.command(self.replace_placeholders(site["case_setup"],
                         {"{case}": self.result["test"]}), timeout=180)
        assert self.sql("SELECT mode FROM mint.settings WHERE instance_id=%s", [self.iid])[0][
            "mode"
        ] == "enforce"

    @property
    def iid(self):
        return self.site["instance_id"]

    def secret(self, role):
        return os.environ[self.site["secret_env"][role]]

    def clean(self, value):
        text = json.dumps(value, ensure_ascii=False, default=str)
        for secret in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(secret, "<redacted>")
        # 주소와 URL 자격도 결과 파일에 남기지 않는다.
        text = re.sub(r"https?://[^\s\"\\]+", "<endpoint>", text)
        return json.loads(text)

    def save(self):
        self.root.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.clean(self.result), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8", newline="\n",
        )

    def skip(self, reason):
        self.result.update(status="skipped", reason=reason)
        pytest.skip(reason)

    def close(self):
        errors = []
        for action in reversed(self.undo):
            try:
                action()
            except Exception as error:
                errors.append(self.clean(str(error)))
        if self.client:
            self.client.close()
        if errors:
            self.result.update(status="failed", cleanup_errors=errors)
        self.save()
        assert not errors, "복구 실패: 증거의 cleanup_errors 확인"

    def command(self, argv, *, check=True, timeout=60, input=None):
        done = subprocess.run(
            argv, cwd=ROOT, text=True, encoding="utf-8", capture_output=True,
            timeout=timeout, input=input, check=False,
        )
        if check:
            assert done.returncode == 0, self.clean(done.stderr + done.stdout)
        return done

    def cli(self, *args, role="admin", check=True):
        env = {**os.environ, "MINT_OPERATOR_TOKEN": self.secret(role)}
        done = subprocess.run(
            [*self.site.get("cli", [sys.executable, "-m", "mint_litellm.cli"]),
             *map(str, args), "--json"],
            cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=60,
        )
        if check:
            assert done.returncode == 0, self.clean(done.stdout + done.stderr)
        if not check:
            return done
        return json.loads(done.stdout)

    def require(self, *commands, handlers=()):
        # --help는 DB 연결 전에 종료한다. 실행 실패는 명령 부재와 구분한다.
        from mint_litellm.cli import build_parser
        from mint_litellm.control import jobs

        parser = build_parser()
        for command in commands:
            try:
                parser.parse_args([*command.split(), "--help"])
            except SystemExit as error:
                if error.code == 2:
                    self.skip(f"미구현으로 건너뜀: 명령 {command}")
                assert error.code == 0, f"명령 탐지 실패: {command}"
        missing = sorted(set(handlers) - jobs.HANDLERS.keys())
        if missing:
            self.skip("미구현으로 건너뜀: 작업 처리기 " + ", ".join(missing))

    def require_module(self, name):
        try:
            present = importlib.util.find_spec(name)
        except ModuleNotFoundError:
            present = None
        if present is None:
            self.skip("미구현으로 건너뜀: 서비스 " + name)

    def sql(self, query, params=(), *, role="db"):
        with psycopg.connect(self.secret(role), row_factory=dict_row) as conn:
            conn.execute("SET statement_timeout = '10s'")
            return conn.execute(query, params).fetchall() if query.lstrip().upper().startswith(
                ("SELECT", "WITH")
            ) else conn.execute(query, params).rowcount

    def request(self, method, path, body=None, *, role="admin", status=(200, 201), base="api"):
        response = self.client.request(
            method, self.site[base].rstrip("/") + path,
            headers={"Authorization": "Bearer " + self.secret(role)}, json=body,
        )
        assert response.status_code in status, self.clean({
            "path": path, "status": response.status_code, "body": response.text[:1000],
        })
        return response.json() if response.content else {}

    def api(self, method, path, body=None, **kwargs):
        return self.request(method, "/api/v1" + path, body, **kwargs)

    def versioned(self, path, action, body=None, **kwargs):
        current = self.api("GET", path)
        return self.api("POST", path + "/" + action, {
            **(body or {}), "state_version": current["state_version"],
        }, **kwargs)

    def wait(self, predicate, seconds, label):
        deadline = time.monotonic() + seconds
        while True:
            value = predicate()
            if value:
                return value
            assert time.monotonic() < deadline, f"시간 상한 초과: {label} ({seconds}s)"
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))

    def rows(self, table, where="TRUE", params=()):
        assert re.fullmatch(r"[a-z_]+", table)
        return self.sql(
            f"SELECT * FROM mint.{table} WHERE instance_id=%s AND ({where})", [self.iid, *params]
        )

    def begin(self, flow, *, entities=(), server=None):
        return {
            "flow": flow, "entities": list(entities), "server": server,
            "since": self.sql("SELECT clock_timestamp() AS t")[0]["t"],
            "started": time.monotonic(),
        }

    def events(self, window):
        rows = self.sql(
            "SELECT kind, source_key, invocation_id, payload, subject FROM mint.events "
            "WHERE instance_id=%s AND inserted_at >= %s ORDER BY inserted_at,event_id",
            [self.iid, window["since"]],
        )
        ids = set(map(str, window["entities"]))
        server = window["server"]
        return [row for row in rows if row["source_key"].split(":")[1] in ids or (
            server and (
                row["payload"].get("server_id") == server
                or row["payload"].get("resolved_server_id") == server
                or (row["subject"] or {}).get("server_id") == server
                or row["payload"].get("server", {}).get("server_id") == server
            )
        )]

    def check_events(self, window, **variables):
        rule = self.expected["flows"][window["flow"]]
        wanted = {kind: variables[n] if isinstance(n, str) else n
                  for kind, n in rule.items()}
        # 같은 엔터티의 source_key 중복과 양의 사건 추가 발생도 검출한다.
        time.sleep(self.site.get("settle_seconds", 2))
        rows = self.events(window)
        actual = Counter(row["kind"] for row in rows)
        selected = {kind: actual[kind] for kind in wanted}
        self.result["steps"].append({
            "flow": window["flow"], "expected_events": wanted, "actual_events": dict(actual),
            "events": rows, "elapsed_ms": (time.monotonic() - window["started"]) * 1000,
        })
        assert selected == wanted, (selected, wanted)
        auxiliary = set(self.expected.get("auxiliary_events", {}).get(window["flow"], []))
        unexpected = set(actual) - wanted.keys() - auxiliary
        assert not unexpected, f"흐름에 정의되지 않은 사건: {sorted(unexpected)}"
        assert len({row["source_key"] for row in rows}) == len(rows)

    def call(self, server, tool, arguments=None, *, role="caller", base=None, allowed=True,
             code=None, cause=None, litellm_rejects=False):
        mark = "acc-" + uuid.uuid4().hex
        url = base or self.site["litellm"][0]
        before = self.counter(server)
        started = time.monotonic()
        response = self.client.post(
            url.rstrip("/") + "/mcp-rest/tools/call",
            headers={"Authorization": "Bearer " + self.secret(role), "x-litellm-call-id": mark},
            json={"server_id": server, "name": tool, "arguments": arguments or {}},
        )
        elapsed = (time.monotonic() - started) * 1000
        time.sleep(self.site.get("settle_seconds", 2))
        delta = self.counter(server) - before
        decisions = self.sql(
            "SELECT kind, source_key, invocation_id, payload FROM mint.events WHERE instance_id=%s "
            "AND payload->>'litellm_call_id'=%s", [self.iid, mark],
        )
        decisions = [row for row in decisions if row["kind"] == "decision_evaluated"]
        events = []
        if decisions:
            events = self.sql(
                "SELECT kind, source_key, payload FROM mint.events WHERE instance_id=%s "
                "AND invocation_id=%s", [self.iid, decisions[0]["invocation_id"]],
            )
        snapshot = decisions[0]["payload"] if decisions else {}
        self.result["steps"].append({
            "call": mark, "status": response.status_code, "upstream_calls": delta,
            "elapsed_ms": elapsed, "events": events, "expected_code": code,
        })
        assert elapsed <= self.expected["limits"]["call_ms"]
        assert delta == (1 if allowed else 0), (delta, allowed)
        if litellm_rejects and not decisions and response.status_code in (400, 403, 404, 500):
            # DS-173: 승인 전 서버는 LiteLLM의 사전 거절(업스트림 0)도 합격이다.
            self.result["steps"][-1]["litellm_rejected"] = True
            return {}
        assert len(decisions) == self.expected["flows"]["call"]["decision_evaluated"]
        rule = self.expected["flows"]["allowed_call" if allowed else "blocked_call"]
        counts = Counter(row["kind"] for row in events)
        assert all(counts[kind] == count for kind, count in rule.items()), (counts, rule)
        if allowed:
            assert response.status_code == 200
            assert not response.json().get("isError", False), self.clean(response.json())
        else:
            assert response.status_code in (400, 403, 409, 503)
            assert code in response.text, self.clean(response.text)
        if cause:
            assert cause in json.dumps(snapshot), self.clean(snapshot)
        return snapshot

    def counter(self, server, method="tools/call"):
        # 계수기는 제품과 별도인 기존 계수 역프록시의 JSON 계수 면이다.
        response = self.client.get(self.site["counters"][server], timeout=5)
        response.raise_for_status()
        value = response.json()
        return value[method]

    def fixture(self, server_name="context7"):
        self.require("intake create", "intake approve", handlers=(
            "intake_run", "sync_target", "activation_finalize",
        ))
        entry = self.site["servers"][server_name]
        server = entry["server_id"]
        intake_id = self.create_intake(server)
        self.wait(
            lambda: self.intake(intake_id)["status"] in ("passed", "failed", "indeterminate"),
            120, "검사 8종",
        )
        intake = self.intake(intake_id)
        assert intake["status"] == "passed", self.clean(intake)
        return {**entry, "intake_id": intake_id, "name": server_name}

    def create_intake(self, server):
        """운영자 경로 신청(CLI). 신청자는 admin 토큰의 사용자이다."""
        s = self.site["intake"]
        r = s["readiness"]

        def text(value):
            return "예" if value is True else str(value)

        # 제어 평면 키에는 서버 URL이 응답되지 않으므로 계약 값에 쓸 URL을 함께 지정한다.
        url = next((e["url"] for e in self.site["servers"].values()
                    if e["server_id"] == server and e.get("url")), None)
        return self.cli(
            "intake", "create", server, *(["--url", url] if url else []), "--org", s["org_id"],
            "--purpose", s["purpose"],
            "--data-grade", s["data_grade"],
            "--allowed-resources", json.dumps(s["allowed_resources"]),
            "--provider", s["provider"], "--owner", s["owner_user_id"],
            "--credential-notice", text(r["credential_notice"]),
            "--revocation-record", text(r["revocation_record"]),
            "--audit-access-days", r["audit_access_days"],
            "--data-return-terms", s["data_return_terms"],
        )["id"]

    def intake(self, intake_id):
        return self.cli("intake", "show", intake_id)["intake"]

    def approval_scope(self):
        """승인 범위: site.approval_scope({type: key|team, id, team?}), 없으면 호출 키의 키 범위."""
        scope = self.site.get("approval_scope")
        if scope:
            return scope
        return {"type": "key",
                "id": hashlib.sha256(self.secret("caller").encode()).hexdigest()}

    def activate(self, fixture):
        intake_id = fixture["intake_id"]
        scope = self.approval_scope()
        extra = ["--team", scope["team"]] if scope.get("team") else []
        self.cli("intake", "approve", intake_id, "--reason", "acceptance",
                 "--scope", scope["type"], "--scope-id", scope["id"], *extra, role="approver")
        server = fixture["server_id"]
        self.wait(lambda: self.rows("approvals", "server_id=%s AND status='active'", [server]),
                  120, "활성화")
        contracts = self.rows("tool_contracts", "server_id=%s AND status='approved'", [server])
        assert contracts and len(contracts) == fixture["tool_count"]
        grants = self.rows("litellm_grants", "server_id=%s AND item='pin'", [server])
        assert grants and all(row["observed"] is True for row in grants)
        return contracts

    def reapprove(self, server):
        """재승인 CLI. 후보 계약(도구·배포)이 생길 때까지 기다린 뒤 승인된 신청의 증거로 부른다."""
        def candidates():
            tools = self.rows("tool_contracts", "server_id=%s AND status='candidate'", [server])
            deployments = self.rows("deployment_contracts",
                                    "server_id=%s AND status='candidate'", [server])
            return (tools, deployments) if tools or deployments else None

        tools, deployments = self.wait(candidates, 120, "재승인 후보 계약")
        intake = self.rows("intakes", "server_id=%s AND decision='approved' "
                           "ORDER BY decided_at DESC LIMIT 1", [server])[0]
        args = ["contract", "reapprove", server, "--intake", str(intake["id"])]
        for tool in tools:
            args += ["--tool-contract", str(tool["id"])]
        if deployments:
            args += ["--deployment-contract", str(deployments[0]["id"])]
        return self.cli(*args, role="approver")

    def active(self, name="context7"):
        entry = self.site["servers"][name]
        if self.rows("approvals", "server_id=%s AND status='active'", [entry["server_id"]]):
            return {**entry, "name": name}
        fixture = self.fixture(name)
        self.activate(fixture)
        return fixture

    def fault(self, name, *, restore=True):
        # argv 배열만 받는다. site의 장비별 compose 경로·서비스 이름을 코드와 분리한다.
        assert name in self.site.get("faults", {}), (
            f"장비 픽스처 설정 누락: faults.{name}; 제품 미구현 건너뜀 대상이 아님"
        )
        command = self.site["faults"][name]
        observation = self.root / (self.run_id + "-" + name + ".observation.json")
        replacements = {"{observation}": str(observation), "{run_id}": self.run_id}
        argv = self.replace_placeholders(command["apply"], replacements)
        done = self.command(argv, check=False, timeout=command.get("timeout", 120))
        if done.returncode == 78:  # 어댑터 규약: 제품 명령·처리기 부재
            self.skip(done.stdout.strip() or f"미구현으로 건너뜀: 어댑터 {name}")
        assert done.returncode == 0, self.clean(done.stderr + done.stdout)
        self.result["steps"].append({"fixture": name, "exit_code": 0})
        if restore:
            self.undo.append(lambda: self.command(command["undo"], timeout=120))

    @staticmethod
    def replace_placeholders(argv, replacements):
        result = []
        for arg in argv:
            if arg in replacements:
                result.append(replacements[arg])
            else:
                for key, value in replacements.items():
                    arg = arg.replace(key, shlex.quote(value))
                result.append(arg)
        return result

    def restore_fault(self, name):
        self.command(self.site["faults"][name]["undo"], timeout=120)

    def artifact(self, name):
        return Path(self.site["artifacts"][name])

    def note(self, **values):
        self.result["steps"].append(self.clean(values))

    def read_observation(self, name):
        path = self.root / (self.run_id + "-" + name + ".observation.json")
        if name.startswith("client_"):
            path = self.artifact(name)
        assert path.is_file(), f"실측 산출물 없음: {name}"
        result = json.loads(path.read_text(encoding="utf-8"))
        assert result["sha"] == self.result["sha"], "다른 SHA의 실측 산출물"
        if not name.startswith("client_"):
            assert result["run_id"] == self.run_id, "이전 실행 산출물 재사용"
        self.note(observation=name, payload=result,
                  sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        return result

    def check_observation(self, name, observed):
        expected = self.expected["observations"][name]
        for dotted, rule in expected.items():
            value = observed
            for key in dotted.split("."):
                value = value[key]
            if isinstance(rule, dict):
                if "max" in rule:
                    assert value <= rule["max"], (name, dotted, value, rule)
                if "min" in rule:
                    assert value >= rule["min"], (name, dotted, value, rule)
            else:
                assert value == rule, (name, dotted, value, rule)

    def verify_artifact(self, record):
        path = Path(record["path"])
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]

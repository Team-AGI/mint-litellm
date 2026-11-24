"""저장소 주소(또는 패키지 하나)로 로컬 MCP를 신청한다. 패키지 형태는 ``package_refs``.

주소에서 기본 브랜치의 최신 커밋(40자)을 찾아 고정하고, 그 커밋의 ``pyproject.toml``·
``package.json``으로 실행 명령을 만든다. 신청은 단말에서 ``mint add``로 올리는 로컬 신청과 같은
출처(endpoint)로 생겨, 검사·묶음·승인·PC 반영이 그대로 이어진다. 네트워크는 ``fetch``로 바꾼다.
"""

import json
import re
import shlex
import tomllib
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from uuid import UUID

import psycopg

from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError, conflict
from mint_litellm.control.services import package_refs, staff, staff_intakes
from mint_litellm.types.canonical import canonical_text
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7

COMMIT = re.compile(r"[0-9a-f]{40}")
NPM_PREFIX = {"github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket"}
API_HOSTS = ("api.github.com", "raw.githubusercontent.com", "pypi.org", "registry.npmjs.org")
MANUAL = "커밋과 실행 명령을 직접 입력하십시오."


def _fetch(url: str) -> bytes | None:
    """공개 주소를 읽는다. 없으면(404) None. 허용한 두 호스트 밖은 읽지 않는다."""
    if urlsplit(url).hostname not in API_HOSTS:
        raise ValueError("host")
    request = urllib.request.Request(
        url, headers={"User-Agent": "mint-litellm", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=6) as response:  # noqa: S310
            return response.read(1_000_000)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def is_local(text: str) -> bool:
    """저장소 주소이거나 패키지 형태면 로컬 MCP 신청이다."""
    return bool(staff_intakes.repo_parts(text.strip()) or package_refs.package_ref(text))


def _branch(url: str) -> str | None:
    segs = [s for s in urlsplit(url).path.split("/") if s]
    return segs[3] if len(segs) == 4 and segs[2] == "tree" else None


def repo_url(url: str) -> str:
    owner, repo = staff_intakes.repo_parts(url) or (None, None)
    if not owner:
        raise ControlError("소스 저장소 주소(예: https://github.com/조직/저장소)를 입력하십시오.")
    return f"https://{urlsplit(url).hostname.lower()}/{owner}/{repo}"


def _commands(owner: str, repo: str, sha: str, files: dict) -> tuple[str, str]:
    """(실행 명령, 안내). 명령을 못 만들면 빈 문자열."""
    base = f"https://github.com/{owner}/{repo}"
    if files.get("pyproject.toml") is not None:
        try:
            doc = tomllib.loads(files["pyproject.toml"].decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeError):
            doc = {}
        scripts = doc.get("project", {}).get("scripts") or doc.get("tool", {}).get(
            "poetry", {}).get("scripts") or {}
        if isinstance(scripts, dict) and scripts:
            return f"uvx --from git+{base}@{sha} {next(iter(scripts))}", ""
    if files.get("package.json") is not None:
        try:
            bins = json.loads(files["package.json"]).get("bin")
        except (ValueError, UnicodeError, AttributeError):
            bins = None
        if bins:
            return (f"npx -y github:{owner}/{repo}#{sha}",
                    "Node.js 패키지입니다. 묶음 없이 접수되며 관리자가 확인합니다.")
    return "", "실행 명령을 찾지 못했습니다. 실행 명령을 직접 입력하십시오."


def resolve(url: str, fetch=None) -> dict:
    """주소의 저장소·커밋·실행 명령을 알아낸다. 실패는 ``note``에 사유를 담는다."""
    fetch = fetch or _fetch
    ref = package_refs.package_ref(url)
    if ref:
        found = package_refs.resolve(ref, fetch)
        if found is None:
            raise ControlError("패키지를 찾지 못했습니다. 이름과 판본을 확인하십시오.")
        return found
    clean = repo_url(url)
    owner, repo = staff_intakes.repo_parts(clean)
    out = {"repo": clean, "name": staff_intakes.server_name(clean), "commit": "", "command": "",
           "note": ""}
    if urlsplit(clean).hostname != "github.com":
        out["note"] = "자동 확인은 GitHub 저장소만 지원합니다. " + MANUAL
        return out
    try:
        meta = fetch(f"https://api.github.com/repos/{owner}/{repo}")
        if meta is None:
            out["note"] = "공개 저장소를 찾지 못했습니다. " + MANUAL
            return out
        branch = _branch(url) or json.loads(meta)["default_branch"]
        head = fetch(f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}")
        sha = json.loads(head)["sha"] if head else ""
        if not COMMIT.fullmatch(sha):
            out["note"] = "커밋을 찾지 못했습니다. " + MANUAL
            return out
        out["commit"] = sha
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/"
        out["command"], out["note"] = _commands(owner, repo, sha, {
            n: fetch(raw + n) for n in ("pyproject.toml", "package.json")})
    except urllib.error.HTTPError as error:
        limited = error.code in (403, 429)
        why = "GitHub 호출 한도에 걸렸습니다" if limited else "GitHub가 응답하지 않습니다"
        out["note"] = f"{why}. " + MANUAL
    except (OSError, ValueError, KeyError, TypeError):
        out["note"] = "GitHub에 연결하지 못했습니다. " + MANUAL
    return out


def _spec(url: str, commit: str, command: str) -> dict:
    """실행 명령을 신청 명세로 바꾼다. 이 저장소의 이 커밋을 가리키는 두 형태만 받는다."""
    base = repo_url(url)
    owner, repo = staff_intakes.repo_parts(base)
    host = urlsplit(base).hostname
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = []
    spec = {"git": base, "name": repo, "version": commit, "extras": []}
    if tokens[:1] == ["uvx"] and len(tokens) >= 4 and tokens[1] == "--from" and tokens[2] in (
            f"git+{base}@{commit}", f"git+{base}.git@{commit}"):
        return {**spec, "index": "git", "command": tokens[3], "argv": tokens[4:]}
    prefix = NPM_PREFIX.get(host)
    if tokens[:1] == ["npx"] and prefix:
        rest = tokens[2:] if tokens[1:2] == ["-y"] else tokens[1:]
        if rest[:1] == [f"{prefix}:{owner}/{repo}#{commit}"]:
            return {**spec, "index": "npm", "command": repo, "argv": rest[1:]}
    example = f"uvx --from git+{base}@{commit} 실행이름"
    raise ControlError(f"실행 명령은 이 커밋을 가리키는 `{example}` 형태여야 합니다.")


def build_payload(form: dict) -> dict:
    url, purpose = str(form.get("url", "")).strip(), str(form.get("purpose", "")).strip()
    commit, command = str(form.get("commit", "")).strip().lower(), str(
        form.get("command", "")).strip()
    name = (str(form.get("name", "")).strip() or staff_intakes.server_name(url)).replace("-", "_")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_]{0,127}", name):
        raise ControlError("이름은 영문·숫자·밑줄만 사용하며 영문·숫자로 시작해야 합니다.")
    if not command:
        raise ControlError("실행 명령을 입력하십시오.")
    spec = None
    if command.startswith("uvx") and "git+" not in command and not staff_intakes.repo_parts(url):
        spec = package_refs.pypi_spec(command, str(form.get("commit", "")).strip())
        if spec is None:
            raise ControlError("실행 명령은 `uvx 패키지==판본` 형태이고 판본이 같아야 합니다.")
    elif not COMMIT.fullmatch(commit):
        raise ControlError("커밋은 40자리 소문자 16진수여야 합니다.")
    if not 1 <= len(purpose) <= 256:
        raise ControlError("도입 목적을 256자 이하로 입력하십시오.")
    return {"server_id": name, "spec": spec or _spec(url, commit, command), "purpose": purpose,
            "data_grade": staff_intakes.DEFAULTS["data_grade"], "resources": [],
            "file_access": [], "allowed_hosts": [], "env_names": []}


def submit_staff(sctx: staff.StaffContext, session_id_hash: str, request_id: str,
                 form: dict) -> str:
    try:
        identifier = UUID(request_id)
    except (ValueError, TypeError):
        raise ControlError("신청 화면을 다시 열어 제출하십시오.") from None
    payload = build_payload(form)
    staff._active_session(sctx, session_id_hash)
    try:
        with staff._staff_transaction(sctx, session_id_hash) as conn:
            row = conn.execute("SELECT mint.staff_submit_local_intake(%s,%s::jsonb)",
                               (identifier, json.dumps(payload))).fetchone()
            return str(row[0])
    except psycopg.errors.UniqueViolation:
        raise conflict("같은 서버의 신청이 이미 진행 중이거나 등록되어 있습니다. "
                       "관리자에게 확인하십시오.") from None
    except psycopg.errors.CheckViolation as error:
        if "MINT-QUOTA" in str(error):
            raise ControlError("진행 중인 신청이 3건입니다. 검사가 끝난 뒤 신청하십시오.") from None
        raise ControlError("신청 내용을 확인하십시오.") from None


def submit_operator(ctx, user: str, form: dict, owner: str | None = None) -> tuple[str, bool]:
    """관리자 화면의 신청. 같은 서버가 진행 중이면 그 신청을 돌려준다(두 번째 값 True).

    ``owner``(담당 사용자)가 있으면 신청자로 그 사람을 적는다. 확인은 부르는 쪽이 한다.
    """
    user = owner or user
    from mint_litellm.control.services import intakes
    from mint_litellm.control.services.base import transact

    payload = build_payload(form)
    sid, spec = payload["server_id"], payload["spec"]
    pack = {**spec, "file_access": [], "network": None, "allowed_hosts": [], "env_names": [],
            "env": {}, "observed_tools": []}
    text = canonical_text(pack)
    with transact(ctx):
        conn = ctx.conn
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                     (f"{ctx.instance_id}:endpoint-server:{sid}",))
        server = fetchone(conn, "SELECT id, status, identity_kind FROM mint.servers"
                          " WHERE instance_id = %s AND server_id = %s FOR UPDATE",
                          (ctx.instance_id, sid))
        if server:
            prior = fetchone(conn, "SELECT id FROM mint.intakes WHERE instance_id = %s"
                             " AND server_id = %s AND status <> 'decided' LIMIT 1",
                             (ctx.instance_id, sid))
            if prior:
                return str(prior["id"]), True
            if server["identity_kind"] != "stdio" or server["status"] not in (
                    "pending", "awaiting_approval", "rejected"):
                raise conflict("같은 이름의 서버가 이미 등록되어 있습니다.")
        org = intakes._derive_org(ctx, None, user)
        if org is None:
            raise ControlError("기본 조직을 설정하도록 담당자에게 요청하세요.")
        if not server:
            conn.execute(
                "INSERT INTO mint.servers (id, instance_id, server_id, status, transport,"
                " auth_type, identity_kind, registered_by)"
                " VALUES (%s, %s, %s, 'pending', 'stdio', 'none', 'stdio', %s)",
                (new_uuid7(), ctx.instance_id, sid, ctx.operator.name))
        identifier = new_uuid7()
        row = fetchone(
            conn,
            "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source, purpose,"
            " data_grade, allowed_resources, provider, owner_user_id, readiness,"
            " data_return_terms, requested_by) VALUES (%s, %s, %s, %s, 'endpoint', %s, %s,"
            " '[]'::jsonb, %s, %s, %s::jsonb, %s, %s) RETURNING *",
            (identifier, ctx.instance_id, org, sid, payload["purpose"], payload["data_grade"],
             spec["index"], user,
             json.dumps({"credential_notice": staff_intakes.DEFAULTS["credential_notice"],
                         "revocation_record": staff_intakes.DEFAULTS["revocation_record"],
                         "audit_access_days": 90}),
             "사용을 끝내면 단말에서 서버를 제거합니다", user))
        conn.execute(
            "INSERT INTO mint.deployment_contracts (id, instance_id, server_id, canonical_text,"
            " sha256, transport, auth_type, proposed_by, identity_kind, pack_spec)"
            " VALUES (%s, %s, %s, %s, encode(sha256(convert_to(%s, 'UTF8')), 'hex'), 'stdio',"
            " 'none', %s, 'stdio', %s::jsonb)",
            (identifier, ctx.instance_id, sid, text, text, ctx.operator.name, json.dumps(pack)))
        ctx.emit(EventKind.INTAKE_RECEIVED, identifier, row["state_version"],
                 {"intake_id": str(identifier), "server_id": sid, "source": "endpoint",
                  "requested_by": user})
        intakes._enqueue_run(ctx, row)
        return str(identifier), False

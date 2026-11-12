#!/usr/bin/env python3
"""MINT 단말 설치 묶음 설치기(표준 라이브러리만, Python 3.9 이상).

관리자 권한(root, Windows는 관리자)으로 돌면 관리형으로 설치한다: 관리형 설정(호출 전·후 훅,
실패 시 차단, 관리형 훅만 허용), 관리자 소유 경로의 에이전트, MINT 승인 목록에서 만든 관리형 MCP
목록(서버는 승인된 실행 계약을 검증하는 실행기를 거쳐 시작된다), 사용자 키 파일. 권한이 없으면
사용자 수준으로 설치하고 MINT에 「관리되지 않음」으로 보고한다. 제거는 설치가 남긴 기록으로 원래
상태를 되돌린다. 설치 상태는 MINT에 보고한다(실패해도 설치는 유지).

대상 도구는 묶음의 ``harnesses``(claude, codex)가 정한다. Codex는 관리형이면 관리자 요구 파일
(``requirements.toml``: 승인 서버 외 차단, 호출 전·후 훅)을, 사용자 수준이면 ``config.toml``의 표식
구간을 쓴다. 서버 표는 승인 서버가 없어도 항상 둔다(표가 없으면 Codex는 서버를 제한하지 않는다).

``--root DIR``은 시험용으로 모든 시스템 경로를 DIR 아래로 옮긴다(파일 내용의 경로는 그대로).
``--dry-run``은 임시 폴더에 설치해 쓰게 될 파일만 보이고 실제 설정은 바꾸지 않는다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path

KIT = Path(__file__).resolve().parent
MANAGED_DIR = "/etc/claude-code"
CODEX_DIR = "/etc/codex"
PROGRAMS = "/usr/local/lib/mint-endpoint"
AGENT = "mint_agent.py"
KEY_REL = ".config/mint/key"
STATE_REL = ".cache/mint"
EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")
REPORT_PATH = "/mint/v1/endpoint/report"
BEGIN = "# >>> mint >>>"
END = "# <<< mint <<<"
NL = chr(10)
REPORT_TIMEOUT = 5


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_atomic(path: Path, data: bytes, mode: int, owner: tuple[int, int] | None = None) -> None:
    """같은 폴더의 임시 파일에 쓰고 바꿔 넣는다. 기존 심볼릭 링크는 따라가지 않는다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".mint-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(name, mode)
        if owner is not None:
            os.chown(name, *owner)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def post(url: str, key: str, payload: dict, ca_file: str | None) -> bool:
    import ssl

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    context = ssl.create_default_context(cafile=ca_file) if url.startswith("https:") else None
    try:
        with urllib.request.urlopen(request, timeout=REPORT_TIMEOUT, context=context) as reply:
            return reply.status == 200
    except OSError:
        return False


def toml(value: object) -> str:
    """TOML 문자열·배열 글자(JSON 문자열이 곧 TOML 기본 문자열이다)."""
    return json.dumps(value, ensure_ascii=False)


def codex_servers(mcp: dict) -> str:
    return "".join(
        f"{NL}[mcp_servers.{toml(name)}]{NL}command = {toml(item['command'])}{NL}"
        f"args = {toml(item['args'])}{NL}"
        for name, item in sorted(mcp.items())
    )


def codex_hooks(commands: dict) -> str:
    return "".join(
        f'{NL}[[hooks.{event}]]{NL}matcher = "^mcp__"{NL}{NL}[[hooks.{event}.hooks]]{NL}'
        f'type = "command"{NL}command = {toml(line)}{NL}timeout = {timeout}{NL}'
        for event, (line, timeout) in commands.items()
    )


def codex_requirements(mcp: dict, hooks: dict, programs: str, windows: bool) -> str:
    """Codex 관리자 요구 파일. 서버 표가 없으면 제한이 없고 비어 있으면 모두 꺼지므로 항상 둔다."""
    # ponytail: 서버 신원이 실행 명령(python)뿐이라 같은 python을 쓰는 다른 서버도 통과한다.
    # 서버마다 실행 래퍼를 두면 좁아진다.
    identities = "".join(
        f"{NL}[mcp_servers.{toml(name)}]{NL}identity = {{ command = {toml(item['command'])} }}{NL}"
        for name, item in sorted(mcp.items())
    )
    key = "windows_managed_dir" if windows else "managed_dir"
    return (
        f"allow_managed_hooks_only = true{NL}{NL}[features]{NL}hooks = true{NL}{NL}"
        f"[mcp_servers]{NL}{identities}{NL}[hooks]{NL}{key} = {toml(programs)}{NL}"
        + codex_hooks(hooks)
    )


def strip_block(text: str) -> str:
    return re.sub(
        rf"(?:\r?\n)?{re.escape(BEGIN)}.*?{re.escape(END)}(?:\r?\n)?", "", text, flags=re.S
    )


def with_block(text: str, body: str) -> str:
    """표식 구간을 파일 끝에 둔다(이미 있으면 바꾼다). 구간 밖은 한 글자도 바꾸지 않는다."""
    rest = strip_block(text)
    gap = "" if not rest else (NL if rest.endswith(NL) else NL + NL)
    return f"{rest}{gap}{BEGIN}{NL}{body.lstrip(NL)}{END}{NL}"


def system_python(path: str) -> bool:
    """Windows에서 일반 사용자가 쓸 수 없는 위치(Program Files·Windows)의 Python인가."""
    real = os.path.normcase(os.path.realpath(path))
    folders = (os.environ.get(v) for v in ("ProgramFiles", "ProgramFiles(x86)", "SystemRoot"))
    return any(
        f and real.startswith(os.path.normcase(os.path.realpath(f)) + os.sep) for f in folders
    )


def is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def keep_private(path: Path, account: str) -> None:
    """Windows는 chmod가 접근 권한이 아니므로 키 파일을 계정·관리자·시스템에만 연다."""
    if sys.platform == "win32":
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{account}:F",
             "*S-1-5-18:F", "*S-1-5-32-544:F"],
            capture_output=True,
        )  # fmt: skip


@dataclass(frozen=True)
class Account:
    """키와 사용자 수준 설정이 놓이는 계정. 관리자 권한으로 돌 때는 설치를 부른 사람이다."""

    name: str
    home: Path
    uid: int
    gid: int


class Kit:
    def __init__(
        self,
        folder: Path,
        root: Path | None,
        managed: bool,
        account: Account,
        chown: bool,
        *,
        windows: bool | None = None,
        strict: bool | None = None,
        dry_run: bool = False,
    ) -> None:
        self.config = json.loads((folder / "kit.json").read_text(encoding="utf-8"))
        self.folder, self.root, self.managed, self.account = folder, root, managed, account
        self.windows = sys.platform == "win32" if windows is None else windows
        self.strict = chown if strict is None else strict  # 실제 시스템에 설치할 때의 점검
        self.dry_run = dry_run
        self.home = account.home
        self.harnesses = self.config.get("harnesses") or ["claude"]  # 옛 묶음은 Claude Code만
        if self.windows:
            files = os.environ.get("ProgramFiles", "C:/Program Files").replace("\\", "/")
            data = os.environ.get("ProgramData", "C:/ProgramData").replace("\\", "/")
            managed_programs = f"{files}/MintEndpoint"
            self.claude_dir, self.codex_dir = f"{files}/ClaudeCode", f"{data}/OpenAI/Codex"
            user_programs = str(self.home / "AppData/Local/MintEndpoint").replace("\\", "/")
        else:
            managed_programs, self.claude_dir, self.codex_dir = PROGRAMS, MANAGED_DIR, CODEX_DIR
            user_programs = str(self.home / ".local/lib/mint-endpoint")
        self.system_paths = (managed_programs, self.claude_dir, self.codex_dir)
        self.logical_programs = managed_programs if self.managed else user_programs
        self.programs = self.physical(self.logical_programs)
        self.managed_dir = self.physical(self.claude_dir)
        self.codex_managed_dir = self.physical(self.codex_dir)
        self.owner = (account.uid, account.gid) if chown else None

    def physical(self, logical: str) -> Path:
        """기록한 경로의 디스크 위치(``--root``가 있으면 시스템 경로만 그 아래로 간다)."""
        if self.root is not None and logical.startswith(self.system_paths):
            return self.root / logical.replace(":", "").lstrip("/")
        return Path(logical)

    def claude(self) -> str | None:
        return None if self.dry_run else find_claude(self.home)

    def shell_line(self, parts: list[str]) -> str:
        """하네스가 셸로 실행하는 한 줄. Codex는 Windows에서 PowerShell로 실행한다."""
        if self.windows:
            return "& " + " ".join("'" + part.replace("'", "''") + "'" for part in parts)
        return shlex.join(parts)

    @property
    def state_file(self) -> Path:
        return self.programs / "state.json"

    def load_state(self) -> dict:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    # -- 설치 -------------------------------------------------------------------------------------

    def write_tracked(self, state: dict, path: Path, logical: str, data: bytes, mode: int) -> None:
        """관리 대상 파일을 쓰되, 우리가 쓴 것이 아닌 기존 파일은 한 번만 백업해 둔다."""
        known = state["files"].get(logical)
        if path.exists() and (known is None or sha256_file(path) != known):
            name = logical.lstrip("/").replace(":", "").replace("/", "__")  # 드라이브 글자 포함
            backup = self.programs / "backup" / name
            if not backup.exists():
                write_atomic(backup, path.read_bytes(), 0o600)
                state["backups"][logical] = str(backup)
        write_atomic(path, data, mode)
        state["files"][logical] = sha256_bytes(data)

    def hook_common(self, contracts: str) -> list[str]:
        common = [
            "--url", self.config["decide_url"],
            "--key-file", f"~/{KEY_REL}",
            "--contracts", contracts,
            "--state-dir", f"~/{STATE_REL}",
        ]  # fmt: skip
        if self.config.get("ca_pem"):
            common += ["--ca-file", f"{self.logical_programs}/ca.pem"]
        return common

    def hook_commands(self, python: str, agent: str, contracts: str) -> dict:
        common = self.hook_common(contracts)
        before = {
            "type": "command", "command": python, "args": [agent, "pre", *common],
            "timeout": 3, "onFailure": "block",
        }  # fmt: skip
        after = {
            "type": "command", "command": python, "args": [agent, "post", *common], "timeout": 5,
        }  # fmt: skip
        failed = {**after, "args": [agent, "post-failure", *common]}
        hooks = {"PreToolUse": before, "PostToolUse": after, "PostToolUseFailure": failed}
        return {event: [{"matcher": "mcp__.*", "hooks": [hook]}] for event, hook in hooks.items()}

    def codex_hook_commands(self, python: str, agent: str, contracts: str) -> dict:
        """Codex에는 실패 호출 훅이 없다. 보고되지 않은 호출은 MINT가 결과 미확인으로 남긴다."""
        common = self.hook_common(contracts)
        return {
            "PreToolUse": (self.shell_line([python, agent, "pre", *common]), 3),
            "PostToolUse": (self.shell_line([python, agent, "post", *common]), 5),
        }

    def check_python(self, python: str) -> None:
        if not (self.managed and self.strict):
            return
        if self.windows:
            if not system_python(python):
                raise SystemExit("관리형 설치에는 모든 사용자용으로 설치한 Python이 필요합니다.")
            return
        info = os.stat(os.path.realpath(python))
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit("python3 is not root-owned; refusing a managed install")

    def install(self) -> dict:
        previous = self.load_state()
        state = {
            "kit_version": self.config["kit_version"],
            "mode": "managed" if self.managed else "user",
            "user": self.account.name,
            "files": dict(previous.get("files", {})),
            "backups": dict(previous.get("backups", {})),
            "mcp_servers": [],
        }
        for kept in ("settings_backup", "codex_config_backup"):
            if kept in previous:
                state[kept] = previous[kept]
        agent = f"{self.logical_programs}/{AGENT}"
        contracts = f"{self.logical_programs}/contracts.json"
        self.write_tracked(
            state, self.programs / AGENT, agent, (self.folder / AGENT).read_bytes(), 0o755
        )
        servers = self.config["servers"]
        self.write_tracked(
            state, self.programs / "contracts.json", contracts,
            json.dumps({"servers": servers}, indent=1).encode(), 0o644,
        )  # fmt: skip
        python = (
            sys.executable.replace("\\", "/")
            if self.windows
            else shutil.which("python3") or sys.executable
        )
        self.check_python(python)
        if self.config.get("ca_pem"):
            self.write_tracked(
                state, self.programs / "ca.pem", f"{self.logical_programs}/ca.pem",
                self.config["ca_pem"].encode(), 0o644,
            )  # fmt: skip
        # 서버는 승인된 계약을 검증하는 실행기를 거쳐 시작된다(검증이 틀리면 시작하지 않는다).
        mcp = {
            name: {
                "command": python,
                "args": [agent, "run", "--contracts", contracts, "--server", name],
            }
            for name in sorted(servers)
        }
        names = set()
        if "claude" in self.harnesses:
            hooks = self.hook_commands(python, agent, contracts)
            if self.managed:
                self.install_managed(state, mcp, hooks)
            else:
                self.install_user(state, mcp, hooks)
            names |= set(state["mcp_servers"])
        if "codex" in self.harnesses:
            hooks = self.codex_hook_commands(python, agent, contracts)
            names |= set(self.install_codex(state, mcp, hooks))
        state["mcp_servers"] = sorted(names)
        key = (self.config["key"] + "\n").encode()
        key_path = self.home / KEY_REL
        write_atomic(key_path, key, 0o600, self.owner)
        keep_private(key_path, self.account.name)
        state["files"][str(key_path)] = sha256_bytes(key)
        if self.owner is not None:
            os.chown(key_path.parent, *self.owner)
        write_atomic(self.state_file, json.dumps(state, indent=1).encode(), 0o644)
        return state

    def install_managed(self, state: dict, mcp: dict, hooks: dict) -> None:
        settings = {"allowManagedHooksOnly": True, "hooks": hooks}
        self.write_tracked(
            state,
            self.managed_dir / "managed-mcp.json",
            f"{self.claude_dir}/managed-mcp.json",
            json.dumps({"mcpServers": mcp}, indent=2).encode(),
            0o644,
        )
        self.write_tracked(
            state,
            self.managed_dir / "managed-settings.json",
            f"{self.claude_dir}/managed-settings.json",
            json.dumps(settings, indent=2).encode(),
            0o644,
        )
        state["mcp_servers"] = sorted(mcp)

    def install_user(self, state: dict, mcp: dict, hooks: dict) -> None:
        settings_path = self.home / ".claude/settings.json"
        original = settings_path.read_text(encoding="utf-8") if settings_path.exists() else None
        mode = (settings_path.stat().st_mode & 0o777) if original is not None else 0o600
        settings = json.loads(original) if original is not None else {}
        registered = settings.setdefault("hooks", {})
        for event, matchers in hooks.items():
            kept = [item for item in registered.get(event, []) if not ours(item)]
            registered[event] = kept + matchers
        # 처음 설치 때의 원문을 보관해 제거 때 글자까지 되돌린다(다시 설치해도 덮어쓰지 않는다).
        state.setdefault("settings_backup", original)
        text = json.dumps(settings, indent=2) + NL
        write_atomic(settings_path, text.encode(), mode, self.owner)
        state["settings_sha"] = sha256_bytes(text.encode())
        claude = self.claude()
        for name, definition in mcp.items():
            if claude is None:
                if not self.dry_run:
                    print("claude가 없어 MCP 서버 등록을 건너뜁니다:", name, file=sys.stderr)
                continue
            subprocess.run([claude, "mcp", "remove", "-s", "user", name], capture_output=True)
            done = subprocess.run(
                [claude, "mcp", "add-json", "-s", "user", name, json.dumps(definition)],
                capture_output=True,
            )
            if done.returncode == 0:
                state["mcp_servers"].append(name)

    def codex_config(self) -> Path:
        return self.home / ".codex/config.toml"

    def install_codex(self, state: dict, mcp: dict, hooks: dict) -> list[str]:
        """Codex 설정. 관리형은 요구 파일(Linux는 서버 정의 파일도), 그 밖은 config.toml 구간."""
        names = sorted(mcp)
        in_user_config = not self.managed or self.windows  # Windows는 관리형 서버 정의 파일이 없다
        if self.managed:
            requirements = codex_requirements(mcp, hooks, self.logical_programs, self.windows)
            self.write_tracked(
                state, self.codex_managed_dir / "requirements.toml",
                f"{self.codex_dir}/requirements.toml", requirements.encode(), 0o644,
            )  # fmt: skip
            if not self.windows:
                self.write_tracked(
                    state, self.codex_managed_dir / "managed_config.toml",
                    f"{self.codex_dir}/managed_config.toml", codex_servers(mcp).lstrip(NL).encode(),
                    0o644,
                )  # fmt: skip
        if in_user_config:
            names = self.write_codex_block(state, mcp, None if self.managed else hooks)
        return names

    def write_codex_block(self, state: dict, mcp: dict, hooks: dict | None) -> list[str]:
        path = self.codex_config()
        raw = path.read_bytes() if path.exists() else None
        original = raw.decode("utf-8-sig") if raw is not None else None
        rest = strip_block(original or "")
        # 사용자가 이미 정의한 이름은 건너뛴다(같은 표를 두 번 적으면 Codex가 설정을 읽지 못한다).
        mine = {}
        for name, item in mcp.items():
            if re.search(rf"(?m)^\[mcp_servers\.[\"']?{re.escape(name)}[\"']?\]", rest):
                print("Codex 설정에 같은 이름의 서버가 있어 건너뜁니다:", name, file=sys.stderr)
            else:
                mine[name] = item
        body = codex_servers(mine)
        if hooks:
            # 사용자가 [features] 표를 이미 갖고 있으면 같은 표를 다시 열 수 없어 그대로 둔다.
            body += codex_hooks(hooks)
            if not re.search(r"(?m)^\[features\]", rest):
                body += f"{NL}[features]{NL}hooks = true{NL}"
        state.setdefault("codex_config_backup", original)
        text = with_block(original or "", body)
        mode = (path.stat().st_mode & 0o777) if raw else 0o600
        write_atomic(path, text.encode(), mode, self.owner)
        state["codex_config_sha"] = sha256_bytes(text.encode())
        return sorted(mine)

    # -- 제거 -------------------------------------------------------------------------------------

    def uninstall(self) -> dict:
        state = self.load_state()
        if not state:
            return {"mode": "none"}
        left = []
        for logical, digest in state.get("files", {}).items():
            path = self.physical(logical)
            if not path.exists():
                continue
            if sha256_file(path) != digest:
                left.append(logical)  # 우리가 쓴 뒤 바뀐 파일은 건드리지 않는다.
                continue
            path.unlink()
            backup = state.get("backups", {}).get(logical)
            if backup and Path(backup).exists():
                write_atomic(path, Path(backup).read_bytes(), 0o644)
        if state.get("mode") == "user":
            self.uninstall_user(state)
        if "codex_config_sha" in state:
            self.uninstall_codex_config(state)
        shutil.rmtree(self.programs, ignore_errors=True)
        shutil.rmtree(self.home / STATE_REL, ignore_errors=True)
        extra = [self.codex_managed_dir.parent] if self.windows else []
        folders = (self.managed_dir, self.codex_managed_dir, *extra, self.home / ".config/mint")
        for folder in folders:
            try:
                folder.rmdir()
            except OSError:
                pass
        return {"mode": state.get("mode"), "kept": left, "kit_version": state.get("kit_version")}

    def uninstall_user(self, state: dict) -> None:
        settings_path = self.home / ".claude/settings.json"
        if settings_path.exists():
            current = settings_path.read_text(encoding="utf-8")
            backup = state.get("settings_backup")
            if sha256_bytes(current.encode()) == state.get("settings_sha"):
                # 설치 뒤 바뀌지 않았으면 처음 원문으로 되돌린다(원래 없었으면 지운다).
                if backup is None:
                    settings_path.unlink()
                else:
                    write_atomic(
                        settings_path, backup.encode(), settings_path.stat().st_mode & 0o777,
                        self.owner,
                    )
            else:
                settings = json.loads(current)
                registered = settings.get("hooks", {})
                for event in EVENTS:
                    registered[event] = [i for i in registered.get(event, []) if not ours(i)]
                    if not registered[event]:
                        del registered[event]
                text = (json.dumps(settings, indent=2) + NL).encode()
                write_atomic(settings_path, text, 0o600, self.owner)
        claude = self.claude()
        for name in state.get("mcp_servers", []):
            if claude is not None:
                subprocess.run([claude, "mcp", "remove", "-s", "user", name], capture_output=True)

    def uninstall_codex_config(self, state: dict) -> None:
        path = self.codex_config()
        if not path.exists():
            return
        current = path.read_bytes().decode("utf-8-sig")
        backup = state.get("codex_config_backup")
        if sha256_bytes(current.encode()) != state["codex_config_sha"]:
            rest = strip_block(current).encode()
            write_atomic(path, rest, path.stat().st_mode & 0o777, self.owner)
        elif backup is None:
            path.unlink()  # 설치가 만든 파일이다.
        else:
            write_atomic(path, backup.encode(), path.stat().st_mode & 0o777, self.owner)

    def harness_versions(self) -> str | None:
        """설치한 도구의 판본. 도구가 알려 준 글자 그대로(둘이면 가운뎃점으로 잇는다)."""
        found = [
            version
            for name, probe in (("claude", claude_version), ("codex", codex_version))
            if name in self.harnesses and (version := probe(self.home))
        ]
        return " · ".join(found)[:64] or None

    def report(self, state: dict, action: str) -> bool:
        installed = action == "installed"
        payload = {
            "kit_version": self.config["kit_version"],
            "action": action,
            "mode": state.get("mode", "none") if installed else "none",
            "claude_version": self.harness_versions(),
            "mcp_servers": state.get("mcp_servers", []) if installed else [],
        }
        url = self.config["decide_url"].rstrip("/") + REPORT_PATH
        ca_pem = self.config.get("ca_pem")
        if not ca_pem:
            return post(url, self.config["key"], payload, None)
        # 제거 뒤에는 설치한 인증서가 없으므로 묶음에 든 인증서를 임시 파일로 쓴다.
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(ca_pem)
        try:
            return post(url, self.config["key"], payload, handle.name)
        finally:
            os.unlink(handle.name)


def ours(item: object) -> bool:
    """훅 항목 중 이 묶음이 넣은 것(에이전트 스크립트 파일 이름으로 식별)."""
    return any(
        isinstance(hook, dict)
        and any(str(a).replace("\\", "/").endswith("/" + AGENT) for a in hook.get("args", []))
        for hook in (item.get("hooks", []) if isinstance(item, dict) else [])
    )


def find_tool(name: str, home: Path) -> str | None:
    """PATH에 없어도 공식 설치 위치(홈의 .local/bin)를 본다. 비대화형 접속은 PATH가 짧다."""
    found = shutil.which(name)
    for fallback in (home / ".local/bin" / name, home / ".local/bin" / (name + ".exe")):
        if not found and fallback.is_file():
            found = str(fallback)
    return found


def find_claude(home: Path) -> str | None:
    return find_tool("claude", home)


def find_codex(home: Path) -> str | None:
    return find_tool("codex", home)


def tool_version(path: str | None) -> str | None:
    if path is None:
        return None
    try:
        done = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip()[:64] or None


def claude_version(home: Path) -> str | None:
    return tool_version(find_claude(home))


def codex_version(home: Path) -> str | None:
    return tool_version(find_codex(home))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MINT endpoint kit")
    parser.add_argument(
        "action", nargs="?", default="install", choices=["install", "uninstall", "status"]
    )
    parser.add_argument("--user-level", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--user")
    parser.add_argument("--home")
    parser.add_argument("--root")
    parser.add_argument("--kit", default=str(KIT))
    args = parser.parse_args(argv)
    windows = sys.platform == "win32"
    if windows:
        name = args.user or os.environ.get("USERNAME", "")
        account = Account(name, Path(os.path.expanduser("~")), 0, 0)
        privileged = is_admin()
    else:
        import pwd

        name = args.user or os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
        entry = pwd.getpwnam(name)
        account = Account(name, Path(entry.pw_dir), entry.pw_uid, entry.pw_gid)
        privileged = os.geteuid() == 0
    if args.home:
        account = replace(account, home=Path(args.home))
    root = Path(args.root) if args.root else None
    managed = privileged and not args.user_level
    chown = privileged and not windows
    sandbox = None
    if args.dry_run:
        if args.action != "install":
            parser.error("--dry-run은 설치에만 쓸 수 있습니다")
        # 관리형 배치를 권한 없이 확인할 수 있게 임시 폴더 안에서 설치한다. 보고도 하지 않는다.
        sandbox = Path(tempfile.mkdtemp(prefix="mint-dry-"))
        root, account = sandbox / "root", replace(account, home=sandbox / "home")
        managed, chown = not args.user_level, False
    kit = Kit(
        Path(args.kit), root, managed, account, chown,
        strict=privileged and not args.dry_run, dry_run=args.dry_run,
    )  # fmt: skip
    if args.action == "status":
        print(json.dumps(kit.load_state() or {"mode": "none"}, indent=1))
        return 0
    if args.action == "install":
        state = kit.install()
        label = "관리형" if state["mode"] == "managed" else "사용자 수준(관리되지 않음)"
        if sandbox is not None:
            print(f"설치 예정: {label}. 쓰는 파일:")
            edited = []  # 사용자의 기존 설정 파일 안에 구간으로 들어가는 것
            if "settings_sha" in state:
                edited.append(str(kit.home / ".claude/settings.json"))
            if "codex_config_sha" in state:
                edited.append(str(kit.codex_config()))
            for logical in sorted([*state["files"], *edited]):
                home = str(account.home).replace("\\", "/")
                print("  " + logical.replace("\\", "/").replace(home, "~"))
            print("MCP 서버:", ", ".join(state["mcp_servers"]) or "없음")
            shutil.rmtree(sandbox, ignore_errors=True)
            return 0
        reported = kit.report(state, "installed")
        print(f"설치 완료: {label}. MINT 보고 {'성공' if reported else '실패(설치는 유지됨)'}")
        return 0
    result = kit.uninstall()
    reported = kit.report({"mode": result.get("mode")}, "removed")
    kept = result.get("kept") or []
    print(f"제거 완료. 바뀌어 남긴 파일 {len(kept)}개. MINT 보고 {'성공' if reported else '실패'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

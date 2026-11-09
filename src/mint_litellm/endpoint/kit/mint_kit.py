#!/usr/bin/env python3
"""MINT 엔드포인트 키트 설치기(표준 라이브러리만, Python 3.9 이상).

관리자 권한(root)으로 돌면 관리형으로 설치한다: 관리형 설정(호출 전 훅, 실패 시 차단, 관리형
훅만 허용), root 소유 경로의 훅, MINT 승인 목록에서 만든 관리형 MCP 목록, 사용자 키 파일.
권한이 없으면 사용자 수준으로 설치하고 MINT에 「관리되지 않음」으로 보고한다. 제거는 설치가
남긴 기록으로 원래 상태를 되돌린다. 설치 상태는 MINT에 보고한다(실패해도 설치는 유지).

``--root DIR``은 시험용으로 모든 시스템 경로를 DIR 아래로 옮긴다(파일 내용의 경로는 그대로).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

KIT = Path(__file__).resolve().parent
MANAGED_DIR = "/etc/claude-code"
PROGRAMS = "/usr/local/lib/mint-endpoint"
HOOK_ARGS_KEY = "--key-file"
KEY_REL = ".config/mint/key"
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


@dataclass(frozen=True)
class Account:
    """키와 사용자 수준 설정이 놓이는 계정. 관리자 권한으로 돌 때는 sudo를 부른 사람이다."""

    name: str
    home: Path
    uid: int
    gid: int


class Kit:
    def __init__(
        self, folder: Path, root: Path, managed: bool, account: Account, chown: bool
    ) -> None:
        self.config = json.loads((folder / "kit.json").read_text(encoding="utf-8"))
        self.folder, self.root, self.managed, self.account = folder, root, managed, account
        self.home = account.home
        self.programs = (
            (root / PROGRAMS.lstrip("/"))
            if self.managed
            else self.home / ".local/lib/mint-endpoint"
        )
        self.managed_dir = root / MANAGED_DIR.lstrip("/")
        self.logical_programs = (
            PROGRAMS if self.managed else str(self.home / ".local/lib/mint-endpoint")
        )
        self.owner = (account.uid, account.gid) if chown else None

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
            backup = self.programs / "backup" / logical.lstrip("/").replace("/", "__")
            if not backup.exists():
                write_atomic(backup, path.read_bytes(), 0o600)
                state["backups"][logical] = str(backup)
        write_atomic(path, data, mode)
        state["files"][logical] = sha256_bytes(data)

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
        if "settings_backup" in previous:
            state["settings_backup"] = previous["settings_backup"]
        hook = (self.folder / "hook.py").read_bytes()
        hook_path = f"{self.logical_programs}/hook.py"
        self.write_tracked(state, self.programs / "hook.py", hook_path, hook, 0o755)
        python = shutil.which("python3") or sys.executable
        if self.managed and self.owner is not None:
            info = os.stat(os.path.realpath(python))
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise SystemExit("python3 is not root-owned; refusing a managed install")
        servers = {
            item["name"]: {"command": item["command"], "args": item["args"], "env": item["env"]}
            for item in self.config["servers"]
        }
        hook_command = {
            "type": "command",
            "command": python,
            "args": [
                hook_path,
                "--url",
                self.config["decide_url"],
                HOOK_ARGS_KEY,
                f"~/{KEY_REL}",
                "--mcp-config",
                (MANAGED_DIR + "/managed-mcp.json") if self.managed else "~/.claude.json",
            ],
            "timeout": 3,
            "onFailure": "block",
        }
        if self.config.get("ca_pem"):
            ca_path = f"{self.logical_programs}/ca.pem"
            self.write_tracked(
                state, self.programs / "ca.pem", ca_path, self.config["ca_pem"].encode(), 0o644
            )
            hook_command["args"] += ["--ca-file", ca_path]
        matcher = {"matcher": "mcp__.*", "hooks": [hook_command]}
        if self.managed:
            self.install_managed(state, servers, matcher)
        else:
            self.install_user(state, servers, matcher)
        key = (self.config["key"] + "\n").encode()
        key_path = self.home / KEY_REL
        write_atomic(key_path, key, 0o600, self.owner)
        state["files"][str(key_path)] = sha256_bytes(key)
        if self.owner is not None:
            os.chown(key_path.parent, *self.owner)
        write_atomic(self.state_file, json.dumps(state, indent=1).encode(), 0o644)
        return state

    def install_managed(self, state: dict, servers: dict, matcher: dict) -> None:
        settings = {"allowManagedHooksOnly": True, "hooks": {"PreToolUse": [matcher]}}
        self.write_tracked(
            state,
            self.managed_dir / "managed-mcp.json",
            f"{MANAGED_DIR}/managed-mcp.json",
            json.dumps({"mcpServers": servers}, indent=2).encode(),
            0o644,
        )
        self.write_tracked(
            state,
            self.managed_dir / "managed-settings.json",
            f"{MANAGED_DIR}/managed-settings.json",
            json.dumps(settings, indent=2).encode(),
            0o644,
        )
        state["mcp_servers"] = sorted(servers)

    def install_user(self, state: dict, servers: dict, matcher: dict) -> None:
        settings_path = self.home / ".claude/settings.json"
        original = settings_path.read_text(encoding="utf-8") if settings_path.exists() else None
        mode = (settings_path.stat().st_mode & 0o777) if original is not None else 0o600
        settings = json.loads(original) if original is not None else {}
        hooks = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
        hooks[:] = [item for item in hooks if not ours(item)] + [matcher]
        # 처음 설치 때의 원문을 보관해 제거 때 글자까지 되돌린다(다시 설치해도 덮어쓰지 않는다).
        state.setdefault("settings_backup", original)
        text = json.dumps(settings, indent=2) + NL
        write_atomic(settings_path, text.encode(), mode)
        state["settings_sha"] = sha256_bytes(text.encode())
        claude = find_claude(self.home)
        for name, definition in servers.items():
            if claude is None:
                print("claude 실행 파일이 없어 MCP 서버 등록을 건너뜁니다:", name, file=sys.stderr)
                continue
            subprocess.run([claude, "mcp", "remove", "-s", "user", name], capture_output=True)
            done = subprocess.run(
                [claude, "mcp", "add-json", "-s", "user", name, json.dumps(definition)],
                capture_output=True,
            )
            if done.returncode == 0:
                state["mcp_servers"].append(name)

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
        shutil.rmtree(self.programs, ignore_errors=True)
        for folder in (self.managed_dir, self.home / ".config/mint"):
            try:
                folder.rmdir()
            except OSError:
                pass
        return {"mode": state.get("mode"), "kept": left, "kit_version": state.get("kit_version")}

    def physical(self, logical: str) -> Path:
        path = Path(logical)
        if self.managed and logical.startswith(("/etc/", "/usr/")):
            return self.root / logical.lstrip("/")
        return path

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
                        settings_path, backup.encode(), settings_path.stat().st_mode & 0o777
                    )
            else:
                settings = json.loads(current)
                hooks = settings.get("hooks", {}).get("PreToolUse", [])
                hooks[:] = [item for item in hooks if not ours(item)]
                write_atomic(settings_path, (json.dumps(settings, indent=2) + NL).encode(), 0o600)
        claude = find_claude(self.home)
        for name in state.get("mcp_servers", []):
            if claude is not None:
                subprocess.run([claude, "mcp", "remove", "-s", "user", name], capture_output=True)

    def report(self, state: dict, action: str) -> bool:
        payload = {
            "kit_version": self.config["kit_version"],
            "action": action,
            "mode": state.get("mode", "none"),
            "managed": state.get("mode") == "managed" and action == "installed",
            "files": {k: v for k, v in state.get("files", {}).items() if not k.endswith(KEY_REL)},
            "mcp_servers": state.get("mcp_servers", []),
            "claude_version": claude_version(self.home),
        }
        url = self.config["decide_url"].rstrip("/") + "/mint/v1/endpoint/report"
        ca = f"{self.logical_programs}/ca.pem" if self.config.get("ca_pem") else None
        return post(
            url,
            self.config["key"],
            payload,
            ca if ca and Path(self.physical(ca)).exists() else None,
        )


def ours(item: object) -> bool:
    """훅 항목 중 이 키트가 넣은 것(훅 스크립트 이름으로 식별)."""
    return any(
        isinstance(hook, dict)
        and any("mint-endpoint/hook.py" in str(a) for a in hook.get("args", []))
        for hook in (item.get("hooks", []) if isinstance(item, dict) else [])
    )


def find_claude(home: Path) -> str | None:
    """PATH에 없어도 공식 설치 위치(홈의 .local/bin)를 본다. 비대화형 접속은 PATH가 짧다."""
    found = shutil.which("claude")
    fallback = home / ".local/bin/claude"
    return found or (str(fallback) if fallback.is_file() else None)


def claude_version(home: Path) -> str | None:
    claude = find_claude(home)
    if claude is None:
        return None
    try:
        done = subprocess.run([claude, "--version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MINT endpoint kit")
    parser.add_argument(
        "action", nargs="?", default="install", choices=["install", "uninstall", "status"]
    )
    parser.add_argument("--user-level", action="store_true")
    parser.add_argument("--user")
    parser.add_argument("--root", default="/")
    parser.add_argument("--kit", default=str(KIT))
    args = parser.parse_args(argv)
    import pwd

    root_user = os.geteuid() == 0
    name = args.user or os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    entry = pwd.getpwnam(name)
    account = Account(name, Path(entry.pw_dir), entry.pw_uid, entry.pw_gid)
    managed = root_user and not args.user_level
    kit = Kit(Path(args.kit), Path(args.root), managed, account, chown=root_user)
    if args.action == "status":
        print(json.dumps(kit.load_state() or {"mode": "none"}, indent=1))
        return 0
    if args.action == "install":
        state = kit.install()
        reported = kit.report(state, "installed")
        label = "관리형" if state["mode"] == "managed" else "사용자 수준(관리되지 않음)"
        print(f"설치 완료: {label}. MINT 보고 {'성공' if reported else '실패(설치는 유지됨)'}")
        return 0
    result = kit.uninstall()
    reported = kit.report({"mode": result.get("mode"), "files": {}}, "removed")
    kept = result.get("kept") or []
    print(f"제거 완료. 바뀌어 남긴 파일 {len(kept)}개. MINT 보고 {'성공' if reported else '실패'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

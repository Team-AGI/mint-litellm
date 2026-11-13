#!/usr/bin/env python3
"""MINT 단말 설치 묶음 설치기(표준 라이브러리만, Python 3.9 이상).

관리자 권한(root, Windows는 관리자)으로 돌면 관리형으로 설치한다: 관리형 설정(호출 전·후 훅,
실패 시 차단, 관리형 훅만 허용), 관리자 소유 경로의 에이전트, MINT 승인 목록에서 만든 관리형 MCP
목록(서버는 승인된 실행 계약을 검증하는 실행기를 거쳐 시작된다), 사용자 키 파일. 권한이 없으면
사용자 수준으로 설치하고 MINT에 「관리되지 않음」으로 보고한다. 제거는 설치가 남긴 기록으로 원래
상태를 되돌린다. 설치 상태는 MINT에 보고한다(실패해도 설치는 유지).

설치한 묶음은 설치 상태를 주기적으로 다시 보고한다: Linux는 사용자 systemd 타이머, Windows는
예약 작업이 ``report`` 하위 명령(설치된 이 파일)을 6시간마다 부르고, 서버 실행기가 시작될 때도
한 번 부른다(1시간 안에 보냈으면 건너뛴다). 키가 만료되기 전 14일 안의 보고는 MINT가 키의 만료
시각을 늘려 준다.

보고 응답에는 MINT가 폐기·반려·미승인으로 보는 서버 이름 목록(``retired``)이 실린다. 관리형 설치의
보고기는 관리자 권한(Linux는 시스템 타이머, Windows는 SYSTEM 예약 작업)으로 돌며, 이 묶음이 쓴 설정
항목과 묶음 실행기가 띄운 프로세스(실행기가 기록한 PID, 시작 시각까지 맞을 때만)와 묶음이 등록한
자동 시작 항목 중 목록에 든 서버의 것만 지우고, 지운 것을 곧바로 다시 보고한다. 사용자가 만든
항목과 묶음이 띄우지 않은 프로세스는 건드리지 않는다. 사용자 수준 설치는 지우지 않고 경보만 남는다.
목록은 실행기가 읽도록 사용자 캐시에 남긴다.

대상 도구는 묶음의 ``harnesses``(claude, codex)가 정한다. Codex는 관리형이면 관리자 요구 파일
(``requirements.toml``: 승인 서버 외 차단, 호출 전·후 훅)을, 사용자 수준이면 ``config.toml``의 표식
구간을 쓴다. 서버 표는 승인 서버가 없어도 항상 둔다(표가 없으면 Codex는 서버를 제한하지 않는다).

``--root DIR``은 시험용으로 모든 시스템 경로를 DIR 아래로 옮긴다(파일 내용의 경로는 그대로).
``--dry-run``은 임시 폴더에 설치해 쓰게 될 파일만 보이고 실제 설정은 바꾸지 않는다.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import random
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
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
# 주기 보고: 간격(시), 시작 지연의 상한(초), 서버 실행기가 시작할 때 보고를 건너뛰는 최소 간격(초)
REPORT_INTERVAL_HOURS = 6
REPORT_JITTER = 1800
REPORT_MIN_GAP = 3600
LAST_REPORT = "last_report"
REPORTER_KEY = "reporter.key"  # Windows 관리형: SYSTEM 보고기가 읽는 키 사본
RETIRED_FILE = "retired.json"  # 마지막 보고 응답의 폐기 서버 목록(실행기가 읽는다)
LAUNCHED = "launched"  # 실행기가 띄운 서버 프로세스의 기록
SYSTEMD_DIR = "/etc/systemd/system"
MAX_PENDING = 256
UNIT = "mint-report"
TASK_NAME = "MINT Endpoint Report"


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


def post(url: str, key: str, payload: dict, ca_file: str | None) -> dict | None:
    """보고를 보내고 응답 본문(JSON 객체)을 돌려준다. 닿지 못했거나 거절되면 None."""
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
            if reply.status != 200:
                return None
            try:
                answer = json.loads(reply.read(65536))
            except ValueError:
                answer = None
            return answer if isinstance(answer, dict) else {"recorded": True}
    except urllib.error.HTTPError as error:
        if error.code == 403:
            sys.stderr.write("MINT 키가 만료되었습니다. 설치 묶음 재발급을 요청하세요." + NL)
        return None
    except OSError:
        return None


def jitter_delay(limit: int, rand=random.random) -> int:
    """주기 보고 전에 기다릴 초(0 이상 ``limit`` 미만). 단말들이 같은 시각에 몰리지 않게 한다."""
    return int(max(limit, 0) * rand())


def report_due(last: float | None, now: float, min_gap: int = REPORT_MIN_GAP) -> bool:
    """마지막 보고 뒤 ``min_gap``초가 지났거나, 기록이 없거나, 시계가 되돌아갔으면 참."""
    return last is None or now < last or now - last >= min_gap


# --- 읽기 전용 인벤토리: 실행 중인 MCP 서버 프로세스와 자동 시작 항목 -----------------------
# 묶음의 실행기(``mint_agent.py run --server 이름``)로 뜬 프로세스와, 그 실행기나 MCP 서버를
# 가리키는 자동 시작 항목만 이름으로 보고한다. 아무것도 바꾸지 않으며, 읽지 못하는 곳은 건너뛴다.
LAUNCHER = re.compile(r"mint_agent\.py\"?\s+run\b.*?--server[ =]\"?([^\s\"]+)")
MCP_WORD = re.compile(r"mint_agent\.py|\bmcp\b|mcp[-_]server", re.IGNORECASE)
MAX_ITEMS = 64
MAX_TEXT = 65536


def server_of(command: str) -> str | None:
    """실행기 명령줄이 시작하는 서버 이름. 실행기가 아니면 None."""
    found = LAUNCHER.search(command)
    return found.group(1)[:128] if found else None


def autostart_item(kind: str, name: str, text: str) -> dict | None:
    """자동 시작 항목의 내용이 MCP 실행기·서버를 가리키면 보고할 항목, 아니면 None."""
    if not MCP_WORD.search(text):
        return None
    return {"kind": kind, "name": name[:256], "server": server_of(text)}


def cron_reboot(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip().startswith("@reboot")]


def parse_reg(text: str) -> list[tuple[str, str]]:
    """``reg query`` 출력의 (값 이름, 값)."""
    rows = []
    for line in text.splitlines():
        parts = re.split(r"\s{2,}", line.strip(), maxsplit=2)
        if len(parts) == 3 and parts[1].startswith("REG_"):
            rows.append((parts[0], parts[2]))
    return rows


def parse_schtasks(text: str) -> list[tuple[str, str]]:
    """``schtasks /query /fo csv /v`` 출력의 (작업 이름, 실행할 명령)."""
    rows = []
    for row in csv.DictReader(io.StringIO(text)):
        name, command = row.get("TaskName"), row.get("Task To Run")
        if name and command:
            rows.append((name, command))
    return rows


def capture(command: list[str]) -> str:
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=20, errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout if done.returncode == 0 else ""


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:MAX_TEXT]
    except OSError:
        return ""


def process_commands(windows: bool) -> list[str]:
    if windows:
        out = capture(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process | ForEach-Object { $_.CommandLine }"]
        )  # fmt: skip
        return out.splitlines()
    commands = []
    for entry in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            commands.append(entry.read_bytes().replace(b"\0", b" ").decode(errors="replace"))
        except OSError:
            continue
    return commands


def scan_processes(windows: bool) -> list[dict]:
    counts: dict[str, int] = {}
    for command in process_commands(windows):
        name = server_of(command)
        if name:
            counts[name] = counts.get(name, 0) + 1
    return [{"server": n, "count": c} for n, c in sorted(counts.items())][:MAX_ITEMS]


def with_sandbox(processes: list[dict], home: Path, windows: bool) -> list[dict]:
    """프로세스 항목에 서버별 격리 상태를 더한다(실행기가 남긴 기록 중 아직 살아 있는 것만).

    ``bwrap``은 기록된 모든 프로세스가 격리 안, ``none``은 하나라도 격리 없이, Windows는
    ``unsupported``. 기록이 없는 서버는 비워 둔다(이전 실행기가 띄운 것).
    """
    seen: dict[str, str] = {}
    folder = home / STATE_REL / LAUNCHED
    for path in sorted(folder.glob("*.json")) if not windows and folder.is_dir() else []:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            server, pid, start = str(record["server"]), int(record["pid"]), record.get("start")
            status = record.get("sandbox")
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if status in ("bwrap", "none") and start and proc_start(pid, False) == start:
            seen[server] = "none" if "none" in (status, seen.get(server)) else "bwrap"
    for item in processes:
        status = "unsupported" if windows else seen.get(item["server"])
        if status:
            item["sandbox"] = status
    return processes


def scan_autostart(home: Path, windows: bool, user: str, profile: bool = True) -> list[dict]:
    found = []

    def add(kind: str, name: str, text: str) -> None:
        item = autostart_item(kind, name, text)
        if item:
            found.append(item)

    if windows:
        for hive in ("HKCU", "HKLM"):
            key = hive + r"\Software\Microsoft\Windows\CurrentVersion\Run"
            for name, value in parse_reg(capture(["reg", "query", key])):
                add("run_key", name, value)
        for name, command in parse_schtasks(capture(["schtasks", "/query", "/fo", "csv", "/v"])):
            add("scheduled_task", name, command)
        startup = home / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
        # 프로필(시작 프로그램 폴더)은 사용자 권한으로 도는 보고기만 읽는다.
        for path in sorted(startup.glob("*")) if profile and startup.is_dir() else []:
            add("startup_folder", path.name, path.name + " " + read_text(path))
    else:
        for kind, folder, pattern in (
            ("systemd", home / ".config/systemd/user", "*.service"),
            ("autostart", home / ".config/autostart", "*.desktop"),
            ("autostart", Path("/etc/xdg/autostart"), "*.desktop"),
        ):
            for path in sorted(folder.glob(pattern)) if folder.is_dir() else []:
                add(kind, path.name, read_text(path))
        for line in cron_reboot(capture(["crontab", "-l", "-u", user])):
            add("cron", "@reboot", line)
    return found[:MAX_ITEMS]


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


def drop_tables(text: str, names: set[str]) -> tuple[str, list[str]]:
    """``[mcp_servers."이름"]`` 표를 지운다(표는 다음 표 머리나 구간 표식에서 끝난다)."""
    headers = {f"[mcp_servers.{toml(name)}]": name for name in names}
    kept, skipping, gone = [], False, []
    for line in text.splitlines(keepends=True):
        bare = line.strip()
        if bare.startswith("[") or bare in (BEGIN, END):
            name = headers.get(bare)
            skipping = name is not None
            if name is not None:
                gone.append(name)
                continue
        if not skipping:
            kept.append(line)
    return "".join(kept), gone


def drop_block_tables(text: str, names: set[str]) -> tuple[str, list[str]]:
    """표식 구간 안의 서버 표만 지운다. 구간 밖(사용자가 쓴 것)은 한 글자도 바꾸지 않는다."""
    found = re.search(rf"{re.escape(BEGIN)}.*?{re.escape(END)}", text, flags=re.S)
    if found is None:
        return text, []
    block, gone = drop_tables(found.group(0), names)
    return text[: found.start()] + block + text[found.end() :], gone


def is_ours_entry(entry: object, name: str) -> bool:
    """관리형 MCP 목록의 항목 중 이 묶음의 실행기가 ``name`` 서버를 시작하는 것."""
    raw = entry.get("args", []) if isinstance(entry, dict) else []
    args = [str(a).replace("\\", "/") for a in raw]
    return (
        any(a.endswith("/" + AGENT) for a in args)
        and "--server" in args
        and args[args.index("--server") + 1 : args.index("--server") + 2] == [name]
    )


def proc_start(pid: int, windows: bool) -> str | None:
    """프로세스의 시작 시각 표지(재사용된 PID를 가려내는 데 쓴다). 없는 프로세스나 모르면 None."""
    if windows:
        out = capture(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-Process -Id {int(pid)}).StartTime.ToFileTimeUtc()"]
        )  # fmt: skip
        return out.strip() or None
    try:
        stat = Path(f"/proc/{int(pid)}/stat").read_text()
    except OSError:
        return None
    return stat.rsplit(")", 1)[-1].split()[19] if ")" in stat else None


def drop_target(user: str | None) -> tuple[int, int] | None:
    """관리자(root)로 돌 때 사용자 홈 일을 내려 보낼 (uid, gid). 이름으로 계정부에서 찾으며
    홈 폴더의 소유자 정보는 쓰지 않는다. root가 아니거나 계정을 모르면 None."""
    if os.name != "posix" or os.geteuid() != 0 or not user:
        return None
    import pwd

    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        return None
    return entry.pw_uid, entry.pw_gid


def as_user(uid: int, gid: int, fn):
    """``fn()``을 uid·gid로 내려간 자식 프로세스에서 돌리고 JSON으로 돌려받는다(실패하면 None).

    사용자 홈의 읽기·쓰기·프로세스 종료를 커널이 그 사용자의 권한으로 집행하게 하므로, 사용자가
    경로 중간을 심볼릭 링크로 바꿔도 root 권한으로 엉뚱한 파일을 읽거나 쓰지 못한다.
    """
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.close(reader)
            os.setgroups([])
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)
            data = json.dumps(fn()).encode()
            with os.fdopen(writer, "wb") as handle:
                handle.write(data)
            code = 0
        except BaseException:
            pass
        os._exit(code)
    os.close(writer)
    with os.fdopen(reader, "rb") as handle:
        data = handle.read(1 << 20)
    _, status = os.waitpid(pid, 0)
    try:
        return json.loads(data) if status == 0 and data else None
    except ValueError:
        return None


def save_retired(home: Path, names: list[str], now: float, folder: Path | None = None) -> None:
    """응답의 폐기 서버 목록을 실행기가 읽을 캐시에 쓴다(기본은 사용자 캐시, SYSTEM은 설치 폴더).
    쓰지 못해도 보고는 계속한다."""
    try:
        write_atomic(
            (folder or home / STATE_REL) / RETIRED_FILE,
            json.dumps({"servers": names, "at": now}).encode(), 0o644 if folder else 0o600,
        )
    except OSError:
        return


def unlink_if_ours(path: str, digest: str | None) -> bool:
    """우리가 쓴 그대로인 파일이면 지운다(이미 없어도 참). 바뀐 파일은 두고 거짓."""
    if not os.path.exists(path):
        return True
    if digest is None or sha256_file(Path(path)) != digest:
        return False
    os.unlink(path)
    return True


# --- 실행 신뢰 점검: 관리자 권한으로 돌 코드와 상위 폴더는 관리자 소유이고 남이 못 쓴다 ---
SAFE_OWNERS = ("NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller")
OPEN_GROUPS = ("builtin\\users", "authenticated users", "everyone")
WRITE_RIGHTS = {"F", "M", "W", "WD", "AD", "GW", "GA", "WO", "WDAC"}


def chain_of(path: str) -> list[str]:
    seen = []
    cur = path
    while True:
        seen.append(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            return seen
        cur = parent


def untrusted_reason(path: str, lstat=os.lstat, realpath=os.path.realpath) -> str | None:
    """POSIX: ``path``와 상위 폴더 전부(링크를 따라간 실제 경로 포함)가 root 소유이고 그룹·모두가
    쓸 수 없는지 본다. 아니면 이유."""
    items = dict.fromkeys(chain_of(os.path.abspath(path)) + chain_of(realpath(path)))
    for item in items:
        try:
            info = lstat(item)
        except OSError:
            return f"{item} cannot be inspected"
        if info.st_uid != 0:
            return f"{item} is not root-owned"
        if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022:
            return f"{item} is writable by other users"
    return None


def windows_owner(path: str, run) -> str:
    script = f"(Get-Acl -LiteralPath '{path}').Owner"
    return run(["powershell", "-NoProfile", "-Command", script]).strip()


def windows_untrusted_reason(path: str, run=None) -> str | None:
    """Windows: ``path``와 상위 폴더의 소유자가 SYSTEM·Administrators이고 Users·Authenticated
    Users·Everyone에 쓰기 권한이 없는지 본다. 아니면 이유."""
    run = run or capture
    for item in chain_of(path.replace("/", "\\")):
        listing = run(["icacls", item])
        if not listing.strip():
            return f"{item} cannot be inspected"
        for line in listing.splitlines():
            if not any(group in line.lower() for group in OPEN_GROUPS):
                continue
            rights = {t for part in re.findall(r"\(([^)]*)\)", line) for t in part.split(",")}
            if rights & WRITE_RIGHTS:
                return f"{item} is writable by other users"
        if windows_owner(item, run) not in SAFE_OWNERS:
            return f"{item} is not owned by an administrator"
    return None


def untrusted_run(folder: Path, windows: bool, python: str | None = None, run=None) -> str | None:
    """관리자 권한 보고기가 돌 때 믿어야 할 것(인터프리터·이 파일·설정·설치 폴더)의 점검."""
    check = (lambda p: windows_untrusted_reason(p, run)) if windows else untrusted_reason
    here = os.path.abspath(__file__)
    for path in (python or sys.executable, here, str(folder / "mint_kit.py"),
                 str(folder / "kit.json"), str(folder)):  # fmt: skip
        reason = check(path)
        if reason:
            return reason
    return None


def windows_system() -> bool:
    """Windows에서 SYSTEM 계정(사용자 이름이 ``컴퓨터$``)으로 도는 예약 작업인가."""
    return os.name == "nt" and os.environ.get("USERNAME", "").endswith("$")


def read_trusted(path: Path, need_root: bool) -> bytes:
    """링크를 따라가지 않고 열어 읽는다. ``need_root``이면 root 소유이고 남이 못 쓰는 파일만."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if need_root and (info.st_uid != 0 or info.st_mode & 0o022):
            raise OSError(f"{path} is not root-owned")
        return handle.read()


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
        self.system_paths = (managed_programs, self.claude_dir, self.codex_dir, SYSTEMD_DIR)
        self.answer: dict = {}  # 마지막 보고의 응답

        self.logical_programs = managed_programs if self.managed else user_programs
        self.programs = self.physical(self.logical_programs)
        self.managed_dir = self.physical(self.claude_dir)
        self.codex_managed_dir = self.physical(self.codex_dir)
        self.owner = (account.uid, account.gid) if chown else None

    # Windows SYSTEM 보고기: 사용자 프로필은 읽지도 쓰지도 않는다(경로 점검과 사용 사이의 경합을
    # 피하는 가장 단순한 방법). 키·보고 기록·폐기 서버 목록은 설치 폴더에 둔다.
    system_mode = False

    def run_as_user(self, fn):
        """사용자 홈 일을 돌린다. 관리자 권한 보고기는 이를 사용자 권한의 자식 프로세스로 바꾼다."""
        return fn()

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
            reason = windows_untrusted_reason(python)
        else:
            reason = untrusted_reason(python)
        if reason:
            raise SystemExit(f"managed install needs a trusted interpreter: {reason}")

    def ensure_sandbox_tool(self) -> None:
        """관리형 Linux 설치는 서버 격리에 쓰는 bubblewrap이 있어야 한다. 없으면 설치를 시도하고,
        못 하면 이유를 알리고 멈춘다(실행기는 격리할 수 없으면 서버를 시작하지 않는다)."""
        if self.windows or not (self.managed and self.strict):
            return
        if self.config.get("allow_unsandboxed"):
            return
        if shutil.which("bwrap"):
            return
        for manager, command in (
            ("apt-get", ["apt-get", "install", "-y", "bubblewrap"]),
            ("dnf", ["dnf", "install", "-y", "bubblewrap"]),
            ("yum", ["yum", "install", "-y", "bubblewrap"]),
            ("zypper", ["zypper", "--non-interactive", "install", "bubblewrap"]),
            ("pacman", ["pacman", "-S", "--noconfirm", "bubblewrap"]),
        ):
            if shutil.which(manager):
                subprocess.run(command, check=False, stdin=subprocess.DEVNULL)
                break
        if not shutil.which("bwrap"):
            raise SystemExit(
                "관리형 설치에는 bubblewrap(bwrap)이 필요합니다. 자동으로 설치하지 못했습니다. "
                "패키지 관리자로 bubblewrap을 설치한 뒤 다시 실행하세요."
            )

    def install(self) -> dict:
        self.ensure_sandbox_tool()
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
        fixed = "/usr/bin/python3"  # 관리자 권한으로 돌 보고기는 시스템 인터프리터를 쓴다
        if self.windows:
            python = sys.executable.replace("\\", "/")
        elif self.managed and self.strict and os.path.exists(fixed):
            python = fixed
        else:
            python = shutil.which("python3") or sys.executable
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
        self.install_reporter(state, python)
        key = (self.config["key"] + "\n").encode()
        key_path = self.home / KEY_REL
        write_atomic(key_path, key, 0o600, self.owner)
        keep_private(key_path, self.account.name)
        state["files"][str(key_path)] = sha256_bytes(key)
        if self.owner is not None:
            os.chown(key_path.parent, *self.owner)
        write_atomic(self.state_file, json.dumps(state, indent=1).encode(), 0o644)
        return state

    def install_reporter(self, state: dict, python: str) -> None:
        """주기 보고에 쓸 이 파일의 사본과 설정(키 제외)을 두고 타이머·예약 작업을 등록한다."""
        tool = f"{self.logical_programs}/mint_kit.py"
        self.write_tracked(
            state, self.programs / "mint_kit.py", tool, (self.folder / "mint_kit.py").read_bytes(),
            0o644,
        )
        config = {k: v for k, v in self.config.items() if k not in ("key", "servers")}
        self.write_tracked(
            state, self.programs / "kit.json", f"{self.logical_programs}/kit.json",
            json.dumps(config, indent=1).encode(), 0o644,
        )  # fmt: skip
        if self.managed and self.strict:
            for path in (self.programs / "mint_kit.py", self.programs / "kit.json", self.programs):
                reason = (windows_untrusted_reason if self.windows else untrusted_reason)(str(path))
                if reason:
                    raise SystemExit(f"managed install needs a trusted kit folder: {reason}")
        if self.windows and self.managed:
            # SYSTEM 보고기는 프로필을 읽지 않으므로 키 사본을 설치 폴더에 둔다(관리자만 읽음).
            self.write_tracked(
                state, self.programs / REPORTER_KEY, f"{self.logical_programs}/{REPORTER_KEY}",
                (self.config["key"] + "\n").encode(), 0o600,
            )  # fmt: skip
            self.lock_programs()
        command = [python, "-I", "-B", tool, "report", "--kit", self.logical_programs]
        if self.managed:
            # 관리자 권한으로 돌므로 사용자의 키와 캐시가 있는 홈을 알려 준다.
            command += ["--home", str(self.home).replace("\\", "/"), "--user", self.account.name]
        if self.windows:
            self.schedule_task(state, command)
        else:
            self.schedule_timer(state, command)

    def lock_programs(self) -> None:
        """설치 폴더의 접근 권한을 명시한다: SYSTEM·Administrators는 쓰기, Users는 읽기만, 키 사본은
        SYSTEM·Administrators만."""
        if self.root is not None or self.dry_run:
            return
        capture([
            "icacls", str(self.programs), "/inheritance:r", "/grant:r",
            "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX",
        ])  # fmt: skip
        capture([
            "icacls", str(self.programs / REPORTER_KEY), "/inheritance:r", "/grant:r",
            "*S-1-5-18:F", "*S-1-5-32-544:F",
        ])  # fmt: skip

    def schedule_timer(self, state: dict, command: list[str]) -> None:
        """systemd 타이머. 시작 지연의 무작위화는 systemd가 한다.

        관리형은 시스템 타이머(관리자 권한이라 폐기 서버의 관리형 설정 항목을 지울 수 있다),
        사용자 수준은 사용자 타이머(다음 로그인부터)이다.
        """
        if self.managed:
            return self.schedule_system_timer(state, command)
        folder = self.home / ".config/systemd/user"
        units = {
            f"{UNIT}.service": (
                "[Unit]\nDescription=MINT endpoint report\n\n[Service]\nType=oneshot\n"
                f"ExecStart={shlex.join(command)}\n"
            ),
            f"{UNIT}.timer": (
                "[Unit]\nDescription=MINT endpoint report\n\n[Timer]\nOnBootSec=5min\n"
                f"OnUnitActiveSec={REPORT_INTERVAL_HOURS}h\n"
                f"RandomizedDelaySec={REPORT_JITTER}\n\n[Install]\nWantedBy=timers.target\n"
            ),
        }
        for name, text in units.items():
            self.write_tracked(state, folder / name, str(folder / name), text.encode(), 0o644)
        wants = folder / "timers.target.wants" / f"{UNIT}.timer"
        wants.parent.mkdir(parents=True, exist_ok=True)
        try:
            if not wants.is_symlink():
                os.symlink(f"../{UNIT}.timer", wants)
        except OSError:
            return  # 링크를 만들 수 없는 곳(Windows 위의 시험 배치 등)에서는 타이머를 켜지 않는다.
        state["links"] = [str(wants)]
        if self.owner is not None:
            for path in (folder.parent.parent, folder.parent, folder, wants.parent):
                if path.is_relative_to(self.home) and path != self.home:
                    os.chown(path, *self.owner)
            for name in units:
                os.chown(folder / name, *self.owner)
            os.lchown(wants, *self.owner)
        elif self.root is None and not self.dry_run:
            capture(["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"])

    def schedule_system_timer(self, state: dict, command: list[str]) -> None:
        folder = self.physical(SYSTEMD_DIR)
        units = {
            f"{UNIT}.service": (
                "[Unit]\nDescription=MINT endpoint report\n\n[Service]\nType=oneshot\n"
                f"ExecStart={shlex.join(command)}\n"
            ),
            f"{UNIT}.timer": (
                "[Unit]\nDescription=MINT endpoint report\n\n[Timer]\nOnBootSec=5min\n"
                f"OnUnitActiveSec={REPORT_INTERVAL_HOURS}h\n"
                f"RandomizedDelaySec={REPORT_JITTER}\n\n[Install]\nWantedBy=timers.target\n"
            ),
        }
        for name, text in units.items():
            self.write_tracked(state, folder / name, f"{SYSTEMD_DIR}/{name}", text.encode(), 0o644)
        wants = folder / "timers.target.wants" / f"{UNIT}.timer"
        wants.parent.mkdir(parents=True, exist_ok=True)
        try:
            if not wants.is_symlink():
                os.symlink(f"../{UNIT}.timer", wants)
        except OSError:
            return
        state["links"] = [str(wants)]
        state["timer"] = "system"
        if self.root is None and not self.dry_run:
            capture(["systemctl", "enable", "--now", f"{UNIT}.timer"])

    def schedule_task(self, state: dict, command: list[str]) -> None:
        """Windows 예약 작업(설치한 계정으로 돈다). 시작 지연은 명령이 스스로 기다린다."""
        if self.root is not None or self.dry_run:
            return
        line = subprocess.list2cmdline([*command, "--jitter", str(REPORT_JITTER)])
        made = capture([
            "schtasks", "/Create", "/TN", TASK_NAME, "/SC", "HOURLY",
            "/MO", str(REPORT_INTERVAL_HOURS), "/TR", line, "/F",
            *(["/RU", "SYSTEM"] if self.managed else []),
        ])  # fmt: skip
        if made:
            state["task"] = TASK_NAME

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
        if state.get("timer") == "system" and self.root is None:
            capture(["systemctl", "disable", "--now", f"{UNIT}.timer"])
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
        for link in state.get("links", []):
            Path(link).unlink(missing_ok=True)
        if state.get("task") and self.root is None:
            capture(["schtasks", "/Delete", "/TN", state["task"], "/F"])
        elif state.get("links") and self.root is None and not self.owner and not state.get("timer"):
            capture(["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"])
        if state.get("mode") == "user":
            self.uninstall_user(state)
        if "codex_config_sha" in state:
            self.uninstall_codex_config(state)
        shutil.rmtree(self.programs, ignore_errors=True)
        shutil.rmtree(self.home / STATE_REL, ignore_errors=True)
        extra = [self.codex_managed_dir.parent] if self.windows else []
        wants = self.physical(SYSTEMD_DIR) / "timers.target.wants"
        folders = (
            self.managed_dir, self.codex_managed_dir, *extra, wants, self.home / ".config/mint"
        )  # fmt: skip
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

    def inventory(self) -> dict:
        """프로세스·자동 시작 인벤토리(사용자 홈을 읽으므로 사용자 권한으로). 실패해도 계속."""
        return self.run_as_user(self.read_inventory) or {}

    def read_inventory(self) -> dict:
        try:
            processes = with_sandbox(scan_processes(self.windows), self.home, self.windows)
            extra = {"profile": False} if self.system_mode else {}
            autostart = scan_autostart(self.home, self.windows, self.account.name, **extra)
        except Exception:
            return {}
        return {"processes": processes, "autostart": autostart}

    def pending_removed(self, state: dict) -> list[dict]:
        """아직 보고하지 못한 제거 항목. 상태 파일을 쓸 수 있는(관리자 권한) 보고기만 보낸다."""
        items = state.get("pending_removed") or []
        return items if items and self.managed and os.access(self.programs, os.W_OK) else []

    def report(self, state: dict, action: str) -> bool:
        installed = action == "installed"
        pending = self.pending_removed(state) if installed else []
        payload = {
            "kit_version": self.config["kit_version"],
            "action": action,
            "mode": state.get("mode", "none") if installed else "none",
            "claude_version": self.harness_versions(),
            "mcp_servers": state.get("mcp_servers", []) if installed else [],
            **self.inventory(),
        }
        if pending:
            payload["removed"] = pending
        url = self.config["decide_url"].rstrip("/") + REPORT_PATH
        ca_pem = self.config.get("ca_pem")
        if not ca_pem:
            answer = post(url, self.config["key"], payload, None)
        else:
            # 제거 뒤에는 설치한 인증서가 없으므로 묶음에 든 인증서를 임시 파일로 쓴다.
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
                handle.write(ca_pem)
            try:
                answer = post(url, self.config["key"], payload, handle.name)
            finally:
                os.unlink(handle.name)
        self.answer = answer if isinstance(answer, dict) else {}
        if answer and pending:
            state.pop("pending_removed", None)
            self.save_state(state)
        return bool(answer)

    def save_state(self, state: dict) -> bool:
        try:
            write_atomic(self.state_file, json.dumps(state, indent=1).encode(), 0o644)
        except OSError:
            return False
        return True

    # -- 폐기 서버 정리(관리형) -----------------------------------------------------------------

    def retrack(self, state: dict, logical: str, before: str, after: bytes) -> None:
        """우리가 쓴 그대로였던 파일만 새 내용을 우리 것으로 다시 기록한다(바뀐 파일은 남긴다)."""
        if state["files"].get(logical) == before:
            state["files"][logical] = sha256_bytes(after)

    def edit_file(self, state: dict, path: Path, logical: str, edit) -> tuple[list[str], bool]:
        """파일 내용을 ``edit(글) -> (새 글, 지운 이름들)``로 고친다. (지운 이름, 쓰기 성공)."""
        if not path.exists() and not path.is_symlink():
            return [], True
        try:
            raw = read_trusted(path, self.root_owned())
            new, gone = edit(raw.decode("utf-8-sig"))
            if not gone:
                return [], True
            write_atomic(path, new.encode(), path.stat().st_mode & 0o777)
        except (OSError, ValueError):
            return [], False
        self.retrack(state, logical, sha256_bytes(raw), new.encode())
        return gone, True

    def root_owned(self) -> bool:
        """실제 시스템에서 관리자(root)로 돌 때는 관리형 파일이 root 소유인지 확인한다."""
        return self.root is None and os.name == "posix" and os.geteuid() == 0

    def drop_configs(self, state: dict, names: set[str]) -> tuple[list[dict], set[str]]:
        """관리형 설정에서 이 묶음이 쓴 ``names`` 서버 항목을 지운다. (지운 항목, 못 지운 이름)."""
        removed: list[dict] = []
        failed: set[str] = set()

        def note(target: str, gone: list[str], ok: bool) -> None:
            removed.extend({"kind": "config", "server": n, "target": target} for n in gone)
            if not ok:
                failed.update(names)

        if "claude" in self.harnesses:

            def edit_json(text: str) -> tuple[str, list[str]]:
                data = json.loads(text)
                listed = data.get("mcpServers", {})
                gone = [n for n in sorted(names) if is_ours_entry(listed.get(n), n)]
                for name in gone:
                    del listed[name]
                return json.dumps(data, indent=2), gone

            logical = f"{self.claude_dir}/managed-mcp.json"
            path = self.managed_dir / "managed-mcp.json"
            note("claude", *self.edit_file(state, path, logical, edit_json))
        if "codex" in self.harnesses:
            found: set[str] = set()
            for name in ("requirements.toml", "managed_config.toml"):
                gone, ok = self.edit_file(
                    state, self.codex_managed_dir / name, f"{self.codex_dir}/{name}",
                    lambda text: drop_tables(text, names),
                )  # fmt: skip
                found.update(gone)
                note("codex", [], ok)
            if self.windows:  # Windows는 관리형 서버 정의가 사용자 설정 파일의 표식 구간에 있다
                gone, ok = self.edit_codex_block(state, self.codex_config(), names)
                found.update(gone)
                note("codex", [], ok)
            note("codex", sorted(found), True)
        return removed, failed

    def edit_codex_block(self, state: dict, path: Path, names: set[str]) -> tuple[list[str], bool]:
        if not path.exists():
            return [], True
        if self.system_mode:
            return [], True  # 사용자 설정 파일은 SYSTEM이 고치지 않는다(관리형 요구 파일은 고친다).
        try:
            current = path.read_bytes().decode("utf-8-sig")
            new, gone = drop_block_tables(current, names)
            if not gone:
                return [], True
            write_atomic(path, new.encode(), path.stat().st_mode & 0o777)
        except OSError:
            return [], False
        if sha256_bytes(current.encode()) == state.get("codex_config_sha"):
            state["codex_config_sha"] = sha256_bytes(new.encode())
        return gone, True

    def stop_launched(self, retired: set[str]) -> list[dict]:
        """실행기가 띄운 프로세스 중 폐기 서버의 것을 끈다(기록한 PID와 시작 시각이 맞을 때만)."""
        folder = self.home / STATE_REL / LAUNCHED
        removed = []
        for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                server, pid, start = str(record["server"]), int(record["pid"]), record.get("start")
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if server not in retired:
                continue
            if not start or proc_start(pid, self.windows) != start:
                path.unlink(missing_ok=True)  # 이미 끝났거나 PID가 다른 프로세스에 재사용되었다.
                continue
            if self.kill(pid):
                path.unlink(missing_ok=True)
                removed.append({"kind": "process", "server": server, "target": None})
        return removed

    def kill(self, pid: int) -> bool:
        if self.windows:
            return bool(capture(["taskkill", "/PID", str(pid), "/T", "/F"]))
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return False
        return True

    def drop_autostart(self, state: dict, retired: set[str]) -> list[dict]:
        """묶음이 서버마다 등록한 자동 시작 항목(상태 파일의 ``autostart``)을 지운다."""
        removed, kept = [], []
        for item in state.get("autostart", []):
            if item.get("server") not in retired:
                kept.append(item)
                continue
            if "task" not in item and self.system_mode:
                kept.append(item)  # 프로필 안의 파일은 SYSTEM이 지우지 않는다.
                continue
            if "task" in item:
                done = self.root is not None or bool(
                    capture(["schtasks", "/Delete", "/TN", item["task"], "/F"])
                )
                target = item["task"]
            else:
                logical = item.get("file", "")
                path = self.physical(logical)
                digest = state["files"].get(logical)
                done = bool(self.run_as_user(lambda p=str(path), d=digest: unlink_if_ours(p, d)))
                if done:
                    state["files"].pop(logical, None)
                target = path.name
            if done:
                removed.append({"kind": "autostart", "server": item["server"], "target": target})
            else:
                kept.append(item)  # 바뀐 파일은 건드리지 않는다.
        state["autostart"] = kept
        return removed

    def remediate(self, state: dict, retired: list[str]) -> list[dict]:
        """폐기 서버의 설정 항목·프로세스·자동 시작 항목을 지우고 지운 것을 상태에 남긴다.

        관리형만 한다. 이 묶음이 쓴 항목과 띄운 프로세스만 대상이며 지운 항목만 돌려준다.
        """
        if not self.managed or not retired:
            return []
        gone_names = set(retired)
        mine = set(state.get("mcp_servers", [])) & gone_names
        removed, failed = self.drop_configs(state, mine) if mine else ([], set())
        if not self.system_mode:  # 실행기 기록은 사용자 프로필에 있다
            removed += self.run_as_user(lambda: self.stop_launched(gone_names)) or []
        removed += self.drop_autostart(state, gone_names)
        state["mcp_servers"] = sorted(set(state.get("mcp_servers", [])) - (mine - failed))
        if removed:
            pending = [*state.get("pending_removed", []), *removed]
            state["pending_removed"] = pending[-MAX_PENDING:]
        if removed or mine:
            self.save_state(state)
        return removed


def report_installed(
    folder: Path,
    *,
    home: Path | None = None,
    user: str | None = None,
    if_due: bool = False,
    jitter: int = 0,
    now=time.time,
    sleep=time.sleep,
    rand=random.random,
) -> int:
    """설치된 묶음의 주기 보고. 설치되어 있지 않거나(키·상태 없음) 할 일이 없으면 조용히 0.

    관리자 권한(root·SYSTEM)으로 돌 때는 먼저 인터프리터·이 파일·설정·설치 폴더를 점검한다. root는
    사용자 홈을 읽고 쓰는 일을 모두 그 사용자 권한으로 내려간 자식 프로세스에서 하고, Windows
    SYSTEM은 사용자 프로필을 아예 만지지 않는다(키 사본·기록·폐기 서버 목록은 설치 폴더).
    """
    home = home or Path(os.path.expanduser("~"))
    target = drop_target(user)
    system = windows_system()
    if target is not None or system:
        problem = untrusted_run(folder, system)
        if problem:
            sys.stderr.write(f"MINT report refused: {problem}" + NL)
            return 1

    def run(fn):
        return as_user(*target, fn) if target else fn()

    # SYSTEM 보고기는 프로필 대신 설치 폴더의 키 사본과 기록만 쓴다.
    stamp = (folder if system else home / STATE_REL) / LAST_REPORT
    key_file = folder / REPORTER_KEY if system else home / KEY_REL

    def read_side() -> dict:
        try:
            last = float(stamp.read_text())
        except (OSError, ValueError):
            last = None
        try:
            key = key_file.read_text(encoding="utf-8").strip()
        except OSError:
            key = ""
        return {"last": last, "key": key}

    seen = run(read_side) or {}
    if if_due and not report_due(seen.get("last"), now()):
        return 0
    key = seen.get("key") or ""
    try:
        state = json.loads((folder / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    if state.get("mode") not in ("managed", "user") or not key:
        return 0
    import getpass

    sleep(jitter_delay(jitter, rand))

    def write_stamp() -> None:
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(str(now()))  # 곧바로 기록해 동시에 뜬 실행기들이 한 번만 보내게 한다.

    run(write_stamp)
    account = Account(user or getpass.getuser(), home, 0, 0)
    kit = Kit(folder, None, state["mode"] == "managed", account, False)
    kit.config["key"] = key
    kit.run_as_user = run
    kit.system_mode = system
    if not kit.report(state, "installed"):
        run(lambda: stamp.unlink(missing_ok=True))  # 닿지 못했으면 다음 기회에 다시 보낸다.
        return 1
    retired = kit.answer.get("retired")
    if isinstance(retired, list):
        names = [n for n in retired if isinstance(n, str)][:MAX_PENDING]
        run(lambda: save_retired(home, names, now(), folder if system else None))
        if kit.remediate(state, names):
            kit.report(state, "installed")  # 지운 것을 곧바로 알린다.
    return 0


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
        "action", nargs="?", default="install", choices=["install", "uninstall", "status", "report"]
    )
    parser.add_argument("--if-due", action="store_true")
    parser.add_argument("--jitter", type=int, default=0)
    parser.add_argument("--user-level", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--user")
    parser.add_argument("--home")
    parser.add_argument("--root")
    parser.add_argument("--kit", default=str(KIT))
    args = parser.parse_args(argv)
    if args.action == "report":
        return report_installed(
            Path(args.kit), if_due=args.if_due, jitter=args.jitter,
            home=Path(args.home) if args.home else None, user=args.user,
        )
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

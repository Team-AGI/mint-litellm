#!/usr/bin/env python3
"""MINT 단말 설치 묶음 설치기(표준 라이브러리만, Python 3.9 이상).

관리자 권한(root, Windows는 관리자)으로 돌면 관리형으로 설치한다: 관리형 설정(호출 전·후 훅,
실패 시 차단, 관리형 훅만 허용), 관리자 소유 경로의 에이전트, MINT 승인 목록에서 만든 관리형 MCP
목록(서버는 승인된 실행 계약을 검증하는 실행기를 거쳐 시작된다), 사용자 키 파일. 권한이 없으면
사용자 수준으로 설치하고 MINT에 「관리되지 않음」으로 보고한다. 제거는 설치가 남긴 기록으로 원래
상태를 되돌린다. 설치 상태는 MINT에 보고한다(실패해도 설치는 유지).

설치한 묶음은 설치 상태를 주기적으로 다시 보고한다: Linux는 사용자 systemd 타이머, Windows는
예약 작업이 ``report --tick`` 하위 명령(설치된 이 파일)을 자주(Linux 20초, Windows 1분; 반영을
기다리는 동안 Windows는 그 1분 안에서 20초 간격으로 세 번 돈다) 부르고,
명령이 보고 간격을 정한다: 진행 중인 검사 권한이나 방금 있었던 승인 변화, 시작 허가를 못 받은
묶음 서버가 있으면 20초, 아니면 6시간. 서버 실행기가 시작될 때도 한 번 부른다(1시간 안에 보냈으면
건너뛴다). 키가 만료되기 전 14일 안의 보고는 MINT가 키의 만료
시각을 늘려 준다.

보고 응답에는 MINT가 폐기·반려·미승인으로 보는 서버 이름 목록(``retired``)이 실린다. 관리형 설치의
보고기는 관리자 권한(Linux는 시스템 타이머, Windows는 SYSTEM 예약 작업)으로 돌며, 이 묶음이 쓴 설정
항목과 묶음 실행기가 띄운 프로세스(실행기가 기록한 PID, 시작 시각까지 맞을 때만)와 묶음이 등록한
자동 시작 항목 중 목록에 든 서버의 것만 지우고, 지운 것을 곧바로 다시 보고한다. 사용자가 만든
항목과 묶음이 띄우지 않은 프로세스는 건드리지 않는다. 사용자 수준 설치는 지우지 않고 경보만 남는다.
목록은 실행기가 읽도록 사용자 캐시에 남긴다.

대상 도구는 묶음의 ``harnesses``(claude, codex, cursor, grok)가 정한다. Cursor는 관리형
``hooks.json``(failClosed)과 사용자 ``mcp.json``, Grok Build CLI는 사용자 훅 파일과 서버 정의를
쓴다.
Codex는 관리형이면 관리자 요구 파일
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
import ntpath
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
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

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
CRLF = chr(13) + NL
REPORT_TIMEOUT = 5
# 주기 보고: 간격(시), 시작 지연의 상한(초), 서버 실행기가 시작할 때 보고를 건너뛰는 최소 간격(초)
REPORT_INTERVAL_HOURS = 6
REPORT_MIN_GAP = 3600
FAST_GAP = 20  # 승인 반영을 기다리는 동안의 보고 간격(초)
FAST_WINDOW = 600  # 반영할 일이 있다고 본 뒤 짧은 주기를 유지하는 시간(초)
FAST_FILE = "fast_until"
LAST_REPORT = "last_report"
REPORTER_KEY = "reporter.key"  # Windows 관리형: SYSTEM 보고기가 읽는 키 사본
RETIRED_FILE = "retired.json"  # 마지막 보고 응답의 폐기 서버 목록(실행기가 읽는다)
LAUNCHED = "launched"  # 실행기가 띄운 서버 프로세스의 기록
PAUSED_FILE = "paused"  # 관리 연결 중지 표지(값은 중지 세대). 실행기·훅이 장애 중에도 지킨다
OFFLINE_FILE = "offline.jsonl"  # 결정 서버에 닿지 못해 단말이 스스로 통과시킨 호출(보고 뒤 비운다)
FAILED_DIR = "start-failed"  # 실행기가 남긴 서버별 시작 실패 사유
TOOLS_DIR = "tools"  # 실행기가 본 서버별 도구 목록(이름·설명·입력 정의)
KEY_REJECTED = "key_rejected"  # 서버가 키를 거절(401·403)했다는 표시. check가 문제로 보인다.
KEY_REJECTED_TEXT = "한 줄 설치 명령을 다시 붙여 넣으십시오 (mint relink 주소)"
UPDATE_NOTE = "update_note"  # 자체 갱신 표시: 「needed」(고정 공개 키 없음) 또는 실패 사유
UPDATE_NEEDED_TEXT = "한 번만 다시 설치하면 이후 자동 갱신됩니다"
UPDATE_FILES = (("mint_agent.py", 0o755), ("mint_kit.py", 0o644))  # 이름 -> 설치 권한
MAX_REPLY = 2 * 1024 * 1024  # 보고 응답에 서명된 갱신 묶음이 실릴 수 있다
last_http_error: list[int] = []  # 마지막 보고가 받은 HTTP 오류 코드(없으면 빈 목록)
TOOLS_SENT = "tools_sent.json"  # 서버 -> 마지막으로 보고한 목록의 해시
MAX_TOOL_LISTS = 4  # 보고 한 번에 싣는 서버 수(나머지는 다음 보고)
SYSTEMD_DIR = "/etc/systemd/system"
APPARMOR_DIR = "/etc/apparmor.d"
APPARMOR_PROFILE = "mint-bwrap"
BIN_DIR = "/usr/local/bin"
SHIM = "mint"
MAX_PENDING = 256
MAX_REPORTED_SERVERS = 256  # 받는 쪽 보고 상한과 같다. 넘으면 잘라 보낸다.
UNIT = "mint-report"
TASK_NAME = "MINT Endpoint Report"
SYNC_TASK_NAME = "MINT Endpoint Sync"  # Windows 관리형: 사용자 권한으로 Codex 설정을 맞추는 작업
SYNC_INTERVAL_MINUTES = 10
NET_TASK_NAME = "MINT Endpoint Net"  # Windows 관리형: 호스트 허용 방화벽 규칙을 만드는 SYSTEM 작업
NET_DIR = "net"
NET_GROUP = "MINT sandbox "


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
            os.chmod(name, 0o600)  # 읽기 전용 모드를 입힌 뒤 실패하면 Windows는 지우지 못한다
            os.unlink(name)


_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _ed_add(a: tuple, b: tuple) -> tuple:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    p, q = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    c, d = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    e, f, g, h = q - p, d - c, d + c, q + p
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(s: int, point: tuple) -> tuple:
    out = (0, 1, 1, 0)
    while s:
        if s & 1:
            out = _ed_add(out, point)
        point = _ed_add(point, point)
        s >>= 1
    return out


def _ed_x(y: int, sign: int) -> int | None:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if (x * x - xx) % _P or (x == 0 and sign):
        return None
    return _P - x if x & 1 != sign else x


def _ed_decode(raw: bytes) -> tuple | None:
    y = int.from_bytes(raw, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _ed_x(y, sign) if y < _P else None
    return None if x is None else (x, y, 1, x * y % _P)


_ED_BASE = (lambda gy: (_ed_x(gy, 0), gy, 1, _ed_x(gy, 0) * gy % _P))(4 * pow(5, _P - 2, _P) % _P)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Ed25519 서명 검증(RFC 8032, 표준 라이브러리만). 형식이 틀리면 거짓."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _ed_decode(public), _ed_decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _Q:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _Q
    left, right = _ed_mul(s, _ED_BASE), _ed_add(r, _ed_mul(k, a))
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 and (
        left[1] * right[2] - right[1] * left[2]
    ) % _P == 0


def update_manifest(version: str, digests: dict) -> bytes:
    """서버가 서명한 글을 다시 만든다(판본과 파일 이름·해시, 이름순)."""
    lines = [f"mint-kit-update-v1 {version}"] + [f"{n} {digests[n]}" for n in sorted(digests)]
    return NL.join(lines).encode()


def update_manifest_v2(version: str, serial: int, digests: dict) -> bytes:
    """판본 번호까지 묶어 서버가 서명한 글(되돌리기 방지)."""
    lines = [f"mint-kit-update-v2 {version} {serial}"]
    lines += [f"{n} {digests[n]}" for n in sorted(digests)]
    return NL.join(lines).encode()


def verify_update(
    keys: str | list[str], update: object, min_serial: int = 0
) -> tuple[str, dict[str, bytes], int, list[str]] | str:
    """서명된 갱신 묶음을 고정 공개 키 목록으로 검증한다.

    통과하면 (판본, 파일들, 판본 번호, 갱신된 공개 키 목록), 아니면 실패 사유.
    묶음의 새 공개 키 공지는 이미 믿는 키가 서명한 것만 목록에 더한다.
    판본 번호가 ``min_serial`` 아래면 ``rollback``.
    """
    import base64
    import zlib

    try:
        files = update["files"]  # type: ignore[index]
        version = update["version"]  # type: ignore[index]
        serial = update["serial"]  # type: ignore[index]
        signature = bytes.fromhex(update["sig2"])  # type: ignore[index]
        if not isinstance(version, str) or set(files) != {n for n, _ in UPDATE_FILES}:
            return "bad_bundle"
        if type(serial) is not int:
            return "bad_bundle"
        data: dict[str, bytes] = {}
        for name, packed in files.items():
            decoder = zlib.decompressobj()
            data[name] = decoder.decompress(base64.b64decode(packed, validate=True), MAX_REPLY * 4)
            if decoder.unconsumed_tail:
                return "too_large"
        known = [keys] if isinstance(keys, str) else list(keys)
        trusted = [bytes.fromhex(k) for k in known]
        for item in update.get("keys") or ():  # type: ignore[union-attr]
            new = bytes.fromhex(item["pub"])
            notice = b"mint-kit-key-v1 " + new.hex().encode()
            if new not in trusted and any(
                ed25519_verify(k, notice, bytes.fromhex(item["sig"])) for k in trusted
            ):
                trusted.append(new)
                known.append(new.hex())
    except (TypeError, KeyError, ValueError, zlib.error, AttributeError):
        return "bad_bundle"
    digests = {name: sha256_bytes(raw) for name, raw in data.items()}
    message = update_manifest_v2(version, serial, digests)
    if not any(ed25519_verify(k, message, signature) for k in trusted):
        return "bad_signature"
    if serial < min_serial:
        return "rollback"
    for name, raw in data.items():
        try:
            compile(raw, name, "exec")
        except (SyntaxError, ValueError):
            return "bad_code"
    return version, data, serial, known


def post(url: str, key: str, payload: dict, ca_file: str | None) -> dict | None:
    """보고를 보내고 응답 본문(JSON 객체)을 돌려준다. 닿지 못했거나 거절되면 None."""
    import ssl

    last_http_error.clear()
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
                answer = json.loads(reply.read(MAX_REPLY))
            except ValueError:
                answer = None
            return answer if isinstance(answer, dict) else {"recorded": True}
    except urllib.error.HTTPError as error:
        last_http_error[:] = [error.code]
        if error.code in (401, 403):
            sys.stderr.write(KEY_REJECTED_TEXT + NL)
        return None
    except OSError:
        return None


def jitter_delay(limit: int, rand=random.random) -> int:
    """주기 보고 전에 기다릴 초(0 이상 ``limit`` 미만). 단말들이 같은 시각에 몰리지 않게 한다."""
    return int(max(limit, 0) * rand())


def report_due(last: float | None, now: float, min_gap: int = REPORT_MIN_GAP) -> bool:
    """마지막 보고 뒤 ``min_gap``초가 지났거나, 기록이 없거나, 시계가 되돌아갔으면 참."""
    return last is None or now < last or now - last >= min_gap


def report_gap(fast_until: float | None, now: float, tick: bool) -> int:
    """보고 간격(초). 표식이 살아 있으면 20초, 아니면 타이머 호출 6시간, 그 밖은 1시간."""
    if fast_until is not None and now < fast_until <= now + FAST_WINDOW:
        return FAST_GAP
    return REPORT_INTERVAL_HOURS * 3600 if tick else REPORT_MIN_GAP


def fast_marked(folder: Path, home: Path | None) -> bool:
    """짧은 주기 표식이 살아 있나(설치 폴더나 사용자 홈 어느 쪽이든)."""
    home = home or Path(os.path.expanduser("~"))
    for path in (folder / FAST_FILE, home / STATE_REL / FAST_FILE):
        try:
            if report_gap(float(path.read_text()[:64]), time.time(), True) == FAST_GAP:
                return True
        except (OSError, ValueError):
            pass
    return False


def mark_fast(folder: Path, now: float) -> None:
    try:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / FAST_FILE).write_text(str(now + FAST_WINDOW))
    except OSError:
        pass


def needs_fast(answer: dict, changed: bool, now: float) -> bool:
    """반영할 일이 남았나: 검사 권한, 방금 있었던 변화, 허가를 못 받은 묶음 서버."""
    if changed or answer.get("inspections"):
        return True
    for item in answer.get("desired") or []:
        contract = item.get("contract") if isinstance(item, dict) else None
        if isinstance(contract, dict) and isinstance(contract.get("pack"), dict) and not (
            (parse_time(item.get("permit_until")) or 0) > now
        ):
            return True
    return False


# --- 읽기 전용 인벤토리: 실행 중인 MCP 서버 프로세스와 자동 시작 항목 -----------------------
# 묶음의 실행기(``mint_agent.py run --server 이름``)로 뜬 프로세스와, 그 실행기나 MCP 서버를
# 가리키는 자동 시작 항목만 이름으로 보고한다. 아무것도 바꾸지 않으며, 읽지 못하는 곳은 건너뛴다.
LAUNCHER = re.compile(r"mint_agent\.py\"?\s+run\b.*?--server[ =]\"?([^\s\"]+)")
MCP_WORD = re.compile(r"mint_agent\.py|\bmcp\b|mcp[-_]server", re.IGNORECASE)
MAX_ITEMS = 64
MAX_TEXT = 65536
SERVER_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


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


def open_node_to_sandbox(home: Path, which=shutil.which, run=lambda c: capture(c)) -> str | None:
    """Windows에서 격리(AppContainer)된 npm 서버가 돌 수 있게 한다. SYSTEM 보고기만 부른다.

    - Node 설치 프로그램은 ``Program Files\\nodejs``의 상속을 끊어 격리가 node_modules를 못 읽는다:
      Program Files의 기본값(모든 응용 프로그램 패키지 읽기·실행)을 되돌린다.
    - Node·npm은 경로의 상위 폴더를 하나씩 lstat한다: 드라이브 루트부터 사용자 폴더·캐시 폴더까지
      「속성 읽기」만 준다(내용 읽기·목록은 아니다). 격리마다 새로 생기는 폴더(Packages 아래)와
      상태 폴더 아래는 상속으로 준다. 고친 Node 폴더를 돌려준다(Node가 없으면 None).
    """
    node = which("node")
    if not node:
        return None
    folder = os.path.dirname(os.path.realpath(node))
    run(["icacls", folder, "/grant", "*S-1-15-2-1:(OI)(CI)(RX)", "/Q"])
    base = ntpath.normpath(str(home))
    chain = [base]
    while ntpath.dirname(chain[-1]) != chain[-1]:
        chain.append(ntpath.dirname(chain[-1]))
    chain += [ntpath.join(base, rel) for rel in ("AppData", r"AppData\Local", r"AppData\Roaming",
                                                 ".cache")]
    for path in chain:
        run(["icacls", path, "/grant", "*S-1-15-2-1:(RA)", "/Q"])
    for rel in (r"AppData\Local\Packages", r".cache\mint"):
        run(["icacls", ntpath.join(base, rel), "/grant", "*S-1-15-2-1:(CI)(RA)", "/Q"])
    return folder


def retire_key(kit: Kit, old_key: str) -> bool:
    """이 PC의 옛 설치 키로 제거를 알려 그 키만 해제한다(같은 사람의 다른 PC는 그대로)."""
    new_key = kit.config.get("key")
    kit.config["key"] = old_key
    kit.replaced_by = sha256_bytes(new_key.encode()) if new_key else None  # 앱 자격을 새 키로
    import contextlib
    import io

    try:
        with contextlib.redirect_stderr(io.StringIO()):  # 옛 키 거절 안내는 여기서 뜻이 없다
            done = kit.report({"mode": "none"}, "removed")
    finally:
        kit.config["key"], kit.replaced_by = new_key, None
    if not done and set(last_http_error) & {401, 403, 404}:
        return True  # 서버가 이미 모르는 키다(해제됐거나 다른 서버의 키): 할 일이 없다
    done = done and (getattr(kit, "answer", None) or {}).get("retired") is not False
    if not done:
        print("이 PC의 옛 연결 키를 해제하지 못했습니다. 관리자 화면 「단말」에서 해제하십시오.")
    return done


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


# --- 실행기 밖에서 직접 뜬 MCP 서버 패키지 ------------------------------------------------------
# ``npx -y @범위/서버``처럼 실행기를 거치지 않고 패키지를 바로 돌리는 명령줄에서 패키지 식별자만
# 읽는다(인자·경로·사용자 이름은 보고하지 않는다: 인자에 비밀이 들 수 있다). 이름에 ``mcp``나
# ``modelcontextprotocol``이 든 패키지만 센다.
OUTSIDE_TOKEN = re.compile(r"\"([^\"]*)\"|'([^']*)'|(\S+)")
OUTSIDE_NAME = re.compile(r"^(?:@[a-z0-9._-]{1,64}/)?[a-z0-9._-]{1,64}$")
OUTSIDE_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,200}$")
OUTSIDE_MCP = re.compile(r"mcp|modelcontextprotocol", re.IGNORECASE)
OUTSIDE_FLAGS = frozenset(
    "--registry --cache --userconfig -c --call --index-url --index --default-index --with"
    " --python --with-requirements --env -e --volume -v --publish -p --name --workdir -w --user -u"
    " --network --net --entrypoint --mount --label -l --env-file --add-host --platform --memory -m"
    " --cpus --hostname -h --pull --restart --cap-add --cap-drop --security-opt --device"
    " --log-driver --tmpfs --dns --group-add --ulimit --shm-size".split()
)
# 실행기 앞에는 이런 감싸기 명령만 올 수 있다(``grep npx 파일``처럼 인자로 든 이름은 거른다).
OUTSIDE_WRAPPERS = frozenset(
    "cmd /c /k env sh bash zsh dash powershell pwsh node nodejs sudo exec start call -c -lc"
    " -command -noprofile -nologo".split()
)


def outside_tokens(command: str) -> list[str]:
    tokens: list[str] = []
    for quoted, single, plain in OUTSIDE_TOKEN.findall(command):
        word = quoted or single or plain
        # ``cmd /c "npx -y 패키지"``처럼 한 덩어리로 감싼 명령줄은 한 번 더 쪼갠다.
        if (quoted or single) and re.match(r"[^\s\\/]+\s", word.strip()):
            tokens += [a or b or c for a, b, c in OUTSIDE_TOKEN.findall(word)]
        else:
            tokens.append(word)
    return tokens


def outside_base(token: str) -> str:
    name = re.split(r"[\\/]", token)[-1].lower()
    return re.sub(r"\.(exe|cmd|bat|ps1|js|cjs|mjs)$", "", name)


def outside_positional(args: list[str], values: tuple[str, ...] = ()) -> str | None:
    """옵션과 그 값을 건너뛴 첫 위치 인자. ``values`` 옵션의 값은 따로 우선한다."""
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
        elif arg.split("=", 1)[0] in values:
            if "=" in arg:
                return arg.split("=", 1)[1]
            return args[i + 1] if i + 1 < len(args) else None
        elif arg.startswith("-"):
            skip = "=" not in arg and arg in OUTSIDE_FLAGS
        else:
            return arg
    return None


def outside_package(command: str) -> tuple[str, str] | None:
    """패키지를 바로 돌리는 명령줄의 (생태계, 패키지 이름). MCP 서버 패키지가 아니면 None."""
    tokens = outside_tokens(command)
    found: tuple[str, str] | None = None
    for i, token in enumerate(tokens):
        if i and (prev := tokens[i - 1]).lower() not in OUTSIDE_WRAPPERS:
            if outside_base(prev) not in OUTSIDE_WRAPPERS:
                break
        base, rest = outside_base(token), tokens[i + 1 :]
        if base in ("npx", "npx-cli", "bunx"):
            found = ("npm", outside_positional(rest, ("-p", "--package")) or "")
        elif base in ("npm", "pnpm", "yarn", "bun") and rest[:1] in (["exec"], ["x"], ["dlx"]):
            found = ("npm", outside_positional(rest[1:], ("-p", "--package")) or "")
        elif base == "uvx" or (base == "uv" and rest[:2] == ["tool", "run"]):
            args = rest[2:] if base == "uv" else rest
            found = ("pypi", outside_positional(args, ("--from",)) or "")
        elif base == "pipx" and rest[:1] == ["run"]:
            found = ("pypi", outside_positional(rest[1:], ("--spec",)) or "")
        elif base.startswith("python") and "-m" in rest and rest.index("-m") + 1 < len(rest):
            found = ("pypi", rest[rest.index("-m") + 1])
        elif base in ("docker", "podman") and rest[:1] == ["run"]:
            found = ("container", outside_positional(rest[1:]) or "")
        if found:
            break
    if not found:
        return None
    ecosystem, spec = found
    if ecosystem == "npm":
        at = spec.find("@", 1)
        name = (spec[:at] if at > 0 else spec).lower()
        ok = bool(OUTSIDE_NAME.match(name))
    elif ecosystem == "pypi":
        name = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", spec)
        name = name.group(0).lower() if name else ""
        ok = bool(name) and spec[len(name) :][:1] in ("", "=", "<", ">", "!", "~", "@", ";", "[")
    else:
        name = spec.split("@", 1)[0].lower()
        tail = name.rsplit("/", 1)[-1]
        name = name[: -len(tail.split(":", 1)[1]) - 1] if ":" in tail else name
        ok = bool(OUTSIDE_IMAGE.match(name))
    return (ecosystem, name) if ok and OUTSIDE_MCP.search(name) else None


def process_entries(windows: bool) -> list[tuple[int, int, str]]:
    """(PID, 부모 PID, 명령줄). 부모를 읽지 못하면 0."""
    rows: list[tuple[int, int, str]] = []
    if windows:
        out = capture(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process | ForEach-Object"
             ' { "$($_.ProcessId) $($_.ParentProcessId) $($_.CommandLine)" }']
        )  # fmt: skip
        for line in out.splitlines():
            head = line.split(" ", 2)
            if len(head) == 3 and head[0].isdigit() and head[1].isdigit():
                rows.append((int(head[0]), int(head[1]), head[2]))
        return rows
    for entry in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            command = entry.read_bytes().replace(b"\0", b" ").decode(errors="replace")
            stat = (entry.parent / "stat").read_text(errors="replace")
            parent = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        rows.append((int(entry.parent.name), parent, command))
    return rows


def scan_outside(windows: bool) -> list[dict]:
    """실행기 밖에서 직접 돈 MCP 서버 패키지: [{package, ecosystem, count}].

    실행기가 띄운 프로세스의 자손(실행기 아래의 ``npx``·``docker`` 등)은 실행기 안이라 뺀다.
    같은 패키지 명령이 부모·자식으로 겹치면(``cmd /c npx``) 하나로 센다.
    """
    entries = process_entries(windows)
    inside = {pid for pid, _, command in entries if server_of(command)}
    grew = True
    while grew:
        grew = False
        for pid, parent, _ in entries:
            if parent in inside and pid not in inside:
                inside.add(pid)
                grew = True
    matched: dict[int, tuple[str, str]] = {}
    counts: dict[tuple[str, str], int] = {}
    for pid, parent, command in entries:
        found = None if pid in inside else outside_package(command)
        if found:
            matched[pid] = found
            if matched.get(parent) != found:
                counts[found] = counts.get(found, 0) + 1
    return [
        {"package": name, "ecosystem": eco, "count": count}
        for (eco, name), count in sorted(counts.items())
    ][:MAX_ITEMS]


def win_process_rows() -> list[tuple[int, int, str, str]]:
    """Windows 프로세스 표 (PID, 부모 PID, 이미지 이름, 명령줄)."""
    out = capture(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process | ForEach-Object "
         '{ "$($_.ProcessId)|$($_.ParentProcessId)|$($_.Name)|$($_.CommandLine)" }']
    )  # fmt: skip
    rows = []
    for line in out.splitlines():
        parts = line.split("|", 3)
        if len(parts) == 4 and parts[0].isdigit() and parts[1].isdigit():
            rows.append((int(parts[0]), int(parts[1]), parts[2], parts[3]))
    return rows


def win_container_name(server: str, launcher_pid: int) -> str:
    """실행기가 서버마다 만드는 AppContainer 프로필 이름(mint_agent의 규칙과 같아야 한다)."""
    return "mint." + re.sub(r"[^A-Za-z0-9_-]", "_", server)[:32] + f".{launcher_pid}"


def win_sids():
    """(프로세스 PID -> 토큰 AppContainer SID 글자, 프로필 이름 -> SID 글자) 조회 함수 둘.

    첫째는 AppContainer가 아니면 빈 글자, 열지 못하면 None. 사용자 프로필은 건드리지 않고
    프로세스 토큰만 읽는다(PROCESS_QUERY_LIMITED_INFORMATION·TOKEN_QUERY)."""
    import ctypes
    from ctypes import wintypes as w

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv")
    vp = ctypes.c_void_p
    k32.OpenProcess.restype, k32.OpenProcess.argtypes = vp, [w.DWORD, w.BOOL, w.DWORD]
    k32.CloseHandle.argtypes = [vp]
    k32.LocalFree.argtypes = [vp]
    adv.OpenProcessToken.argtypes = [vp, w.DWORD, vp]
    adv.GetTokenInformation.argtypes = [vp, ctypes.c_int, vp, w.DWORD, vp]
    adv.ConvertSidToStringSidW.argtypes = [vp, vp]
    adv.FreeSid.argtypes = [vp]
    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [ctypes.c_wchar_p, vp]

    def text(sid) -> str:
        buf = vp()
        if not adv.ConvertSidToStringSidW(sid, ctypes.byref(buf)):
            return ""
        try:
            return ctypes.wstring_at(buf)
        finally:
            k32.LocalFree(buf)

    def of_process(pid: int) -> str | None:
        handle = k32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        token = vp()
        try:
            if not adv.OpenProcessToken(handle, 0x8, ctypes.byref(token)):
                return None
            try:
                flag, size = w.DWORD(), w.DWORD()
                if not adv.GetTokenInformation(
                    token, 29, ctypes.byref(flag), 4, ctypes.byref(size)
                ):
                    return None
                if not flag.value:
                    return ""
                buf = ctypes.create_string_buffer(512)
                if not adv.GetTokenInformation(token, 31, buf, 512, ctypes.byref(size)):
                    return None
                return text(vp.from_buffer(buf).value)
            finally:
                k32.CloseHandle(token)
        finally:
            k32.CloseHandle(handle)

    def of_name(name: str) -> str:
        sid = vp()
        if userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(sid)) != 0:
            return ""
        try:
            return text(sid)
        finally:
            adv.FreeSid(sid)

    return of_process, of_name


def classify_windows(rows, token_sid, container_sid) -> dict[str, str]:
    """서버별 실제 격리 상태. 실행기 프로세스의 직계 자식(서버)의 토큰이 그 실행기가 만든
    AppContainer이면 ``appcontainer``, 아니면 ``none``(하나라도 격리 밖이면 ``none``).
    토큰을 읽지 못한 서버는 항목이 없다."""
    launchers = {pid: name for pid, _, _, cmd in rows if (name := server_of(cmd))}
    found: dict[str, str] = {}
    for pid, parent, image, _ in rows:
        server = launchers.get(parent)
        if not server or pid in launchers or image.lower() == "conhost.exe":
            continue
        sid = token_sid(pid)
        if sid is None:
            continue
        inside = bool(sid) and sid == container_sid(win_container_name(server, parent))
        status = "appcontainer" if inside else "none"
        found[server] = "none" if "none" in (status, found.get(server)) else status
    return found


def win_start_table() -> dict[int, str]:
    """Windows: 실행 중인 모든 프로세스의 (PID -> 시작 시각 표지)를 한 번에 읽는다.

    기록마다 PowerShell을 부르면 실행기 기록이 쌓였을 때 보고가 몇 분씩 걸린다."""
    out = capture([
        "powershell", "-NoProfile", "-Command",
        "Get-Process | ForEach-Object { try { "
        '"$($_.Id) $($_.StartTime.ToFileTimeUtc())" } catch {} }',
    ])  # fmt: skip
    table: dict[int, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            table[int(parts[0])] = parts[1]
    return table


def net_filtered(programs: Path, windows: bool, start_of=None) -> set[str]:
    """Windows: 호스트 허용 방화벽 규칙이 걸려 있고 그 실행기가 아직 도는 서버 이름들."""
    found: set[str] = set()
    folder = programs / NET_DIR / "rules"
    for path in sorted(folder.glob("*.json")) if windows and folder.is_dir() else []:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if (start_of or proc_start)(int(record["pid"]), windows) == str(record["start"]):
                found.add(str(record["server"]))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return found


def windows_sandbox_status() -> dict[str, str]:
    """운영체제가 보는 서버별 격리 상태(기록 파일을 믿지 않는다). 조회하지 못하면 빈 값."""
    try:
        return classify_windows(win_process_rows(), *win_sids())
    except Exception:
        return {}


def with_sandbox(
    processes: list[dict],
    home: Path,
    windows: bool,
    read_records: bool = True,
    observed: dict[str, str] | None = None,
    filtered: set[str] | None = None,
    start_of=None,
) -> list[dict]:
    """프로세스 항목에 서버별 격리 상태를 더한다(실행기가 남긴 기록 중 아직 살아 있는 것만).

    ``bwrap``·``appcontainer``는 기록된 모든 프로세스가 격리 안, ``none``은 하나라도 격리 없이.
    Windows에서는 운영체제가 보는 값(``observed``: 서버 프로세스 토큰)이 기록보다 앞선다.
    기록이 없고 토큰도 읽지 못한 서버는 Linux에서는 비워 두고 Windows에서는 ``unsupported``이다
    (관리자 계정 보고기는 사용자 프로필의 기록을 읽지 않는다: ``read_records``).
    호스트 허용 목록 서버는 실행기가 센 거절 수 ``egress_refused``도 더하고, Windows에서 그 목록을
    거르지 못한 채 도는 서버는 ``egress_unfiltered``를 더한다(관리자 계정 보고기는 기록을 읽지
    않으므로 이 값을 내지 못한다). 방화벽 규칙이 걸린 서버(``filtered``: 설치 폴더의 규칙 기록,
    또는 실행기 기록)는 ``egress_filtered``를 더한다.
    """
    seen: dict[str, str] = {}
    refused: dict[str, int] = {}
    unfiltered: set[str] = set()
    firewalled: set[str] = set(filtered or ())
    folder = home / STATE_REL / LAUNCHED
    for path in sorted(folder.glob("*.json")) if read_records and folder.is_dir() else []:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            server, pid, start = str(record["server"]), int(record["pid"]), record.get("start")
            status = record.get("sandbox")
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if status in ("bwrap", "appcontainer", "none") and start:
            if (start_of or proc_start)(pid, windows) == start:
                seen[server] = "none" if "none" in (status, seen.get(server)) else status
                if isinstance(record.get("egress_refused"), int) and record["egress_refused"] >= 0:
                    refused[server] = refused.get(server, 0) + record["egress_refused"]
                if record.get("egress_unfiltered") is True:
                    unfiltered.add(server)
                if record.get("egress_filtered") is True:
                    firewalled.add(server)
    for item in processes:
        status = (
            (observed or {}).get(item["server"])
            or seen.get(item["server"])
            or ("unsupported" if windows else None)
        )
        if status:
            item["sandbox"] = status
        if item["server"] in refused:  # 호스트 허용 목록 서버가 거절당한 접속 수
            item["egress_refused"] = refused[item["server"]]
        if item["server"] in unfiltered:  # Windows: 호스트 허용 목록을 거르지 못함
            item["egress_unfiltered"] = True
        elif item["server"] in firewalled:  # Windows: 방화벽 규칙이 호스트 허용 목록을 집행함
            item["egress_filtered"] = True
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


# 실행기의 검증과 로컬 MCP 서버의 초기화가 끝날 시간을 확보한다.
STARTUP_WAIT_SECONDS = 120


def claude_allow(names) -> list[str]:
    """Claude Code 도구 확인 자동 허용 규칙(MINT가 관리하는 서버만)."""
    return [f"mcp__{re.sub(r'[^A-Za-z0-9_-]', '_', n)}__*" for n in sorted(names)]


def codex_servers(mcp: dict) -> str:
    return "".join(
        f"{NL}[mcp_servers.{toml(name)}]{NL}command = {toml(item['command'])}{NL}"
        f"args = {toml(item['args'])}{NL}"
        f"startup_timeout_sec = {STARTUP_WAIT_SECONDS}{NL}"
        f"tool_timeout_sec = {TOOL_WAIT_SECONDS}{NL}"
        f'default_tools_approval_mode = "approve"{NL}'
        for name, item in sorted(mcp.items())
    )


# 판정 대상: MCP 도구와 하네스 내장 도구. Codex는 셸(Bash)과 apply_patch(파일 편집)에만 훅이
# 걸리고 웹 검색 같은 호스팅 도구에는 걸리지 않는다.
CLAUDE_MATCHER = "mcp__.*|Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit|WebFetch|WebSearch"
CODEX_MATCHER = "^(mcp__.*|Bash|apply_patch)$"


def codex_hooks(commands: dict) -> str:
    return "".join(
        f"{NL}[[hooks.{event}]]{NL}matcher = {toml(CODEX_MATCHER)}{NL}{NL}"
        f'[[hooks.{event}.hooks]]{NL}'
        f'type = "command"{NL}command = {toml(line)}{NL}timeout = {timeout}{NL}'
        for event, (line, timeout) in commands.items()
    )


def codex_identities(mcp: dict) -> str:
    return "".join(
        f"{NL}[mcp_servers.{toml(name)}]{NL}identity = {{ command = {toml(item['command'])} }}{NL}"
        for name, item in sorted(mcp.items())
    )


# 게이트웨이는 승인을 기다리는 호출을 최대 300초(MINT_APPROVAL_HOLD_SECONDS 상한) 붙잡는다.
# 하네스의 도구 시간 제한이 그보다 짧으면 승인되기 전에 하네스가 호출을 끊는다.
TOOL_WAIT_SECONDS = 330


def codex_gateway_server(gateway: dict) -> str:
    """Codex의 게이트웨이 서버 표(주소와, 사용자에 결속된 MCP 전용 키를 담은 인증 머리글)."""
    bearer = toml("Bearer " + gateway["key"])
    return (
        f"{NL}[mcp_servers.{toml(gateway['name'])}]{NL}url = {toml(gateway['url'])}{NL}"
        f"http_headers = {{ Authorization = {bearer} }}{NL}"
        f"tool_timeout_sec = {TOOL_WAIT_SECONDS}{NL}"
        f'default_tools_approval_mode = "approve"{NL}'
    )


def codex_gateway_identity(gateway: dict) -> str:
    return (
        f"{NL}[mcp_servers.{toml(gateway['name'])}]{NL}"
        f"identity = {{ url = {toml(gateway['url'])} }}{NL}"
    )


def codex_requirements(
    mcp: dict, hooks: dict, programs: str, windows: bool, gateway: dict | None = None
) -> str:
    """Codex 관리자 요구 파일. 서버 표가 없으면 제한이 없고 비어 있으면 모두 꺼지므로 항상 둔다."""
    # ponytail: 서버 신원이 실행 명령(python)뿐이라 같은 python을 쓰는 다른 서버도 통과한다.
    # 서버마다 실행 래퍼를 두면 좁아진다.
    identities = codex_identities(mcp) + (codex_gateway_identity(gateway) if gateway else "")
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


def pack_consistent(item: dict, contract: dict) -> bool:
    """묶음 항목이면 응답의 묶음 해시가 계약의 것과 같아야 한다(판 1 항목은 해당 없음)."""
    pack = contract.get("pack")
    if pack is None and item.get("pack_sha256") is None:
        return True
    digest = item.get("pack_sha256")
    return (
        isinstance(pack, dict) and isinstance(digest, str) and pack.get("sha256") == digest
        and bool(SHA256_HEX.match(digest))
    )


def contract_version(contract: dict) -> str:
    """계약 내용의 판본(MINT가 응답에 싣는 값과 같은 계산)."""
    text = json.dumps(contract, sort_keys=True, separators=(",", ":"))
    return sha256_bytes(text.encode())


def codex_table(text: str, name: str) -> str | None:
    """``[mcp_servers."이름"]`` 표의 본문(표 머리 다음 줄부터 다음 표 머리 앞까지). 없으면 None."""
    header = f"[mcp_servers.{toml(name)}]"
    body: list[str] | None = None
    for line in text.splitlines(keepends=True):
        bare = line.strip()
        if body is not None and (bare.startswith("[") or bare in (BEGIN, END)):
            break
        if body is not None:
            body.append(line)
        elif bare == header:
            body = []
    return None if body is None else "".join(body)


def codex_table_is_ours(body: str, name: str) -> bool:
    """표가 이 묶음의 실행기로 ``name`` 서버를 시작하는 것인가(사용자가 쓴 표는 아니다)."""
    return AGENT in body and f'"--server", {toml(name)}' in body


def put_codex_tables(text: str, mcp: dict, identity: bool) -> tuple[str, list[str]]:
    """서버 표를 더하거나 바꾼다. 이름이 같은 표가 이 묶음의 것이 아니면 건드리지 않는다.

    ``identity``이면 요구 파일의 신원 표(실행 명령만 적는다)이고, 이미 있으면 그대로 둔다.
    """
    done = []
    for name, item in sorted(mcp.items()):
        body = codex_table(text, name)
        if identity and body is not None:
            continue
        if body is not None and not codex_table_is_ours(body, name):
            continue
        if body is not None:
            text = drop_tables(text, {name})[0]
        if text and not text.endswith(NL):
            text += NL
        text += (codex_identities if identity else codex_servers)({name: item})
        done.append(name)
    return text, done


def put_block_tables(text: str, mcp: dict) -> tuple[str, list[str]]:
    """사용자 설정 파일의 표식 구간 안에서만 서버 표를 더하거나 바꾼다(구간 밖은 그대로)."""
    found = re.search(rf"{re.escape(BEGIN)}.*?{re.escape(END)}", text, flags=re.S)
    if found is None:
        return text, []
    body, done = put_codex_tables(found.group(0)[: -len(END)], mcp, False)
    return text[: found.start()] + body + END + text[found.end() :], done


APPROVE_LINE = 'default_tools_approval_mode = "approve"'
_SERVER_APPROVAL = re.compile(r"\s*default_tools_approval_mode\s*=")
_TOOL_APPROVAL = re.compile(r'^(\s*approval_mode\s*=\s*)"(?!approve")[^"]*"')


def approve_tables(text: str, names, servers: bool = True) -> str:
    """``names`` 서버 표에 서버 단위 자동 허용을 보장하고, 그 서버의 도구별 확인 설정은 허용으로
    맞춘다(도구별 값이 서버 값보다 앞서 일부 도구만 묻는 일을 없앤다). 다른 줄은 그대로 둔다.
    ``servers``가 거짓이면 도구별 설정만 고친다(사용자가 쓴 서버 표는 건드리지 않는다)."""
    heads = {f"[mcp_servers.{q}]" for n in names for q in (toml(n), n)}
    tools = tuple(f"[mcp_servers.{q}.tools." for n in names for q in (toml(n), n))
    eol = "\r\n" if "\r\n" in text else NL
    parts: list[tuple[str | None, list[str]]] = []
    for line in text.splitlines(keepends=True):
        bare = line.strip()
        if bare.startswith("[") or bare in (BEGIN, END):
            parts.append((bare, [line]))
        elif parts:
            parts[-1][1].append(line)
        else:
            parts.append((None, [line]))
    out: list[str] = []
    for head, lines in parts:
        if head in heads and servers:
            lines = [ln for ln in lines if not _SERVER_APPROVAL.match(ln)]
            last = max((i for i, ln in enumerate(lines) if ln.strip()), default=0)
            if not lines[last].endswith(("\n", "\r")):
                lines[last] += eol
            lines.insert(last + 1, APPROVE_LINE + eol)
        elif head and head.startswith(tools):
            lines = [_TOOL_APPROVAL.sub(r'\1"approve"', ln) for ln in lines]
        out += lines
    return "".join(out)


def approve_user_config(text: str, names) -> str:
    """사용자 설정: 표식 구간 안은 전부, 구간 밖은 이 서버들의 도구별 확인 설정만 맞춘다."""
    found = re.search(rf"{re.escape(BEGIN)}.*?{re.escape(END)}", text, flags=re.S)
    if found is None:
        return approve_tables(text, names, servers=False)
    return (
        approve_tables(text[: found.start()], names, servers=False)
        + approve_tables(found.group(0), names)
        + approve_tables(text[found.end() :], names, servers=False)
    )


# --- Cursor·Grok Build CLI: 훅 파일·MCP 설정 조각 ---

CURSOR_DIR = "/etc/cursor"
GROK_DIR = "/etc/grok"
CURSOR_EVENT = "beforeMCPExecution"


def cursor_hooks_text(existing: str | None, line: str, timeout: int) -> str:
    """Cursor 훅 파일: 기존 내용은 두고 MINT 항목만 더한다. 기본이 fail-open이라 failClosed."""
    try:
        data = json.loads(existing) if existing else {}
    except ValueError:
        data = {}
    data = data if isinstance(data, dict) else {}
    data["version"] = 1
    hooks = data["hooks"] if isinstance(data.get("hooks"), dict) else {}
    data["hooks"] = hooks
    kept = [
        h for h in hooks.get(CURSOR_EVENT) or []
        if not (isinstance(h, dict) and AGENT in str(h.get("command")))
    ]
    kept.append({"command": line, "timeout": timeout, "failClosed": True})
    hooks[CURSOR_EVENT] = kept
    return json.dumps(data, indent=2, ensure_ascii=False) + NL


def grok_hooks_text(line: str, timeout: int) -> str:
    """Grok Build CLI 사용자 훅 파일(``~/.grok/hooks/*.json``). 도구 이름 필터는 두지 않는다."""
    hook = {"type": "command", "command": line, "timeout": timeout}
    return json.dumps({"hooks": {"PreToolUse": [{"hooks": [hook]}]}}, indent=2) + NL


def cursor_mcp_entries(mcp: dict, gateway: dict | None) -> dict:
    found = {n: {"command": i["command"], "args": i["args"]} for n, i in mcp.items()}
    if gateway:
        found[gateway["name"]] = {
            "url": gateway["url"], "headers": {"Authorization": "Bearer " + gateway["key"]},
        }
    return found


def grok_gateway_server(gateway: dict) -> str:
    """Grok의 게이트웨이 서버 표(주소와 인증 머리글)."""
    bearer = toml("Bearer " + gateway["key"])
    return (
        f"{NL}[mcp_servers.{toml(gateway['name'])}]{NL}url = {toml(gateway['url'])}{NL}"
        f"headers = {{ Authorization = {bearer} }}{NL}"
    )


# --- 단말의 하네스 설정에서 찾은, 이 묶음이 관리하지 않는 MCP 항목(자격 증명이 없는 값만) ---

HOST_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
PACKAGE_NAME = re.compile(r"^(@[a-z0-9._-]{1,64}/)?[a-z0-9._-]{1,64}(@[A-Za-z0-9._-]{1,32})?$")
RUNNERS = ("npx", "uvx", "bunx", "pipx")
MAX_CONFIG = 8 << 20


def local_mcp_item(harness: str, name: object, entry: object) -> dict | None:
    """설정 항목 하나에서 보고할 값만 뽑는다: 이름, 전송 종류, 실행 파일 이름이나 호스트.

    인자·환경 변수·헤더·URL의 사용자 정보와 경로·질의는 읽지 않는다(토큰이 들어갈 자리다).
    이 묶음의 실행기로 시작하는 항목(관리 대상)은 건너뛴다.
    """
    if not isinstance(name, str) or not name or not isinstance(entry, dict):
        return None
    raw = entry.get("args")
    args = [a for a in raw if isinstance(a, str)] if isinstance(raw, list) else []
    if any(a.replace("\\", "/").endswith("/" + AGENT) for a in args):
        return None
    package = None
    url = next((entry[k] for k in URL_FIELDS if isinstance(entry.get(k), str) and entry[k]), None)
    command = entry.get("command")
    if isinstance(url, str) and url:
        try:
            host = urllib.parse.urlsplit(url).hostname or ""
        except ValueError:
            host = ""
        kind = "sse" if str(entry.get("type")).lower() == "sse" else "http"
        target = host if HOST_NAME.match(host) else "unknown"
    elif isinstance(command, str) and command.strip():
        base = command.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
        base = re.sub(r"\.(exe|cmd|bat)$", "", base)
        kind, target = "stdio", (base if HOST_NAME.match(base) else "unknown")
        if target in RUNNERS:
            first = next((a for a in args if not a.startswith("-")), "")
            package = first if PACKAGE_NAME.match(first) else None
    else:
        return None
    return {"harness": harness, "name": name[:128], "kind": kind, "target": target,
            "package": package}  # fmt: skip


def managed_names(state: dict) -> set[str]:
    return {n for n in [*(state.get("mcp_servers") or []), state.get("gateway"),
                        state.get("user_gateway")] if isinstance(n, str)}


def scan_local_mcp(home: Path, managed: object = ()) -> list[dict]:
    """홈의 AI 도구 설정에 있는, 관리 대상이 아닌 MCP 항목. 읽지 못하면 건너뛴다."""
    return scan_mcp(home, managed)["local_mcp"]


def is_agent_entry(entry: object) -> bool:
    """이 묶음의 실행기로 시작하는 항목인가(서버 이름은 보지 않는다)."""
    raw = entry.get("args") if isinstance(entry, dict) else None
    return isinstance(raw, list) and any(
        isinstance(a, str) and a.replace("\\", "/").endswith("/" + AGENT) for a in raw
    )


def scan_mcp(home: Path, managed: object = (), windows: bool | None = None) -> dict:
    """AI 도구 설정을 한 번 읽어 관리 대상 밖 MCP 항목, 도구별 항목 수(전체·관리 밖), 평문 키,
    읽지 못한 도구를 돌려준다. 키는 종류와 자리만 담고 값은 담지 않는다."""
    found: dict[tuple, dict] = {}
    counts: dict[str, list[int]] = {}
    keys: dict[tuple, dict] = {}
    errors: list[str] = []
    excluded = {"litellm_gateway", *(n for n in managed if isinstance(n, str))}

    def add(harness: str, servers: object) -> None:
        for name, entry in (servers.items() if isinstance(servers, dict) else ()):
            count = counts.setdefault(harness, [0, 0])
            count[0] += 1
            if name in excluded or is_agent_entry(entry) or not isinstance(name, str):
                continue
            count[1] += 1
            for item in plaintext_keys(harness, name, entry):
                keys.setdefault(tuple(item.values()), item)
            item = local_mcp_item(harness, name, entry)
            if item:
                found.setdefault(tuple(item.values()), item)

    read_mcp_sources(home, add, errors, windows)
    return {
        "local_mcp": sorted(found.values(), key=lambda i: (i["harness"], i["name"]))[:MAX_ITEMS],
        "counts": counts,
        "plaintext_keys": list(keys.values())[:MAX_KEYS],
        "scan_errors": sorted(set(errors)),
    }


# --- 훅이 없는 AI 도구 ---------------------------------------------------------------------------
# 이 도구들은 호출 전 훅을 관리형으로 둘 수 없다. 설정의 로컬 서버를 실행기 항목(--mediate)으로
# 써서 도구 호출을 서버에 보내기 전에 판정한다(로컬 서버만 판정). 원격 서버는 판정하지 못한다.
HOOK_CLIENTS = ("claude", "codex", "cursor", "grok")
MEDIATED_CLIENTS = (
    "gemini", "antigravity", "windsurf", "vscode", "claude_desktop", "cline", "lmstudio",
)  # fmt: skip
CLIENT_FILE = "clients.json"  # 사용자 캐시: 도구별로 이 묶음이 쓴 서버 이름·만든 파일 여부·쓴 시각
CLIENTS_DIR = "clients"  # 사용자 캐시: 실행기가 남긴 도구별 마지막 시작 시각
URL_FIELDS = ("url", "serverUrl", "httpUrl")
MAX_KEYS = 32
KEY_PATTERNS = (
    ("anthropic", re.compile(r"sk-(?:ant)-[A-Za-z0-9_-]{20,}")),
    ("openai", re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("google", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("github", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}")),
    ("aws", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack", re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}")),
    ("huggingface", re.compile(r"hf_[A-Za-z0-9]{30,}")),
)
KEY_FIELD = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTHORIZATION", re.IGNORECASE)


def key_kind(value: object, field: str = "") -> str | None:
    """값이 그대로 적힌 API 키로 보이면 종류. 변수 참조(``${...}``·``$X``·``%X%``)는 아니다."""
    if not isinstance(value, str) or len(value) < 16:
        return None
    for kind, pattern in KEY_PATTERNS:
        if pattern.search(value):
            return kind
    reference = "${" in value or value.startswith(("$", "%", "env:"))
    if field and KEY_FIELD.search(field) and len(value) >= 20 and not reference:
        return "generic"
    return None


def plaintext_keys(client: str, name: str, entry: object) -> list[dict]:
    """설정 항목 하나에 그대로 적힌 키의 종류와 자리(환경 변수·헤더·인자·주소). 값은 담지 않는다."""
    if not isinstance(entry, dict):
        return []
    found: dict[tuple, dict] = {}

    def check(where: str, value: object, field: str = "") -> None:
        kind = key_kind(value, field)
        if kind:
            item = {"client": client, "entry": name[:128], "kind": kind, "where": where}
            found.setdefault((where, kind), item)

    for where, table in (("env", entry.get("env")), ("headers", entry.get("headers"))):
        for field, value in table.items() if isinstance(table, dict) else ():
            check(where, value, str(field))
    for value in entry.get("args") if isinstance(entry.get("args"), list) else ():
        check("args", value)
    for field in URL_FIELDS:
        check("url", entry.get(field))
    return list(found.values())


def app_data(home: Path, windows: bool) -> Path:
    """사용자 앱 설정 폴더(Windows Roaming, macOS Application Support, Linux ~/.config)."""
    if windows:
        return home / "AppData/Roaming"
    if sys.platform == "darwin":
        return home / "Library/Application Support"
    return home / ".config"


def client_sources(home: Path, windows: bool) -> list[tuple[str, Path, str, Path]]:
    """(도구, 설정 파일, 서버 표 이름, 설치 표지). 표지가 있으면 그 도구가 이 PC에 있다고 본다.
    같은 도구가 두 번 나오면(판본마다 위치가 다르다) 읽기는 둘 다, 쓰기는 표지가 있는 앞의 것."""
    data, gemini = app_data(home, windows), home / ".gemini"
    code, desktop = data / "Code/User", data / "Claude"
    cline, surf = code / "globalStorage/saoudrizwan.claude-dev", home / ".codeium/windsurf"
    table = "mcpServers"
    return [
        ("gemini", gemini / "settings.json", table, gemini / "settings.json"),
        # Antigravity는 판본이 오르며 antigravity/에서 config/로 옮겼다(새 위치를 먼저 쓴다).
        ("antigravity", gemini / "config/mcp_config.json", table, gemini / "config"),
        ("antigravity", gemini / "antigravity/mcp_config.json", table, gemini / "antigravity"),
        ("windsurf", surf / "mcp_config.json", table, surf),
        ("vscode", code / "mcp.json", "servers", code),
        ("cline", cline / "settings/cline_mcp_settings.json", table, cline),
        ("claude_desktop", desktop / "claude_desktop_config.json", table, desktop),
        ("lmstudio", home / ".lmstudio/mcp.json", table, home / ".lmstudio"),
    ]


def client_entry(client: str, python: str, args: list[str]) -> dict:
    """훅 없는 도구의 설정에 쓰는 실행기 항목. Gemini CLI는 승인 서버의 확인 창을 끈다(FM-11)."""
    entry: dict = {"command": python, "args": args}
    if client == "vscode":
        entry = {"type": "stdio", **entry}
    if client == "gemini":
        entry["trust"] = True
    return entry


def read_client_record(home: Path) -> dict:
    try:
        record = json.loads((home / STATE_REL / CLIENT_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return record if isinstance(record, dict) else {}


def client_started(home: Path, client: str) -> float:
    try:
        return float((home / STATE_REL / CLIENTS_DIR / client).read_text(encoding="utf-8")[:32])
    except (OSError, ValueError):
        return 0.0


def ai_client_rows(
    home: Path, windows: bool, harnesses, scan: dict, record: dict
) -> list[dict]:
    """도구별 보장(호출 전 판정·로컬 서버만 판정·관리되지 않음·검사 실패). 이 PC에 있는 것만."""
    counts, errors = scan.get("counts") or {}, set(scan.get("scan_errors") or ())
    present = {c for c, _, _, marker in client_sources(home, windows) if marker.exists()}
    rows = []
    for client in (*HOOK_CLIENTS, *MEDIATED_CLIENTS):
        total, unmanaged = counts.get(client, [0, 0])
        hooked = client in HOOK_CLIENTS and client in harnesses
        if not (hooked or client in counts or client in errors or client in present):
            continue
        mine = record.get(client) if isinstance(record.get(client), dict) else {}
        if hooked:
            connection, coverage = "hook", "pre_call"
        elif client in errors:
            connection, coverage = "failed", "scan_failed"
        elif mine.get("failed"):
            connection, coverage = "failed", "unmanaged"
        elif "names" in mine:
            connection, coverage = "mediated", "local_only"
        else:
            connection, coverage = "none", "unmanaged"
        restart = bool(
            connection == "mediated" and mine.get("names")
            and float(mine.get("written") or 0) > client_started(home, client)
        )  # fmt: skip
        rows.append({
            "client": client, "version": None, "connection": connection, "coverage": coverage,
            "servers": min(total, 256), "unmanaged": min(unmanaged, 256), "restart_needed": restart,
        })  # fmt: skip
    return rows[:16]


def read_offline(home: Path) -> list[dict]:
    """장애 중 실행기·훅이 스스로 통과시킨 호출을 (서버, 도구, AI 도구) 단위로 묶는다.

    기록 파일은 이름을 바꿔 보낼 몫(``.sending``)에 옮긴 뒤 읽는다. 그 사이 새로 쌓이는 호출은 새
    파일로 간다. 보고가 성공하면 보낼 몫을 지우고, 실패하면 다음 보고에 다시 싣는다.
    """
    groups: dict[tuple, dict] = {}
    folder = home / STATE_REL
    sending = folder / (OFFLINE_FILE + ".sending")
    try:
        moving = folder / f"{OFFLINE_FILE}.{os.getpid()}"
        os.replace(folder / OFFLINE_FILE, moving)
        with open(sending, "ab") as handle:
            handle.write(moving.read_bytes())
        moving.unlink()
    except OSError:
        pass
    try:
        lines = sending.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines[-2000:]:
        try:
            item = json.loads(line)
            key = (str(item["server"])[:128], str(item["tool"])[:128], str(item["harness"])[:32])
            at = str(item["at"])
        except (ValueError, KeyError, TypeError):
            continue
        if not all(key):
            continue
        group = groups.setdefault(key, {"server": key[0], "tool": key[1], "harness": key[2],
                                        "at": at, "count": 0})  # fmt: skip
        group["count"] = min(group["count"] + 1, 10_000)
    return list(groups.values())[:64]


def read_paused_gen(folder: Path) -> int | None:
    try:
        return int((folder / PAUSED_FILE).read_text(encoding="utf-8").strip() or 0)
    except (OSError, ValueError):
        return None


def set_paused(folder: Path, paused: bool, gen: int) -> None:
    """관리 연결 중지 표지를 두거나 지운다(실행기·훅이 장애 중에도 지키는 명시 차단)."""
    path = folder / PAUSED_FILE
    try:
        if paused:
            folder.mkdir(parents=True, exist_ok=True)
            path.write_text(str(gen), encoding="utf-8")
        else:
            path.unlink(missing_ok=True)
    except OSError:
        pass


def load_settings(path: Path) -> object:
    """설정 파일 JSON. 도구가 빈 파일로 만들어 두기도 하므로 빈 파일은 빈 설정이다."""
    text = path.read_text(encoding="utf-8-sig")
    return json.loads(text) if text.strip() else {}


def read_servers(path: Path, table: str) -> dict | None:
    """설정 파일의 서버 표. 파일이 없으면 None, 읽거나 해석하지 못하면 예외."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return None
    if size > MAX_CONFIG:
        raise ValueError("settings file is too large")
    data = load_settings(path)
    if not isinstance(data, dict):
        raise ValueError("settings file is not an object")
    servers = data.get(table)
    return servers if isinstance(servers, dict) else {}


def read_mcp_sources(
    home: Path, add, errors: list | None = None, windows: bool | None = None
) -> None:
    """AI 도구 설정 파일의 서버 표를 ``add(도구, 표)``로 넘긴다. 없는 파일은 건너뛰고, 있는데 읽지
    못한 훅 없는 도구는 ``errors``에 담는다."""
    try:
        if (home / ".claude.json").stat().st_size <= MAX_CONFIG:
            data = json.loads((home / ".claude.json").read_text(encoding="utf-8-sig"))
            add("claude", data.get("mcpServers"))
            for project in (data.get("projects") or {}).values():
                add("claude", project.get("mcpServers") if isinstance(project, dict) else None)
    except (OSError, ValueError, AttributeError):
        pass
    try:
        import tomllib

        path = home / ".codex/config.toml"
        if path.stat().st_size <= MAX_CONFIG:
            text = strip_block(path.read_bytes().decode("utf-8-sig"))
            add("codex", tomllib.loads(text).get("mcp_servers"))
    except (ImportError, OSError, ValueError):
        pass  # tomllib은 Python 3.11부터라 이전 판본에서는 Codex 설정을 읽지 않는다.
    scan_cursor_grok(home, add)
    for client, path, table, _ in client_sources(
        home, sys.platform == "win32" if windows is None else windows
    ):
        try:
            servers = read_servers(path, table)
        except (OSError, ValueError):
            if errors is not None:
                errors.append(client)
            continue
        if servers is not None:
            add(client, servers)


def scan_cursor_grok(home: Path, add) -> None:
    """Cursor(``~/.cursor/mcp.json``)와 Grok Build CLI(``~/.grok/config.toml``)의 MCP 항목."""
    try:
        path = home / ".cursor/mcp.json"
        if path.stat().st_size <= MAX_CONFIG:
            add("cursor", json.loads(path.read_text(encoding="utf-8-sig")).get("mcpServers"))
    except (OSError, ValueError, AttributeError):
        pass
    try:
        import tomllib

        path = home / ".grok/config.toml"
        if path.stat().st_size <= MAX_CONFIG:
            add("grok", tomllib.loads(strip_block(path.read_bytes().decode("utf-8-sig")))
                .get("mcp_servers"))
    except (ImportError, OSError, ValueError):
        pass


def scan_tool_lists(home: Path) -> list[dict]:
    """실행기가 남긴 도구 목록 중 마지막 보고 뒤 바뀐 것(사용자 홈을 읽으므로 사용자 권한으로)."""
    folder = home / STATE_REL / TOOLS_DIR
    try:
        sent = json.loads((home / STATE_REL / TOOLS_SENT).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        sent = {}
    items: list[dict] = []
    try:
        files = sorted(folder.glob("*.json"))
    except OSError:
        return items
    for path in files:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            server, digest, tools = doc["server"], doc["sha256"], doc["tools"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if (
            isinstance(server, str) and isinstance(digest, str) and isinstance(tools, list)
            and sent.get(server) != digest
        ):
            items.append({"server": server, "sha256": digest, "tools": tools,
                          "truncated": bool(doc.get("truncated"))})
        if len(items) >= MAX_TOOL_LISTS:
            break
    return items


def scan_start_failures(home: Path) -> list[dict]:
    """실행기가 남긴 시작 실패(서버 이름·짧은 사유). 도구 목록을 받으면 실행기가 지운다."""
    items: list[dict] = []
    try:
        files = sorted((home / STATE_REL / FAILED_DIR).glob("*.json"))
    except OSError:
        return items
    for path in files[:MAX_TOOL_LISTS]:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            server, reason = doc["server"], doc["reason"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if isinstance(server, str) and isinstance(reason, str):
            items.append({"server": server, "reason": reason[:80]})
    return items


def mark_tool_lists_sent(home: Path, items: list[dict]) -> None:
    """보고한 목록의 해시를 남겨 같은 목록을 다시 보내지 않게 한다."""
    path = home / STATE_REL / TOOLS_SENT
    try:
        sent = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        sent = {}
    sent.update({i["server"]: i["sha256"] for i in items})
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sent), encoding="utf-8")
    except OSError:
        pass


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
CREATE_RIGHTS = {"WD", "AD"}  # 폴더 안에 파일·하위 폴더만 만들 수 있는 권리


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
    for depth, item in enumerate(chain_of(path.replace("/", "\\"))):
        listing = run(["icacls", item])
        if not listing.strip():
            return f"{item} cannot be inspected"
        for line in listing.splitlines():
            if not any(group in line.lower() for group in OPEN_GROUPS):
                continue
            rights = {t for part in re.findall(r"\(([^)]*)\)", line) for t in part.split(",")}
            if "IO" in rights:
                continue  # 상속 전용 항목은 이 폴더 자신에게는 적용되지 않는다.
            if depth:
                rights -= CREATE_RIGHTS  # 상위 폴더에 새로 만드는 항목은 있던 경로를 못 바꾼다.
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


def prefix_clash(gateway: str, servers) -> str | None:
    """하네스의 도구 이름 접두가 게이트웨이와 겹치는 승인 서버 이름(없으면 None)."""

    def prefix(name: str) -> str:
        return "mcp__" + re.sub(r"[^a-zA-Z0-9_]", "_", name).lower() + "__"

    return next((n for n in sorted(servers) if prefix(n).startswith(prefix(gateway))), None)


def bwrap_probe(bwrap: str) -> bool:
    """bubblewrap이 이 계정으로 실제 격리를 만들 수 있는가(사용자 이름공간이 막혀 있으면 거짓)."""
    probe = [bwrap, "--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--", "/bin/true"]
    try:
        done = subprocess.run(probe, capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def apparmor_blocks_userns() -> bool:
    """AppArmor가 권한 없는 사용자의 사용자 이름공간을 막는 설정(Ubuntu 24.04 기본)인가."""
    try:
        text = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text()
    except OSError:
        return False
    return text.strip() == "1"


def apparmor_profile(bwrap: str) -> str:
    """bubblewrap에만 사용자 이름공간을 허용하는 AppArmor 프로필(다른 프로그램은 그대로 막힌다)."""
    return f"profile {APPARMOR_PROFILE} {bwrap} flags=(unconfined) {{{NL}  userns,{NL}}}{NL}"


def codex_hook_trust(text: str) -> str | None:
    """사용자 Codex 설정에서 이 묶음의 훅을 Codex가 신뢰했는지 추정한다. 묶음의 훅이 없으면 None.

    Codex는 훅을 신뢰하기 전에는 실행하지 않고, 신뢰하면 설정의 ``[hooks.state...]`` 표에
    ``trusted_hash``를 남긴다. 표의 이름을 몰라 어떤 훅이든 신뢰 기록이 있으면 신뢰로 본다.
    """
    if BEGIN not in text or "[[hooks." not in text:
        return None
    trusted = re.search(r"(?m)^\[hooks\.state\b[^\n]*\]", text) and "trusted_hash" in text
    return "trusted" if trusted else "untrusted"


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
            self.cursor_dir, self.grok_dir = f"{data}/Cursor", f"{data}/grok"
            user_programs = str(self.home / "AppData/Local/MintEndpoint").replace("\\", "/")
        else:
            managed_programs, self.claude_dir, self.codex_dir = PROGRAMS, MANAGED_DIR, CODEX_DIR
            self.cursor_dir, self.grok_dir = CURSOR_DIR, GROK_DIR
            user_programs = str(self.home / ".local/lib/mint-endpoint")
        self.system_paths = (
            managed_programs, self.claude_dir, self.codex_dir, SYSTEMD_DIR, APPARMOR_DIR, BIN_DIR,
            self.cursor_dir, self.grok_dir,
        )
        self.answer: dict = {}  # 마지막 보고의 응답

        self.logical_programs = managed_programs if self.managed else user_programs
        self.programs = self.physical(self.logical_programs)
        self.managed_dir = self.physical(self.claude_dir)
        self.codex_managed_dir = self.physical(self.codex_dir)
        self.cursor_managed_dir = self.physical(self.cursor_dir)
        self.grok_managed_dir = self.physical(self.grok_dir)
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
            call = "& " + " ".join("'" + part.replace("'", "''") + "'" for part in parts)
            # 종료 코드를 넘기지 않으면 훅의 차단(2)이 1로 바뀌어 Codex가 그냥 통과시킨다.
            return call + "; exit $LASTEXITCODE"
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

    def gateway(self) -> dict | None:
        """하네스 설정에 넣을 게이트웨이(이름·주소·MCP 전용 키). 없으면 None. 사용자 수준 설치는
        사용자 설정 파일(Claude 사용자 범위, Codex config.toml 구간)에 같은 항목을 넣는다."""
        named, key = self.config.get("gateway"), self.config.get("gateway_key")
        if not isinstance(named, dict) or not key:
            return None
        return {"name": named["name"], "url": named["url"], "key": key}

    def secret_owner(self) -> tuple[int, int] | None:
        """키가 든 관리형 파일의 소유자: root, 그룹은 설치한 사용자(그 사용자의 하네스만 읽는다)."""
        return (0, self.account.gid) if self.owner is not None else None

    def write_tracked(
        self, state: dict, path: Path, logical: str, data: bytes, mode: int,
        owner: tuple[int, int] | None = None,
    ) -> None:
        """관리 대상 파일을 쓰되, 우리가 쓴 것이 아닌 기존 파일은 한 번만 백업해 둔다."""
        known = state["files"].get(logical)
        if path.exists() and (known is None or sha256_file(path) != known):
            name = logical.lstrip("/").replace(":", "").replace("/", "__")  # 드라이브 글자 포함
            backup = self.programs / "backup" / name
            if not backup.exists():
                write_atomic(backup, path.read_bytes(), 0o600)
                state["backups"][logical] = str(backup)
        write_atomic(path, data, mode, owner)
        state["files"][logical] = sha256_bytes(data)

    def hook_common(self, contracts: str, harness: str) -> list[str]:
        common = [
            "--url", self.config["decide_url"],
            "--key-file", f"~/{KEY_REL}",
            "--contracts", contracts,
            "--state-dir", f"~/{STATE_REL}",
            "--harness", harness,
        ]  # fmt: skip
        if self.config.get("ca_pem"):
            common += ["--ca-file", f"{self.logical_programs}/ca.pem"]
        return common

    def hook_commands(self, python: str, agent: str, contracts: str) -> dict:
        common = self.hook_common(contracts, "claude")
        before = {
            "type": "command", "command": python, "args": [agent, "pre", *common],
            "timeout": 3, "onFailure": "block",
        }  # fmt: skip
        after = {
            "type": "command", "command": python, "args": [agent, "post", *common], "timeout": 5,
        }  # fmt: skip
        failed = {**after, "args": [agent, "post-failure", *common]}
        hooks = {"PreToolUse": before, "PostToolUse": after, "PostToolUseFailure": failed}
        return {
            event: [{"matcher": CLAUDE_MATCHER, "hooks": [hook]}] for event, hook in hooks.items()
        }

    def codex_hook_commands(self, python: str, agent: str, contracts: str) -> dict:
        """Codex에는 실패 호출 훅이 없다. 보고되지 않은 호출은 MINT가 결과 미확인으로 남긴다."""
        common = self.hook_common(contracts, "codex")
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

    def sandbox_works(self, bwrap: str) -> bool:
        """설치한 사용자(관리자 계정이면 nobody)의 권한으로 bubblewrap을 실제로 한 번 돌려 본다."""
        target = (self.account.uid, self.account.gid) if self.owner is not None else None
        if target is not None and target[0] == 0:
            target = drop_target("nobody")
        if target is None:
            return bwrap_probe(bwrap)
        return bool(as_user(*target, lambda: bwrap_probe(bwrap)))

    def allow_apparmor_userns(self, state: dict, bwrap: str) -> bool:
        """AppArmor가 사용자 이름공간을 막고 있으면 bubblewrap에만 허용하는 프로필을 설치한다."""
        parser = shutil.which("apparmor_parser")
        if not apparmor_blocks_userns() or not parser:
            return False
        if not self.dry_run and not self.physical(APPARMOR_DIR).is_dir():
            return False
        logical = f"{APPARMOR_DIR}/{APPARMOR_PROFILE}"
        path = self.physical(logical)
        profile = apparmor_profile(os.path.realpath(bwrap)).encode()
        self.write_tracked(state, path, logical, profile, 0o644)
        if self.dry_run:  # 목록용: 프로필은 쓰지만 적용(apparmor_parser)은 하지 않는다.
            state["apparmor"] = logical
            return True
        done = subprocess.run(
            [parser, "-r", str(path)], capture_output=True, stdin=subprocess.DEVNULL
        )
        if done.returncode != 0:
            path.unlink(missing_ok=True)
            state["files"].pop(logical, None)
            sys.stderr.write(done.stderr.decode(errors="replace")[:500])
            return False
        state["apparmor"] = logical
        return True

    def ensure_sandbox_tool(self, state: dict) -> None:
        """관리형 Linux 설치는 서버 격리에 쓰는 bubblewrap이 있고 실제로 동작해야 한다.

        없으면 설치를 시도하고, 있어도 사용자 이름공간이 막혀 동작하지 않으면(Ubuntu 24.04의
        AppArmor 기본 설정) 허용 프로필을 설치한다. 그래도 안 되면 이유와 조치를 알리고 멈춘다
        (실행기는 격리할 수 없으면 서버를 시작하지 않는다). 격리 없는 시작을 허용한 묶음은 멈추는
        대신 경고만 한다.
        """
        if self.windows or not self.managed:
            return
        if self.dry_run:  # 실제 설치가 쓸 AppArmor 프로필도 같은 함수로 목록에 올린다.
            if bwrap := shutil.which("bwrap"):
                self.allow_apparmor_userns(state, bwrap)
            return
        if not self.strict:
            return
        allowed = bool(self.config.get("allow_unsandboxed"))
        bwrap = shutil.which("bwrap")
        if not bwrap:
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
            bwrap = shutil.which("bwrap")
        if not bwrap:
            problem = (
                "관리형 설치에는 bubblewrap(bwrap)이 필요합니다. 자동으로 설치하지 못했습니다. "
                "패키지 관리자로 bubblewrap을 설치한 뒤 다시 실행하세요."
            )
        elif self.sandbox_works(bwrap) or (
            self.allow_apparmor_userns(state, bwrap) and self.sandbox_works(bwrap)
        ):
            return
        elif apparmor_blocks_userns():
            problem = (
                "이 단말은 AppArmor가 일반 사용자의 사용자 이름공간을 막고 있어"
                "(kernel.apparmor_restrict_unprivileged_userns=1) bubblewrap이 서버를 격리하지 "
                f"못합니다. {APPARMOR_DIR}/{APPARMOR_PROFILE}에 bubblewrap용 프로필(userns 허용)을 "
                "두고 apparmor_parser -r로 적용하거나 이 sysctl을 0으로 바꾼 뒤 다시 실행하세요."
            )
        else:
            problem = (
                "bubblewrap이 서버를 격리하지 못합니다. 사용자 이름공간이 막혀 있는지"
                "(user.max_user_namespaces, 컨테이너·보안 모듈 설정) 확인한 뒤 다시 실행하세요."
            )
        if not allowed:
            raise SystemExit(problem)
        sys.stderr.write(f"경고: {problem} 격리 없이 서버를 시작하도록 허용된 묶음입니다.{NL}")

    def install(self) -> dict:
        previous = self.load_state()
        state = {
            "kit_version": self.config["kit_version"],
            "mode": "managed" if self.managed else "user",
            "user": self.account.name,
            "files": dict(previous.get("files", {})),
            "backups": dict(previous.get("backups", {})),
            "mcp_servers": [],
            "python": "",
        }
        for kept in (
            "settings_backup", "codex_config_backup", "grok_config_backup", "cursor_mcp_created"
        ):
            if kept in previous:
                state[kept] = previous[kept]
        self.ensure_sandbox_tool(state)
        agent = f"{self.logical_programs}/{AGENT}"
        contracts = f"{self.logical_programs}/contracts.json"
        self.write_tracked(
            state, self.programs / AGENT, agent, (self.folder / AGENT).read_bytes(), 0o755
        )
        servers = self.config["servers"]
        gateway = self.gateway()
        listing: dict = {"servers": servers}
        if gateway:
            clash = prefix_clash(gateway["name"], servers)
            if clash:
                raise SystemExit(f"승인된 서버 이름 {clash}이(가) 게이트웨이 이름과 겹칩니다.")
            # 호출 전 훅은 게이트웨이 호출을 통과시키고 판정은 서버 쪽 가드레일에 맡긴다.
            listing["gateways"] = [gateway["name"]]
            state["gateway"] = gateway["name"]
        self.write_tracked(
            state, self.programs / "contracts.json", contracts,
            json.dumps(listing, indent=1).encode(), 0o644,
        )  # fmt: skip
        fixed = "/usr/bin/python3"  # 관리자 권한으로 돌 보고기는 시스템 인터프리터를 쓴다
        if self.windows:
            python = sys.executable.replace("\\", "/")
        elif self.managed and self.strict and os.path.exists(fixed):
            python = fixed
        else:
            python = shutil.which("python3") or sys.executable
        self.check_python(python)
        state["python"] = python
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
        if "cursor" in self.harnesses:
            names |= set(self.install_cursor(state, mcp, python, agent, contracts))
        if "grok" in self.harnesses:
            names |= set(self.install_grok(state, mcp, python, agent, contracts))
        state["mcp_servers"] = sorted(names)
        self.connect_clients(python)  # 훅 없는 AI 도구도 설치 때 바로 잇는다(설치 뒤 필수 클릭 0)
        self.install_reporter(state, python)
        self.install_shim(state, python)
        key = (self.config["key"] + "\n").encode()
        key_path = self.home / KEY_REL
        write_atomic(key_path, key, 0o600, self.owner)
        keep_private(key_path, self.account.name)
        state["files"][str(key_path)] = sha256_bytes(key)
        if self.owner is not None:
            os.chown(key_path.parent, *self.owner)
        write_atomic(self.state_file, json.dumps(state, indent=1).encode(), 0o644)
        for stale in (TOOLS_SENT, KEY_REJECTED):  # 새 키로 도구 목록을 다시 보고하게 한다
            (self.home / STATE_REL / stale).unlink(missing_ok=True)
        return state

    def install_reporter(self, state: dict, python: str) -> None:
        """주기 보고에 쓸 이 파일의 사본과 설정(키 제외)을 두고 타이머·예약 작업을 등록한다."""
        tool = f"{self.logical_programs}/mint_kit.py"
        self.write_tracked(
            state, self.programs / "mint_kit.py", tool, (self.folder / "mint_kit.py").read_bytes(),
            0o644,
        )
        config = {
            k: v for k, v in self.config.items() if k not in ("key", "servers", "gateway_key")
        }
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
        command = [python, "-I", "-B", tool, "report", "--tick", "--kit", self.logical_programs]
        if self.managed:
            # 관리자 권한으로 돌므로 사용자의 키와 캐시가 있는 홈을 알려 준다.
            command += ["--home", str(self.home).replace("\\", "/"), "--user", self.account.name]
        if self.windows:
            self.schedule_task(state, command)
            self.schedule_sync_task(state, python, tool)
            self.schedule_net_task(state, python)
        else:
            self.schedule_timer(state, command)

    def install_shim(self, state: dict, python: str) -> None:
        """``mint``·``mint add``·``mint status``를 부를 수 있는 짧은 명령."""
        tool = f"{self.logical_programs}/mint_kit.py"
        if self.windows:
            # 사용자 PATH에 기본으로 있는 WindowsApps 폴더에 둔다(PATH 수정·새 창이 필요 없다).
            path = self.home / "AppData/Local/Microsoft/WindowsApps" / (SHIM + ".cmd")
            text = (
                f'@echo off{CRLF}'
                f'if "%~1"=="" ("{python}" -I -B "{tool}" screen & exit /b){CRLF}'
                f'"{python}" -I -B "{tool}" %*{CRLF}'
            )
            self.write_tracked(state, path, str(path), text.encode(), 0o755)
            return
        if self.managed:
            logical = f"{BIN_DIR}/{SHIM}"
            path = self.physical(logical)
        else:
            path = self.home / ".local/bin" / SHIM
            logical = str(path)
        text = (
            f"#!/bin/sh{NL}[ $# -gt 0 ] || {{{NL}"
            f"  [ -t 0 ] && [ -t 1 ] && set -- screen || set -- status{NL}}}{NL}"
            f'exec {shlex.quote(python)} -I -B {shlex.quote(tool)} "$@"{NL}'
        )
        self.write_tracked(state, path, logical, text.encode(), 0o755, self.owner)

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
                f"OnUnitActiveSec={FAST_GAP}s\n\n[Install]\nWantedBy=timers.target\n"
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
                f"OnUnitActiveSec={FAST_GAP}s\n\n[Install]\nWantedBy=timers.target\n"
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
        """Windows 예약 작업(설치한 계정으로 돈다). 1분마다 불리고 간격은 명령이 정한다."""
        if self.root is not None or self.dry_run:
            return
        line = subprocess.list2cmdline(command)
        made = capture([
            "schtasks", "/Create", "/TN", TASK_NAME, "/SC", "MINUTE",
            "/MO", "1", "/TR", line, "/F",
            *(["/RU", "SYSTEM"] if self.managed else []),
        ])  # fmt: skip
        if made:
            state["task"] = TASK_NAME

    def schedule_sync_task(self, state: dict, python: str, tool: str) -> None:
        """Windows 관리형 Codex: SYSTEM 보고기가 고치지 못하는 사용자 ``config.toml``의 서버 정의를
        설치한 사용자 권한으로 주기적으로(그리고 보고기가 서버 목록을 바꾼 직후) 맞추는 작업."""
        if self.root is not None or self.dry_run or not self.managed:
            return  # 훅 없는 AI 도구 연결·사용자 쪽 보고도 이 작업이 하므로 Codex가 없어도 둔다
        gui = python[:-len("python.exe")] + "pythonw.exe" if python.lower().endswith(
            "python.exe") else python  # fmt: skip
        if gui != python and not Path(gui).exists():
            gui = python
        line = subprocess.list2cmdline(
            [gui, "-I", "-B", tool, "sync", "--kit", self.logical_programs]
        )
        made = capture([
            "schtasks", "/Create", "/TN", SYNC_TASK_NAME, "/SC", "MINUTE",
            "/MO", str(SYNC_INTERVAL_MINUTES), "/TR", line, "/RU", self.account.name, "/IT", "/F",
        ])  # fmt: skip
        if made:
            state["sync_task"] = SYNC_TASK_NAME

    def schedule_net_task(self, state: dict, python: str) -> None:
        """Windows 관리형: 서버 실행기가 호스트 허용 방화벽 규칙을 요청할 SYSTEM 작업을 등록한다.

        요청 폴더는 일반 사용자가 파일을 만들기만 할 수 있고(읽지도 지우지도 못한다), 작업은 사용자
        누구나 실행할 수 있다. 작업은 요청을 검증해 ``mint.`` AppContainer 프로필에만 규칙을 건다.
        한 시간마다도 돌아 실행기가 죽어 남은 규칙을 지운다.
        """
        if self.root is not None or self.dry_run or not self.managed:
            return
        requests = self.programs / NET_DIR / "req"
        requests.mkdir(parents=True, exist_ok=True)
        capture([
            "icacls", str(requests), "/inheritance:r", "/grant:r",
            "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(WD)",
        ])  # fmt: skip
        agent = str(self.programs / AGENT)
        arguments = subprocess.list2cmdline(["-I", "-B", agent, "netpolicy", "--contracts", "none"])
        start = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <SecurityDescriptor>D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition><Interval>PT1H</Interval></Repetition>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{escape(python)}</Command><Arguments>{escape(arguments)}</Arguments></Exec>
  </Actions>
</Task>
"""
        with tempfile.TemporaryDirectory() as scratch:
            definition = Path(scratch) / "net.xml"
            definition.write_bytes(xml.encode("utf-16"))  # 서명(BOM)이 붙는다
            made = capture(
                ["schtasks", "/Create", "/TN", NET_TASK_NAME, "/XML", str(definition), "/F"]
            )
        if made:
            state["net_task"] = NET_TASK_NAME

    def install_managed(self, state: dict, mcp: dict, hooks: dict) -> None:
        env = {"MCP_TIMEOUT": str(STARTUP_WAIT_SECONDS * 1000)}
        settings = {"allowManagedHooksOnly": True, "hooks": hooks, "env": env}
        entries, gateway = dict(mcp), self.gateway()
        if gateway:
            entries[gateway["name"]] = {
                "type": "http", "url": gateway["url"],
                "headers": {"Authorization": "Bearer " + gateway["key"]},
            }
            env["MCP_TOOL_TIMEOUT"] = str(TOOL_WAIT_SECONDS * 1000)
        settings["permissions"] = {"allow": claude_allow(entries)}
        self.write_tracked(
            state,
            self.managed_dir / "managed-mcp.json",
            f"{self.claude_dir}/managed-mcp.json",
            json.dumps({"mcpServers": entries}, indent=2).encode(),
            0o640 if gateway else 0o644,
            self.secret_owner() if gateway else None,
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
        gateway = self.gateway()
        allow = settings.setdefault("permissions", {}).setdefault("allow", [])
        allow.extend(
            rule for rule in claude_allow([*mcp, *([gateway["name"]] if gateway else [])])
            if rule not in allow
        )
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
        gateway = self.gateway()
        if gateway and claude is not None:
            definition = {
                "type": "http", "url": gateway["url"],
                "headers": {"Authorization": "Bearer " + gateway["key"]},
            }  # fmt: skip
            subprocess.run(
                [claude, "mcp", "remove", "-s", "user", gateway["name"]], capture_output=True
            )
            done = subprocess.run(
                [claude, "mcp", "add-json", "-s", "user", gateway["name"], json.dumps(definition)],
                capture_output=True,
            )
            if done.returncode == 0:
                state["user_gateway"] = gateway["name"]  # 승인 서버 목록(보고)과 따로 지운다.

    def codex_config(self) -> Path:
        return self.home / ".codex/config.toml"

    def install_codex(self, state: dict, mcp: dict, hooks: dict) -> list[str]:
        """Codex 설정. 관리형은 요구 파일(Linux는 서버 정의 파일도), 그 밖은 config.toml 구간."""
        names = sorted(mcp)
        in_user_config = not self.managed or self.windows  # Windows는 관리형 서버 정의 파일이 없다
        if self.managed:
            gateway = self.gateway()
            requirements = codex_requirements(
                mcp, hooks, self.logical_programs, self.windows, gateway
            )
            self.write_tracked(
                state, self.codex_managed_dir / "requirements.toml",
                f"{self.codex_dir}/requirements.toml", requirements.encode(), 0o644,
            )  # fmt: skip
            if not self.windows:
                self.write_tracked(
                    state, self.codex_managed_dir / "managed_config.toml",
                    f"{self.codex_dir}/managed_config.toml",
                    (codex_servers(mcp) + (codex_gateway_server(gateway) if gateway else ""))
                    .lstrip(NL).encode(),
                    0o640 if gateway else 0o644, self.secret_owner() if gateway else None,
                )  # fmt: skip
        if in_user_config:
            names = self.write_codex_block(
                state, mcp, None if self.managed else hooks,
                self.gateway() if self.windows or not self.managed else None,
            )
        return names

    def write_codex_block(
        self, state: dict, mcp: dict, hooks: dict | None, gateway: dict | None = None
    ) -> list[str]:
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
        if gateway and not re.search(
            rf"(?m)^\[mcp_servers\.[\"']?{re.escape(gateway['name'])}[\"']?\]", rest
        ):
            body += codex_gateway_server(gateway)
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

    def hook_line(self, python: str, agent: str, command: str, contracts: str) -> str:
        """Cursor·Grok가 셸로 실행하는 훅 한 줄(Windows 셸 종류는 공식 문서에 없어 cmd 규칙)."""
        harness = command.removesuffix("-pre")  # cursor-pre -> cursor, grok-pre -> grok
        parts = [python, agent, command, *self.hook_common(contracts, harness)]
        return subprocess.list2cmdline(parts) if self.windows else shlex.join(parts)

    def own_new_dirs(self, path: Path) -> None:
        """루트가 홈 아래에 새로 만든 폴더·파일을 사용자 소유로 맞춘다."""
        if self.owner is None:
            return
        for item in (path, *path.parents):
            if item == self.home or not item.is_relative_to(self.home):
                break
            os.chown(item, *self.owner)

    def install_cursor(
        self, state: dict, mcp: dict, python: str, agent: str, contracts: str
    ) -> list[str]:
        """Cursor: 관리형이면 시스템 hooks.json, 아니면 사용자 hooks.json에 beforeMCPExecution 훅
        (failClosed). 게이트웨이·승인 서버는 사용자 ``~/.cursor/mcp.json``에 둔다."""
        line = self.hook_line(python, agent, "cursor-pre", contracts)
        if self.managed:
            path, logical = self.cursor_managed_dir / "hooks.json", f"{self.cursor_dir}/hooks.json"
        else:
            path = self.home / ".cursor/hooks.json"
            logical = str(path)
        before = path.read_bytes().decode("utf-8-sig") if path.exists() else None
        if before is not None and sha256_bytes(before.encode()) == state["files"].get(logical):
            before = None  # 우리가 쓴 것: 새로 쓴다
        self.write_tracked(
            state, path, logical, cursor_hooks_text(before, line, 5).encode(), 0o644,
            None if self.managed else self.owner,
        )
        if not self.managed:
            self.own_new_dirs(path)
        config = self.home / ".cursor/mcp.json"
        try:
            data = json.loads(config.read_text(encoding="utf-8-sig")) if config.exists() else {}
        except (OSError, ValueError):
            data = None  # 읽지 못하는 파일은 건드리지 않는다.
        if not isinstance(data, dict):
            return []
        listed = data["mcpServers"] if isinstance(data.get("mcpServers"), dict) else {}
        data["mcpServers"] = listed
        mine = {
            name: entry
            for name, entry in cursor_mcp_entries(mcp, self.gateway()).items()
            if name not in listed
            or is_ours_entry(listed[name], name)
            or listed[name].get("url") == entry.get("url")
        }
        listed.update(mine)
        state["cursor_mcp_created"] = state.get("cursor_mcp_created", not config.exists())
        state["cursor_mcp"] = sorted(mine)
        mode = (config.stat().st_mode & 0o777) if config.exists() else 0o600
        write_atomic(
            config, json.dumps(data, indent=2, ensure_ascii=False).encode(), mode, self.owner
        )
        self.own_new_dirs(config)
        return sorted(set(mine) & set(mcp))

    def connect_clients(self, python: str | None = None) -> dict:
        """훅이 없는 AI 도구의 MCP 설정에 승인 로컬 서버를 실행기 항목(전송 전 판정)으로 둔다.

        사용자 권한으로 돈다. 이 PC에 있는 도구만, 이 묶음의 항목만 더하고 바꾸고 지운다(같은 이름의
        사용자 항목은 그대로 둔다). 읽지 못하는 설정 파일은 건드리지 않고 「연결 실패」로 남긴다.
        도구별 기록(사용자 캐시 ``clients.json``)을 돌려준다.
        """
        try:
            listing = json.loads(read_trusted(self.programs / "contracts.json", False))
        except (OSError, ValueError):
            return read_client_record(self.home)  # 승인 목록을 모르면 아무것도 바꾸지 않는다
        gone: set[str] = set()
        for folder in (self.home / STATE_REL, self.programs):  # SYSTEM 보고기는 설치 폴더에 둔다
            try:
                listed = json.loads((folder / RETIRED_FILE).read_text(encoding="utf-8"))
                gone |= {n for n in (listed.get("servers") or []) if isinstance(n, str)}
            except (OSError, ValueError, AttributeError):
                pass
        names = sorted(n for n in (listing.get("servers") or {}) if n not in gone)
        python = python or (self.load_state() or {}).get("python") or sys.executable.replace(
            "\\", "/")
        agent = f"{self.logical_programs}/{AGENT}"
        contracts = f"{self.logical_programs}/contracts.json"
        common = [
            "--url", self.config["decide_url"], "--key-file", f"~/{KEY_REL}",
            "--state-dir", f"~/{STATE_REL}",
        ]  # fmt: skip
        if self.config.get("ca_pem"):
            common += ["--ca-file", f"{self.logical_programs}/ca.pem"]
        record, done, now = read_client_record(self.home), set(), time.time()
        for client, path, table, marker in client_sources(self.home, self.windows):
            if client in done or not marker.exists():
                continue
            done.add(client)
            mine = record.get(client) if isinstance(record.get(client), dict) else {}
            try:
                existed = path.exists()
                data = load_settings(path) if existed else {}
                if not isinstance(data, dict) or not isinstance(data.get(table) or {}, dict):
                    raise ValueError("unexpected settings shape")
            except (OSError, ValueError):
                record[client] = {**mine, "failed": True}
                continue
            listed = dict(data.get(table) or {})
            before = json.dumps(listed, sort_keys=True)
            for name in set(mine.get("names") or ()) - set(names):
                if is_ours_entry(listed.get(name), name):
                    listed.pop(name)
            put = []
            for name in names:
                if name in listed and not is_ours_entry(listed[name], name):
                    continue  # 같은 이름의 사용자 항목은 건드리지 않는다
                args = [agent, "run", "--contracts", contracts, "--server", name,
                        "--mediate", "--client", client, *common]  # fmt: skip
                listed[name] = client_entry(client, python, args)
                put.append(name)
            changed = json.dumps(listed, sort_keys=True) != before
            if changed:
                data[table] = listed
                mode = (path.stat().st_mode & 0o777) if existed else 0o600
                try:
                    write_atomic(
                        path, json.dumps(data, indent=2, ensure_ascii=False).encode(), mode,
                        self.owner,
                    )  # fmt: skip
                    if self.owner is not None and not existed:
                        self.own_new_dirs(path)
                except OSError:
                    record[client] = {**mine, "failed": True}
                    continue
            record[client] = {
                "names": put, "created": mine.get("created", not existed),
                "written": now if changed else mine.get("written", 0),
            }  # fmt: skip
        try:
            write_atomic(
                self.home / STATE_REL / CLIENT_FILE, json.dumps(record).encode(), 0o600, self.owner
            )
        except OSError:
            pass
        return record

    def disconnect_clients(self) -> None:
        """``connect_clients``가 더한 항목을 지운다. 만든 파일이 비면 파일도 지운다."""
        record = read_client_record(self.home)
        for client, path, table, _ in client_sources(self.home, self.windows):
            mine = record.get(client) if isinstance(record.get(client), dict) else {}
            if not mine.get("names"):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8-sig"))
                listed = data[table]
                for name in mine["names"]:
                    if is_ours_entry(listed.get(name), name):
                        listed.pop(name)
                if not listed and len(data) == 1 and mine.get("created"):
                    path.unlink()
                else:
                    info = path.stat()
                    owner = (info.st_uid, info.st_gid) if os.name == "posix" else None
                    write_atomic(
                        path, json.dumps(data, indent=2, ensure_ascii=False).encode(),
                        info.st_mode & 0o777, owner,
                    )  # fmt: skip
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                pass
            mine["names"] = []
        (self.home / STATE_REL / CLIENT_FILE).unlink(missing_ok=True)

    def uninstall_cursor_mcp(self, state: dict) -> None:
        config = self.home / ".cursor/mcp.json"
        try:
            data = json.loads(config.read_text(encoding="utf-8-sig"))
            listed = data["mcpServers"]
            for name in state.get("cursor_mcp", []):
                listed.pop(name, None)
            if not listed and len(data) == 1 and state.get("cursor_mcp_created"):
                config.unlink()
            else:
                write_atomic(
                    config, json.dumps(data, indent=2, ensure_ascii=False).encode(),
                    config.stat().st_mode & 0o777, self.owner,
                )
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass

    def grok_config(self) -> Path:
        return self.home / ".grok/config.toml"

    def install_grok(
        self, state: dict, mcp: dict, python: str, agent: str, contracts: str
    ) -> list[str]:
        """Grok Build CLI: PreToolUse 훅은 사용자 ``~/.grok/hooks/mint.json``(관리형 훅 위치는
        문서에 없다). 서버 정의는 Linux 관리형이면 ``/etc/grok/managed_config.toml``, 그 밖은
        ``~/.grok/config.toml`` 표식 구간."""
        line = self.hook_line(python, agent, "grok-pre", contracts)
        hooks = self.home / ".grok/hooks/mint.json"
        self.write_tracked(
            state, hooks, str(hooks), grok_hooks_text(line, 5).encode(), 0o644, self.owner
        )
        self.own_new_dirs(hooks)
        gateway = self.gateway()
        gateway_toml = grok_gateway_server(gateway) if gateway else ""
        if self.managed and not self.windows:
            self.write_tracked(
                state, self.grok_managed_dir / "managed_config.toml",
                f"{self.grok_dir}/managed_config.toml",
                (codex_servers(mcp) + gateway_toml).lstrip(NL).encode(),
                0o640 if gateway else 0o644, self.secret_owner() if gateway else None,
            )  # fmt: skip
            return sorted(mcp)
        path = self.grok_config()
        raw = path.read_bytes() if path.exists() else None
        original = raw.decode("utf-8-sig") if raw is not None else None
        rest = strip_block(original or "")

        def taken(name: str) -> bool:
            return bool(re.search(rf"(?m)^\[mcp_servers\.[\"']?{re.escape(name)}[\"']?\]", rest))

        mine = {n: i for n, i in mcp.items() if not taken(n)}
        body = codex_servers(mine)
        if gateway and not taken(gateway["name"]):
            body += gateway_toml
        state.setdefault("grok_config_backup", original)
        text = with_block(original or "", body)
        mode = (path.stat().st_mode & 0o777) if raw else 0o600
        write_atomic(path, text.encode(), mode, self.owner)
        self.own_new_dirs(path)
        state["grok_config_sha"] = sha256_bytes(text.encode())
        return sorted(mine)

    def uninstall_grok_config(self, state: dict) -> None:
        path = self.grok_config()
        if not path.exists():
            return
        current = path.read_bytes().decode("utf-8-sig")
        backup = state.get("grok_config_backup")
        mode = path.stat().st_mode & 0o777
        if sha256_bytes(current.encode()) != state["grok_config_sha"]:
            write_atomic(path, strip_block(current).encode(), mode, self.owner)
        elif backup is None:
            path.unlink()
        else:
            write_atomic(path, backup.encode(), mode, self.owner)

    def harness_problems(self, state: dict) -> list[str]:
        """Cursor·Grok 훅 파일이 우리가 쓴 그대로 있는가."""
        found = []
        for logical, digest in state.get("files", {}).items():
            tail = logical.replace("\\", "/")
            if "cursor" in self.harnesses and tail.lower().endswith("cursor/hooks.json"):
                label = "Cursor"
            elif "grok" in self.harnesses and tail.endswith(".grok/hooks/mint.json"):
                label = "Grok Build CLI"
            else:
                continue
            path = self.physical(logical)
            if not path.exists() or sha256_file(path) != digest:
                found.append(f"{label} 훅 파일이 없거나 바뀌었습니다: {logical}")
        return found

    # -- 제거 -------------------------------------------------------------------------------------

    def user_timer(self, state: dict) -> bool:
        """사용자 수준 설치가 등록한 사용자 systemd 타이머가 있는가."""
        return bool(
            state.get("links") and self.root is None and not self.owner
            and not state.get("timer") and not state.get("task")
        )

    def unload_apparmor(self, state: dict) -> None:
        """프로필 파일을 지우기 전에 커널에서 내린다(상태에 이름이 없어도 추적 파일로 찾는다)."""
        logical = f"{APPARMOR_DIR}/{APPARMOR_PROFILE}"
        profile = state.get("apparmor") or (logical if logical in state.get("files", {}) else None)
        parser = shutil.which("apparmor_parser") or next(
            (p for p in ("/usr/sbin/apparmor_parser", "/sbin/apparmor_parser") if Path(p).exists()),
            None,
        )
        if not profile or self.root is not None or not parser:
            return
        try:
            subprocess.run(
                [parser, "-R", str(self.physical(profile))],
                capture_output=True, stdin=subprocess.DEVNULL, timeout=20,
            )  # fmt: skip
        except (OSError, subprocess.SubprocessError):
            pass

    def uninstall(self) -> dict:
        state = self.load_state()
        if not state:
            return {"mode": "none"}
        left = []
        self.clean_servers()  # 실행기 파일을 지우기 전에: 서버를 끄고 AppContainer 항목을 정리한다
        if state.get("timer") == "system" and self.root is None:
            capture(["systemctl", "disable", "--now", f"{UNIT}.timer"])
        elif self.user_timer(state):
            # 유닛 파일을 지우기 전에 끈다. 지운 뒤에는 이미 떠 있는 타이머가 남는다.
            capture(["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"])
        self.unload_apparmor(state)
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
        for key in ("task", "sync_task", "net_task"):
            if state.get(key) and self.root is None:
                capture(["schtasks", "/Delete", "/TN", state[key], "/F"])
        if state.get("mode") == "user":
            self.uninstall_user(state)
        if "codex_config_sha" in state:
            self.uninstall_codex_config(state)
        if "grok_config_sha" in state:
            self.uninstall_grok_config(state)
        if state.get("cursor_mcp"):
            self.uninstall_cursor_mcp(state)
        self.disconnect_clients()  # 훅 없는 AI 도구 설정의 실행기 항목(사용자 캐시를 지우기 전에)
        shutil.rmtree(self.programs, ignore_errors=True)
        shutil.rmtree(self.home / STATE_REL, ignore_errors=True)
        extra = [self.codex_managed_dir.parent] if self.windows else []
        extra += [self.cursor_managed_dir, self.grok_managed_dir]
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

    def clean_servers(self) -> None:
        """제거 전에 실행기가 띄운 서버를 끄고 Windows의 AppContainer 프로필·ACE 흔적을 지운다."""
        if self.root is not None:
            return
        try:
            self.stop_launched(None)
        except OSError:
            pass
        agent = self.programs / AGENT
        if self.windows and agent.exists():
            try:  # 기록이 없거나 어긋난 실행기도 명령줄로 찾아 끈다.
                if self.stop_by_command(None):
                    time.sleep(2)  # 끈 실행기가 정리를 끝낼 틈을 준다
            except OSError:
                pass
            time.sleep(1)
            capture([
                sys.executable, "-I", "-B", str(agent), "reconcile", "--contracts", "none",
                "--state-dir", str(self.home / STATE_REL),
            ])  # fmt: skip
        if self.windows and self.managed and not self.dry_run:
            capture([  # 서버 격리용 방화벽 규칙이 남아 있으면 모두 지운다
                "powershell", "-NoProfile", "-Command",
                f"Get-NetFirewallRule | Where-Object {{ $_.Group -like '{NET_GROUP}*' }} "
                "| Remove-NetFirewallRule",
            ])  # fmt: skip

    def sync_codex_block(self, state: dict, write: bool = True) -> dict:
        """Windows 관리형 Codex: 사용자 설정 구간의 서버 정의를 계약 파일·폐기 목록에 맞춘다.

        SYSTEM 보고기는 사용자 프로필을 고치지 않으므로 사용자 권한으로 이 명령을 돌려야 한다.
        """
        path = self.codex_config()
        todo: dict = {"added": [], "dropped": []}
        if not (self.windows and self.managed and "codex" in self.harnesses and path.exists()):
            return todo
        listing: dict = {}
        names: dict = {}
        try:
            listing = json.loads(read_trusted(self.programs / "contracts.json", False))
            names = json.loads((self.programs / RETIRED_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        retired = {n for n in (names.get("servers") or []) if isinstance(n, str)}
        python = state.get("python") or sys.executable.replace("\\", "/")
        agent = f"{self.logical_programs}/{AGENT}"
        mcp = {
            name: {"command": python,
                   "args": [agent, "run", "--contracts", f"{self.logical_programs}/contracts.json",
                            "--server", name]}
            for name in sorted(listing.get("servers") or {}) if name not in retired
        }  # fmt: skip
        current = path.read_bytes().decode("utf-8-sig")
        new, put = put_block_tables(current, mcp)
        todo["added"] = [n for n in put if codex_table(current, n) is None]
        new, todo["dropped"] = drop_block_tables(new, retired)
        new = approve_user_config(new, [*mcp, *(listing.get("gateways") or [])])
        if write and new != current:
            write_atomic(path, new.encode(), path.stat().st_mode & 0o777, self.owner)
        return todo

    def approval_names(self) -> list[str]:
        """자동 허용 대상: 승인된 서버와 게이트웨이."""
        named = self.config.get("gateway")
        gateway = [named["name"]] if isinstance(named, dict) and named.get("name") else []
        return sorted({*self.local_contracts(), *gateway})

    def refresh_approvals(self, state: dict) -> bool:
        """이미 설치된 PC의 하네스 도구 확인 설정을 현재 판본(서버 단위 자동 허용)으로 맞춘다.

        보고 때마다 불러도 같은 결과이다. MINT 관리 서버의 항목만 고치고 사용자 설정은 보존한다.
        권한이 없어 못 쓰는 파일은 건너뛴다(관리자 보고기가 맞춘다).
        """
        names = self.approval_names()
        if not names:
            return False
        changed = False
        if "claude" in self.harnesses:
            rules = claude_allow(names)

            def edit_allow(text: str) -> tuple[str, list[str]]:
                data = json.loads(text)
                allow = data.setdefault("permissions", {}).setdefault("allow", [])
                add = [r for r in rules if r not in allow]
                allow.extend(add)
                return json.dumps(data, indent=2) + (NL if not self.managed else ""), add

            if self.managed:
                gone, _ = self.edit_file(
                    state, self.managed_dir / "managed-settings.json",
                    f"{self.claude_dir}/managed-settings.json", edit_allow,
                )  # fmt: skip
                changed |= bool(gone)
            else:
                changed |= bool(self.run_as_user(lambda: self.edit_user_file(
                    state, self.home / ".claude/settings.json", "settings_sha", edit_allow,
                )))  # fmt: skip
        if "codex" in self.harnesses:
            def edit_toml(fix):
                def edit(text: str) -> tuple[str, list[str]]:
                    new = fix(text, names)
                    return new, ([""] if new != text else [])

                return edit

            if self.managed and not self.windows:
                gone, _ = self.edit_file(
                    state, self.codex_managed_dir / "managed_config.toml",
                    f"{self.codex_dir}/managed_config.toml", edit_toml(approve_tables),
                )  # fmt: skip
                changed |= bool(gone)
            if (not self.managed or self.windows) and not self.system_mode:
                changed |= bool(self.run_as_user(lambda: self.edit_user_file(
                    state, self.codex_config(), "codex_config_sha", edit_toml(approve_user_config),
                )))  # fmt: skip
        if changed:
            self.save_state(state)
        return changed

    def edit_user_file(self, state: dict, path: Path, sha_key: str, edit) -> bool:
        """사용자 홈의 설정 파일을 고친다(바뀐 것이 없으면 쓰지 않는다). 쓴 뒤의 해시를 기록한다."""
        try:
            raw = path.read_bytes().decode("utf-8-sig")
            new, gone = edit(raw)
            if not gone:
                return False
            write_atomic(path, new.encode(), path.stat().st_mode & 0o777, self.owner)
        except (OSError, ValueError):
            return False
        if sha256_bytes(raw.encode()) == state.get(sha_key):
            state[sha_key] = sha256_bytes(new.encode())  # 제거 때 되돌릴 수 있게 맞춘다
        return True

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
        for name in [*state.get("mcp_servers", []), *filter(None, [state.get("user_gateway")])]:
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
            for name, probe in (
                ("claude", claude_version), ("codex", codex_version),
                ("cursor", cursor_version), ("grok", grok_version),
            )
            if name in self.harnesses and (version := probe(self.home))
        ]
        return " · ".join(found)[:64] or None

    def inventory(self) -> dict:
        """프로세스·자동 시작 인벤토리(사용자 홈을 읽으므로 사용자 권한으로). 실패해도 계속."""
        return self.run_as_user(self.read_inventory) or {}

    def read_inventory(self) -> dict:
        try:
            table = win_start_table() if self.windows else None
            start_of = (lambda pid, windows: table.get(pid)) if table is not None else None
            processes = with_sandbox(
                scan_processes(self.windows), self.home, self.windows, not self.system_mode,
                windows_sandbox_status() if self.windows else None,
                net_filtered(self.programs, self.windows, start_of), start_of,
            )
            extra = {"profile": False} if self.system_mode else {}
            autostart = scan_autostart(self.home, self.windows, self.account.name, **extra)
            outside = scan_outside(self.windows)
        except Exception:
            return {}
        found: dict = {}
        if not self.system_mode:  # SYSTEM 보고기는 사용자 프로필을 읽지 않는다(사용자 작업 몫)
            scan = scan_mcp(self.home, managed_names(self.load_state() or {}), self.windows)
            found = {
                "local_mcp": scan["local_mcp"],
                "tool_lists": scan_tool_lists(self.home),
                "start_failures": scan_start_failures(self.home),
                "ai_clients": ai_client_rows(
                    self.home, self.windows, self.harnesses, scan, read_client_record(self.home)
                ),
                "plaintext_keys": scan["plaintext_keys"],
                "scan_errors": scan["scan_errors"],
                "offline_calls": read_offline(self.home),
                "paused_ack": read_paused_gen(self.home / STATE_REL),
            }
        return {
            "processes": processes, "autostart": autostart, "outside_processes": outside, **found
        }

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
            "mcp_servers": state.get("mcp_servers", [])[:MAX_REPORTED_SERVERS] if installed else [],
            **self.inventory(),
        }
        if payload.get("paused_ack") is None:
            payload.pop("paused_ack", None)
        if installed:
            import platform
            import socket

            payload["host"] = socket.gethostname()[:255] or None  # 목록에서 PC를 알아보게
            payload["os"] = f"{platform.system()} {platform.release()}".strip()[:64] or None
            # "clients": 사용자 권한 보고기 — 연결 복구·신청 요청을 받아 처리할 수 있다
            payload["capabilities"] = ["inspect"] + ([] if self.system_mode else ["clients"])
            if self.config.get("update_key"):
                payload["kit_update"] = True  # 서명된 프로그램 갱신을 받을 수 있다
            if self.update_error:
                payload["update_error"] = self.update_error[:80]
            versions = self.stored_versions()
            if versions:
                payload["decision_versions"] = versions
        if pending:
            payload["removed"] = pending
        if not installed and getattr(self, "replaced_by", None):
            payload["replaced_by"] = self.replaced_by
        trust = self.hook_trust(state) if installed else None
        if trust:
            payload["hook_trust"] = trust
        if not self.config.get("key"):
            return False  # 키를 모르면 보고하지 않는다(설치·제거 자체는 그대로).
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
        if isinstance(answer, dict) and installed and not self.system_mode:
            # 검사 권한은 하네스 설정·desired와 따로 사용자 캐시에만 둔다(사라진 것은 지운다).
            self.run_as_user(lambda: save_inspections(self.home, self.answer.get("inspections")))
        if answer and payload.get("tool_lists"):
            self.run_as_user(lambda: mark_tool_lists_sent(self.home, payload["tool_lists"]))
        if answer and payload.get("offline_calls"):  # 보낸 장애 중 통과 기록은 비운다
            self.run_as_user(
                lambda: (self.home / STATE_REL / (OFFLINE_FILE + ".sending")).unlink(
                    missing_ok=True) or True
            )
        if answer and pending:
            state.pop("pending_removed", None)
            self.save_state(state)
        return bool(answer)

    update_error: str | None = None  # 직전 자체 갱신이 실패한 사유(다음 보고에 싣는다)

    def apply_update(self, folder: Path, state: dict, update: object) -> str | None:
        """서명 검증을 통과한 묶음으로 설치된 프로그램 파일을 바꾼다. 실패하면 사유(옛 코드 유지).

        모든 새 파일을 임시 파일로 먼저 쓴 뒤에 이름을 바꿔 넣고 ``kit.json``의 판본은 맨 끝에
        바꾼다(중간에 멈추면 판본이 옛것이라 다음 보고가 다시 받는다). 새 코드는 다음 주기부터 돈다.
        """
        if not self.config.get("update_key"):
            return "no_key"
        keys = self.config.get("update_keys") or [self.config["update_key"]]
        checked = verify_update(keys, update, int(self.config.get("kit_serial") or 0))
        if isinstance(checked, str):
            return checked
        version, files, serial, keys = checked
        if not os.access(folder, os.W_OK):
            return "not_writable"
        try:
            config = json.loads((folder / "kit.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "no_config"
        config["kit_version"] = version
        config["kit_serial"] = serial
        config["update_keys"] = keys
        staged: list[tuple[str, Path]] = []  # (임시 파일, 최종 경로)
        sums: dict[str, str] = {}
        try:
            for name, mode in UPDATE_FILES:
                staged.append((self.stage(folder, files[name], mode), folder / name))
                sums[f"{self.logical_programs}/{name}"] = sha256_bytes(files[name])
            body = json.dumps(config, indent=1).encode()
            staged.append((self.stage(folder, body, 0o644), folder / "kit.json"))
            sums[f"{self.logical_programs}/kit.json"] = sha256_bytes(body)
            while staged:
                os.replace(staged[0][0], staged[0][1])
                staged.pop(0)
        except OSError:
            return "write_failed"
        finally:
            for temp, _ in staged:
                try:
                    os.unlink(temp)
                except OSError:
                    pass
        state["files"].update(sums)
        state["kit_version"] = version
        self.config["kit_version"] = version
        self.config["kit_serial"] = serial
        self.config["update_keys"] = keys
        self.save_state(state)
        return None

    @staticmethod
    def stage(folder: Path, data: bytes, mode: int) -> str:
        """같은 폴더의 임시 파일에 내용을 써 둔다(이름 바꾸기 전까지 설치된 파일은 그대로)."""
        fd, name = tempfile.mkstemp(dir=folder, prefix=".mint-upd-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.chmod(name, mode)
        except OSError:
            os.unlink(name)
            raise
        return name

    def hook_trust(self, state: dict) -> str | None:
        """사용자 수준 Codex 설치의 훅을 Codex가 신뢰하는지(설정 파일 추정). 모르면 None."""
        if state.get("mode") != "user" or "codex" not in self.harnesses:
            return None

        def read() -> str | None:
            try:
                return codex_hook_trust(self.codex_config().read_bytes().decode("utf-8-sig"))
            except OSError:
                return None

        return self.run_as_user(read)

    def check(self, state: dict) -> tuple[dict, list[str]]:
        """설치 상태 점검: 상태 파일 내용과 이 계정에서 보이는 문제 목록(비어 있으면 이상 없음)."""
        problems: list[str] = []
        bwrap = shutil.which("bwrap")
        if state.get("mode") == "managed" and not self.windows and not self.config.get(
            "allow_unsandboxed"
        ):
            if not bwrap:
                problems.append("bubblewrap이 없어 서버를 격리하지 못합니다.")
            elif not bwrap_probe(bwrap):
                problems.append(
                    "bubblewrap이 이 계정에서 동작하지 않습니다(사용자 이름공간이 막혔을 수 있음)."
                )
        if self.windows and state.get("mode") == "managed":
            stale = self.sync_codex_block(state, write=False)
            if stale["added"] or stale["dropped"]:
                problems.append(
                    "Codex 서버 정의가 승인 서버 목록과 다릅니다. `install.cmd sync`로 맞추세요."
                )
        problems += self.harness_problems(state)
        trust = self.hook_trust(state)
        if trust == "untrusted":
            problems.append(
                "Codex가 MINT 훅을 아직 신뢰하지 않아 호출 전 판정이 실행되지 않습니다. "
                "Codex에서 훅을 검토해 신뢰하세요."
            )
        if any((d / KEY_REJECTED).exists() for d in (self.home / STATE_REL, self.programs)):
            problems.append(KEY_REJECTED_TEXT)
        for folder in (self.home / STATE_REL, self.programs):
            try:
                note = (folder / UPDATE_NOTE).read_text(encoding="utf-8").strip()
            except OSError:
                continue
            problems.append(UPDATE_NEEDED_TEXT if note == "needed" else f"자동 갱신 실패: {note}")
            break
        if state.get("mode") == "user":
            problems.append("사용자 수준 설치라 관리되지 않습니다. 관리자 권한으로 재설치하세요.")
        return {**state, "problems": problems, "hook_trust": trust}, problems

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
            info = path.stat()  # 키가 든 관리형 파일의 소유 그룹을 지킨다.
            owner = (info.st_uid, info.st_gid) if self.root_owned() else None
            write_atomic(path, new.encode(), info.st_mode & 0o777, owner)
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

    def stop_launched(self, retired: set[str] | None) -> list[dict]:
        """실행기가 띄운 프로세스 중 폐기 서버의 것을 끈다(기록한 PID와 시작 시각이 맞을 때만)."""
        folder = self.home / STATE_REL / LAUNCHED
        removed = []
        for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                server, pid, start = str(record["server"]), int(record["pid"]), record.get("start")
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if retired is not None and server not in retired:
                continue
            if not start or proc_start(pid, self.windows) != start:
                path.unlink(missing_ok=True)  # 이미 끝났거나 PID가 다른 프로세스에 재사용되었다.
                continue
            if self.kill(pid):
                path.unlink(missing_ok=True)
                removed.append({"kind": "process", "server": server, "target": None})
        return removed

    def stop_by_command(self, retired: set[str] | None) -> list[dict]:
        """프로필을 읽지 않는 SYSTEM 보고기: 이 묶음의 실행기로 폐기 서버를 돌리는 프로세스를 끈다.

        명령줄이 이 설치 폴더의 실행기로 ``run --server 이름``인 프로세스만 대상이다(자식 포함).
        ``retired``가 None이면 이 묶음의 서버를 모두(제거할 때) 끈다.
        """
        agent = f"{self.logical_programs}/{AGENT}".replace("\\", "/").lower()
        removed = []
        rows = process_entries(self.windows)
        for pid, _, command in rows:
            server = server_of(command)
            if server and (retired is None or server in retired) and agent in (
                command.replace("\\", "/").lower()
            ):
                if self.windows:
                    self.end_launcher(pid, rows)
                elif not self.kill(pid):
                    continue
                removed.append({"kind": "process", "server": server, "target": None})
        return removed

    def end_launcher(self, pid: int, rows: list[tuple[int, int, str]]) -> None:
        """Windows: 서버(실행기의 자식)를 먼저 끄고 실행기가 AppContainer 항목을 지우고 끝나기를
        잠깐 기다린다. 그래도 남아 있으면 실행기를 끈다(남은 항목은 다음 정리 때 지워진다)."""
        for child, parent, _ in rows:
            if parent == pid:
                self.kill(child)
        for _ in range(20):
            time.sleep(0.5)
            if pid not in {row[0] for row in process_entries(True)}:
                return
        self.kill(pid)

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
        if self.system_mode:  # 실행기 기록은 사용자 프로필에 있어 명령줄로 찾는다
            removed += self.stop_by_command(gone_names)
        else:
            removed += self.run_as_user(lambda: self.stop_launched(gone_names)) or []
        removed += self.drop_autostart(state, gone_names)
        state["mcp_servers"] = sorted(set(state.get("mcp_servers", [])) - (mine - failed))
        if removed:
            pending = [*state.get("pending_removed", []), *removed]
            state["pending_removed"] = pending[-MAX_PENDING:]
        if removed or mine:
            self.save_state(state)
        return removed

    # -- 승인 서버 목록 반영(관리형) --------------------------------------------------------------

    def desired_items(self, desired: list, skip: set[str]) -> dict[str, dict]:
        """응답의 ``desired``에서 형식과 판본이 맞는 항목만(이름 -> 계약). 틀린 항목은 버린다."""
        items: dict[str, dict] = {}
        for item in desired[:MAX_PENDING]:
            name = item.get("name") if isinstance(item, dict) else None
            contract = item.get("contract") if isinstance(item, dict) else None
            if (
                isinstance(name, str) and SERVER_NAME.match(name) and name not in skip
                and isinstance(contract, dict) and isinstance(contract.get("executable"), str)
                and item.get("version") == contract_version(contract)
                and pack_consistent(item, contract)
            ):
                items[name] = contract
        return items

    def refresh(self, state: dict, desired: list, retired: list | None = None) -> list[str]:
        """MINT가 승인한 서버 목록에 맞춰 관리형 설정에 서버를 더하거나(계약이 바뀌었으면 갱신)
        한다. 돌려주는 값은 더하거나 갱신한 이름이다.

        폐기 서버를 지우는 일은 ``remediate``가 한다. 여기서는 지우지 않는다. 사용자 수준 설치는
        파일을 고치지 않고 바뀐 서버를 알리기만 한다. 관리형은 이 묶음이 쓴 계약 파일(기록한
        해시와 같을 때만)과 이 묶음의 실행기로 시작하는 항목만 고치고, 같은 이름의 사용자 항목은
        건드리지 않는다.
        """
        items = self.desired_items(desired, set(retired or ()))
        logical = f"{self.logical_programs}/contracts.json"
        path = self.programs / "contracts.json"
        try:
            raw = read_trusted(path, self.managed and self.root_owned())
            listing = json.loads(raw)
            current = listing.get("servers", {})
        except (OSError, ValueError, AttributeError):
            return []
        configured = set(state.get("mcp_servers", []))
        todo = {n: c for n, c in items.items() if current.get(n) != c or n not in configured}
        if not todo:
            return []
        if not self.managed:
            print(
                "MINT 승인 서버가 바뀌었습니다: " + ", ".join(sorted(todo))
                + ". 설치 명령을 다시 실행하면 반영됩니다.",
                file=sys.stderr,
            )
            return []
        if state.get("files", {}).get(logical) != sha256_bytes(raw):
            print("MINT 계약 파일이 바뀌어 있어 서버 목록을 갱신하지 않습니다.", file=sys.stderr)
            return []
        python = state.get("python") or sys.executable.replace("\\", "/")
        agent = f"{self.logical_programs}/{AGENT}"
        mcp = {
            name: {
                "command": python,
                "args": [agent, "run", "--contracts", logical, "--server", name],
            }
            for name in sorted(todo)
        }
        data = json.dumps({**listing, "servers": {**current, **todo}}, indent=1).encode()
        try:
            write_atomic(path, data, 0o644)
        except OSError:
            return []
        state.setdefault("files", {})[logical] = sha256_bytes(data)
        done = self.put_configs(state, mcp)
        state["mcp_servers"] = sorted(configured | done)
        self.save_state(state)
        return sorted(done)

    # -- 묶음 서버: 허가·준비·철회 ----------------------------------------------------------------

    drop_to: tuple[int, int] | None = None  # 관리자 보고기가 사용자 캐시를 읽을 때 내려갈 계정

    def local_contracts(self) -> dict:
        try:
            doc = json.loads((self.programs / "contracts.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        servers = doc.get("servers") if isinstance(doc, dict) else None
        return servers if isinstance(servers, dict) else {}

    def local_permits(self) -> dict:
        try:
            doc = json.loads((self.programs / PERMITS).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        permits = doc.get("permits") if isinstance(doc, dict) else None
        return permits if isinstance(permits, dict) else {}

    def writable(self) -> bool:
        return self.managed and os.access(self.programs, os.W_OK)

    def stored_versions(self) -> dict[str, int]:
        try:
            data = json.loads((self.programs / VERSIONS).read_text(encoding="utf-8"))["versions"]
            return {n: v for n, v in data.items() if isinstance(v, int) and v > 0}
        except (OSError, ValueError, KeyError, AttributeError):
            return {}

    def apply_versions(self, state: dict, desired: list, dropped: set[str]) -> bool:
        """받은 서버별 결정 버전을 ``versions.json``에 쓴다(보고·첫 호출 보고가 되돌려 보낸다)."""
        if not self.writable():
            return False
        wanted = self.desired_items(desired, dropped)
        versions = {
            i["name"]: i["decision_version"] for i in desired[:MAX_PENDING]
            if isinstance(i, dict) and i.get("name") in wanted
            and isinstance(i.get("decision_version"), int) and i["decision_version"] > 0
        }
        data = json.dumps({"versions": versions}, indent=1, sort_keys=True).encode()
        path, logical = self.programs / VERSIONS, f"{self.logical_programs}/{VERSIONS}"
        try:
            if path.exists() and path.read_bytes() == data:
                return False
            write_atomic(path, data, 0o644)
        except OSError:
            return False
        state.setdefault("files", {})[logical] = sha256_bytes(data)
        self.save_state(state)
        return True

    def apply_permits(self, state: dict, desired: list, dropped: set[str]) -> bool:
        """응답의 시작 허가를 계약 파일 옆 ``permits.json``에 쓴다(서버가 허가를 빼면 지워진다)."""
        if not self.writable():
            return False
        permits = {}
        for item in desired[:MAX_PENDING]:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            contract = item.get("contract") if isinstance(item.get("contract"), dict) else {}
            digest, until = item.get("pack_sha256"), item.get("permit_until")
            pack = contract.get("pack") if isinstance(contract.get("pack"), dict) else {}
            if (
                item["name"] not in dropped and isinstance(digest, str)
                and pack.get("sha256") == digest and parse_time(until) is not None
                and SERVER_NAME.match(item["name"])
            ):
                permits[item["name"]] = {"pack_sha256": digest, "permit_until": until}
        data = json.dumps({"permits": permits}, indent=1, sort_keys=True).encode()
        path, logical = self.programs / PERMITS, f"{self.logical_programs}/{PERMITS}"
        try:
            if path.exists() and path.read_bytes() == data:
                return False
            write_atomic(path, data, 0o644)
        except OSError:
            return False
        state.setdefault("files", {})[logical] = sha256_bytes(data)
        self.save_state(state)
        return True

    def drop_contracts(self, state: dict, names: list[str]) -> list[str]:
        """범위를 잃은 서버를 계약 파일(과 허가)에서 뺀다. 이 묶음이 쓴 그대로인 파일만 고친다."""
        if not self.writable() or not names:
            return []
        logical = f"{self.logical_programs}/contracts.json"
        path = self.programs / "contracts.json"
        try:
            raw = read_trusted(path, self.root_owned())
            listing = json.loads(raw)
            current = listing.get("servers", {})
        except (OSError, ValueError, AttributeError):
            return []
        gone = [n for n in names if n in current]
        if not gone or state.get("files", {}).get(logical) != sha256_bytes(raw):
            return []
        data = json.dumps(
            {**listing, "servers": {k: v for k, v in current.items() if k not in gone}}, indent=1
        ).encode()
        try:
            write_atomic(path, data, 0o644)
        except OSError:
            return []
        state["files"][logical] = sha256_bytes(data)
        permits = {k: v for k, v in self.local_permits().items() if k not in gone}
        try:
            body = json.dumps({"permits": permits}, indent=1, sort_keys=True).encode()
            write_atomic(self.programs / PERMITS, body, 0o644)
            state["files"][f"{self.logical_programs}/{PERMITS}"] = sha256_bytes(body)
        except OSError:
            pass
        self.save_state(state)
        return gone

    def promote_packs(self) -> list[str]:
        """사용자가 받아 둔 묶음(관리자 단계 대기)을 다시 검증해 풀고 준비 폴더로 옮긴다."""
        if not self.writable():
            return []
        made = []
        for name, contract in sorted(self.local_contracts().items()):
            pack = contract.get("pack") if isinstance(contract, dict) else None
            digest = pack.get("sha256") if isinstance(pack, dict) else None
            if not isinstance(digest, str) or not SHA256_HEX.match(digest):
                continue
            if ready_status(self.programs / PACKS / digest[:16], digest) == "ok":
                continue
            staged = self.home / STATE_REL / PACKS / digest[:16]
            blobs = read_staged(self.drop_to, staged, {"manifest.json": MANIFEST_MAX})
            try:
                if blobs is None:
                    continue
                blobs["manifest.json"].seek(0)
                files = manifest_files(json.loads(blobs["manifest.json"].read()))
                more = read_staged(self.drop_to, staged, {f["name"]: f["size"] for f in files})
                if more is None:
                    continue
                blobs.update(more)
                install_blobs(digest, blobs, self.programs / PACKS)
                made.append(name)
            except (PackError, OSError, ValueError):
                sys.stderr.write(f"MINT 묶음 준비 실패: {name}" + NL)
            finally:
                for handle in (blobs or {}).values():
                    handle.close()
        return made

    def auto_fetch(self, state: dict, desired: list, dropped: set[str]) -> list[str]:
        """승인된 묶음 서버의 묶음을 보고기가 받아 검증하고 푼다(관리형). 실패 사유를 남긴다."""
        url, key = self.config.get("decide_url"), self.config.get("key")
        if not self.writable() or not url or not key:
            return []
        gateway = Gateway(url, key, self.config.get("ca_pem"))
        errors = self.pack_errors()
        made: list[str] = []
        for name, contract in sorted(self.desired_items(desired, dropped).items())[:MAX_FETCH]:
            pack = contract.get("pack") if isinstance(contract.get("pack"), dict) else {}
            digest = pack.get("sha256")
            if not isinstance(digest, str) or not SHA256_HEX.match(digest):
                continue
            if ready_cached(self.programs / PACKS / digest[:16], digest,
                            self.programs / PACK_VERIFIED, write=True) == "ok":
                errors.pop(name, None)
                continue
            blobs: dict = {}
            try:
                blobs = fetch_pack(gateway, name, digest)
                install_blobs(digest, blobs, self.programs / PACKS)
                errors.pop(name, None)
                made.append(name)
            except (PackError, OSError) as exc:
                errors[name] = {"sha256": digest, "reason": str(exc)[:120]}
            finally:
                for handle in blobs.values():
                    handle.close()
        wanted = {i.get("name") for i in desired if isinstance(i, dict)}
        try:
            write_atomic(self.programs / PACK_ERRORS, json.dumps(
                {n: v for n, v in errors.items() if n in wanted}, sort_keys=True).encode(), 0o644)
        except OSError:
            pass
        return made

    def pack_errors(self) -> dict:
        try:
            doc = json.loads((self.programs / PACK_ERRORS).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return doc if isinstance(doc, dict) else {}

    def put_configs(self, state: dict, mcp: dict) -> set[str]:
        """관리형 설정 파일에 서버 항목을 더하거나 바꾼다(이 묶음의 것만). 반영한 이름."""
        done: set[str] = set()
        if "claude" in self.harnesses:

            def edit_json(text: str) -> tuple[str, list[str]]:
                data = json.loads(text)
                listed = data.setdefault("mcpServers", {})
                put = [
                    n for n in sorted(mcp) if n not in listed or is_ours_entry(listed.get(n), n)
                ]
                listed.update({n: mcp[n] for n in put})
                return json.dumps(data, indent=2), put

            logical = f"{self.claude_dir}/managed-mcp.json"
            path = self.managed_dir / "managed-mcp.json"
            done |= set(self.edit_file(state, path, logical, edit_json)[0])
        if "codex" in self.harnesses:
            found: set[str] = set()
            accepted = mcp
            if not self.windows:  # 서버 표를 못 더한 이름은 신원 표도 더하지 않는다.
                gone, _ = self.edit_file(
                    state, self.codex_managed_dir / "managed_config.toml",
                    f"{self.codex_dir}/managed_config.toml",
                    lambda text: put_codex_tables(text, mcp, False),
                )  # fmt: skip
                found.update(gone)
                accepted = {n: mcp[n] for n in mcp if n in gone}
            gone, _ = self.edit_file(
                state, self.codex_managed_dir / "requirements.toml",
                f"{self.codex_dir}/requirements.toml",
                lambda text: put_codex_tables(text, accepted, True),
            )  # fmt: skip
            found.update(gone if self.windows else ())
            if self.windows and not self.system_mode:  # 서버 정의가 사용자 설정의 표식 구간에 있다
                config = self.codex_config()
                try:
                    current = config.read_bytes().decode("utf-8-sig")
                    new, gone = put_block_tables(current, mcp)
                    if gone:
                        write_atomic(config, new.encode(), config.stat().st_mode & 0o777)
                        if sha256_bytes(current.encode()) == state.get("codex_config_sha"):
                            state["codex_config_sha"] = sha256_bytes(new.encode())
                        found.update(gone)
                except OSError:
                    pass
            done |= found
        return done


# --- 실행 묶음(pack): 받기·검증·준비 ----------------------------------------------------------
# 묶음 = manifest.json + wheel 파일들. 단말은 MINT에서만 받고, 해시가 맞는 wheel만 zip으로 직접
# 풀어(pip 없음) 준비 폴더를 만든다. 준비 폴더는 ``.ready.json``을 마지막에 쓰고 한 번에 이름을
# 바꿔 놓으므로 반쯤 된 폴더는 「사용 가능」으로 보이지 않는다.
PACKS = "packs"  # 설치 폴더 아래: 준비된 묶음(<해시 앞 16>/)
PERMITS = "permits.json"  # 계약 파일 옆: 서버별 시작 허가(만료 시각)
VERSIONS = "versions.json"  # 계약 파일 옆: 서버별로 받아 둔 결정 버전
READY = ".ready.json"
PACK_VERIFIED = "pack-verified.json"  # 검증 작업이 남긴 묶음 검증 기록(목록이 읽는다)
PACK_ERRORS = "pack-errors.json"  # 자동 받기가 실패한 서버의 사유(화면이 읽는다)
MAX_FETCH = 8  # 보고 한 번에 받는 묶음 수
CALLED = "called"  # 서버별 첫 호출 성공 표지(실행기 훅이 남긴다)
PACK_MAX_FILES = 10_000
PACK_MAX_BYTES = 512 << 20
PACK_MAX_WHEELS = 256
MANIFEST_MAX = 1 << 20
PACK_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,200}\.whl$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
S_NEED, S_WORK, S_READY = "받기 필요", "준비 중", "사용 가능"
S_EXPIRED, S_NOPROG = "실행 허가 만료", "필요한 프로그램 없음"
S_BAD, S_WAIT = "묶음 불일치", "반영 대기"
S_FAILED, S_START = "받기 실패", "시작 대기"
STEP_NAMES = ("시작 검증 통과", "도구 목록 받음", "첫 호출 성공")


class PackError(Exception):
    """묶음을 받거나 풀 수 없는 사유(사람이 읽는 문장)."""


def manifest_digest(manifest: object) -> str:
    text = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_bytes(text.encode("utf-8"))


def manifest_files(manifest: object) -> list[dict]:
    """manifest의 wheel 목록(이름·해시·크기). 모양이 틀리면 ``PackError``."""
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list) or not 0 < len(files) <= PACK_MAX_WHEELS:
        raise PackError("묶음 목록의 모양이 틀립니다")
    seen: set[str] = set()
    total = 0
    for item in files:
        name = item.get("name") if isinstance(item, dict) else None
        size, digest = (item.get("size"), item.get("sha256")) if isinstance(item, dict) else (0, 0)
        if (
            not isinstance(name, str) or not PACK_FILE.match(name) or name in seen
            or not isinstance(digest, str) or not SHA256_HEX.match(digest)
            or not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= PACK_MAX_BYTES
        ):
            raise PackError("묶음 목록에 받을 수 없는 파일이 있습니다")
        seen.add(name)
        total += size
    if total > PACK_MAX_BYTES:
        raise PackError("묶음이 너무 큽니다")
    return files


def wheel_target(name: str) -> str | None:
    """wheel 안 경로를 준비 폴더의 상대 경로로. 받지 않으면 None, 위험하면 오류."""
    if name.endswith("/"):
        return None
    parts = name.split("/")
    if (
        not name or len(name) > 1024 or "\\" in name or chr(0) in name or name.startswith("/")
        or any(p in ("", ".", "..") or len(p) > 255 or ":" in p for p in parts)
    ):
        raise PackError(f"안전하지 않은 경로가 있습니다: {name[:60]}")
    if parts[0].endswith(".data"):
        if len(parts) >= 3 and parts[1] in ("purelib", "platlib"):
            return "/".join(parts[2:])
        return None  # scripts·headers·data는 쓰지 않는다
    return name


def extract_wheel(handle, dest: Path, seen: dict[str, tuple[str, str]], budget: list[int]) -> None:
    """wheel 하나를 ``dest``에 직접 푼다. ``budget``은 [남은 파일 수, 남은 바이트]."""
    try:
        archive = zipfile.ZipFile(handle)
    except zipfile.BadZipFile as exc:
        raise PackError("wheel을 열 수 없습니다") from exc
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 1:
                raise PackError("암호가 걸린 파일이 있습니다")
            mode = (info.external_attr >> 16) & 0o170000
            if mode not in (0, 0o100000):
                raise PackError(f"링크나 특수 파일이 있습니다: {info.filename[:60]}")
            rel = wheel_target(info.filename)
            if rel is None:
                continue
            budget[0] -= 1
            budget[1] -= info.file_size
            if budget[0] < 0 or budget[1] < 0:
                raise PackError("파일 수나 크기가 상한을 넘습니다")
            sha, written = hashlib.sha256(), 0
            target = dest / rel
            key = rel.lower()
            if key in seen and seen[key][0] != rel:
                raise PackError(f"대소문자만 다른 경로가 겹칩니다: {rel[:60]}")
            try:
                with archive.open(info) as source:
                    chunks = []
                    for block in iter(lambda: source.read(1 << 20), b""):
                        written += len(block)
                        if written > info.file_size:
                            raise PackError("압축 해제 크기가 선언과 다릅니다")
                        sha.update(block)
                        chunks.append(block)
                digest = sha.hexdigest()
                if key in seen:
                    if seen[key][1] != digest:
                        raise PackError(f"같은 경로의 내용이 서로 다릅니다: {rel[:60]}")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                fd = os.open(target, flags | getattr(os, "O_NOFOLLOW", 0), 0o644)
                with os.fdopen(fd, "wb") as out:
                    out.writelines(chunks)
                seen[key] = (rel, digest)
            except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
                raise PackError(f"파일을 풀지 못했습니다: {rel[:60]}") from exc


def tree_hashes(folder: Path) -> dict[str, str]:
    """준비 폴더의 파일 해시 목록(``.ready.json`` 제외). 링크가 있으면 ``PackError``."""
    found: dict[str, str] = {}
    for base, dirs, names in os.walk(folder, followlinks=False):
        for name in [*dirs, *names]:
            path = Path(base) / name
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise PackError(f"링크나 특수 파일이 있습니다: {name[:60]}")
            if name in names and (rel := path.relative_to(folder).as_posix()) != READY:
                found[rel] = sha256_file(path)
    return found


def tree_digest(files: dict[str, str]) -> str:
    return sha256_bytes(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


def ready_status(folder: Path, digest: str) -> str:
    """준비 폴더 상태: ``missing``(없음)·``ok``·``bad``(내용이 다름)."""
    try:
        ready = json.loads((folder / READY).read_text(encoding="utf-8"))
    except OSError:
        return "missing"
    except ValueError:
        return "bad"
    try:
        files = tree_hashes(folder)
    except (OSError, PackError):
        return "bad"
    good = (
        isinstance(ready, dict) and ready.get("pack_sha256") == digest
        and ready.get("files") == files and ready.get("content_sha256") == tree_digest(files)
    )
    return "ok" if good else "bad"


def tree_signature(folder: Path) -> list:
    """준비 폴더의 (경로, 크기, 수정 시각) 목록. 내용을 읽지 않는다."""
    rows = []
    for base, _dirs, names in os.walk(folder, followlinks=False):
        for name in names:
            path = Path(base) / name
            info = path.lstat()
            rows.append([path.relative_to(folder).as_posix(), info.st_size, info.st_mtime_ns])
    return sorted(rows)


def ready_cached(folder: Path, digest: str, record: Path, write: bool = False) -> str:
    """목록용 ``ready_status``. 검증 작업이 남긴 기록(판본·시각·파일 크기와 수정 시각)이 지금과
    같으면 파일을 다시 읽지 않는다. 설치·변경·실행 때의 전체 검증은 그대로이다."""
    key = digest[:16]
    try:
        docs = json.loads(record.read_text(encoding="utf-8"))
        docs = docs if isinstance(docs, dict) else {}
    except (OSError, ValueError):
        docs = {}
    sig = tree_signature(folder) if folder.is_dir() else None
    held = docs.get(key)
    if sig is not None and isinstance(held, dict) and (
            held.get("pack_sha256") == digest and held.get("sig") == sig):
        return "ok"
    status = ready_status(folder, digest)
    if write and status == "ok" and sig is not None:
        docs[key] = {"pack_sha256": digest, "sig": sig, "at": time.time()}
        try:
            write_atomic(record, json.dumps(docs, sort_keys=True).encode(), 0o644)
        except OSError:
            pass
    return status


def check_blobs(digest: str, blobs: dict) -> dict:
    """받은 manifest·wheel(열린 파일 객체)을 승인 해시와 대조한다. 맞으면 manifest."""
    handle = blobs.get("manifest.json")
    if handle is None:
        raise PackError("묶음 목록이 없습니다")
    handle.seek(0)
    raw = handle.read(MANIFEST_MAX + 1)
    try:
        manifest = json.loads(raw) if len(raw) <= MANIFEST_MAX else None
    except ValueError:
        manifest = None
    if manifest is None or manifest_digest(manifest) != digest:
        raise PackError("묶음 목록이 승인된 해시와 다릅니다")
    for item in manifest_files(manifest):
        wheel = blobs.get(item["name"])
        if wheel is None:
            raise PackError(f"받지 못한 파일이 있습니다: {item['name'][:60]}")
        wheel.seek(0)
        sha, size = hashlib.sha256(), 0
        while block := wheel.read(1 << 20):
            size += len(block)
            sha.update(block)
        if size != item["size"] or sha.hexdigest() != item["sha256"]:
            raise PackError(f"파일이 목록과 다릅니다: {item['name'][:60]}")
    return manifest


def install_blobs(digest: str, blobs: dict, packs: Path) -> Path:
    """검증된 묶음을 ``packs/<앞 16>/``에 푼다. 끝까지 되었을 때만 그 이름이 생긴다."""
    manifest = check_blobs(digest, blobs)
    final = packs / digest[:16]
    stage = packs / f".tmp-{digest[:16]}-{os.getpid()}"
    try:
        packs.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(mode=0o755)
        seen: dict[str, tuple[str, str]] = {}
        budget = [PACK_MAX_FILES, PACK_MAX_BYTES]
        for item in manifest_files(manifest):
            blobs[item["name"]].seek(0)
            extract_wheel(blobs[item["name"]], stage, seen, budget)
        files = tree_hashes(stage)
        ready = {"pack_sha256": digest, "files": files, "content_sha256": tree_digest(files)}
        write_atomic(stage / READY, json.dumps(ready, indent=1).encode(), 0o644)
        if final.exists():
            old = packs / f".old-{digest[:16]}-{os.getpid()}"
            os.replace(final, old)
            shutil.rmtree(old, ignore_errors=True)
        os.replace(stage, final)
    except OSError as exc:
        raise PackError(f"준비 폴더를 만들지 못했습니다({type(exc).__name__})") from exc
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return final


def stage_blobs(blobs: dict, folder: Path) -> None:
    """검증된 파일을 사용자 캐시에 둔다(관리자 단계가 다시 검증하고 푼다)."""
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True, mode=0o700)
    for name, handle in blobs.items():
        handle.seek(0)
        write_atomic(folder / name, handle.read(), 0o600)


def read_staged(
    target: tuple[int, int] | None, folder: Path, limits: dict[str, int]
) -> dict | None:
    """``folder``의 파일을 사용자 권한으로 읽어 이 프로세스만 가진 임시 파일에 담는다.

    관리자가 사용자 캐시를 읽을 때 쓴다: 읽기는 내려간 자식이 하므로 링크 바꿔치기가 통하지 않고,
    담긴 내용은 이후 사용자가 바꿀 수 없다. 읽지 못하거나 상한을 넘으면 None.
    """
    sinks = {name: tempfile.TemporaryFile() for name in limits}

    def work() -> int:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            for name, cap in limits.items():
                with os.fdopen(os.open(folder / name, flags), "rb") as source:
                    got = 0
                    for block in iter(lambda: source.read(1 << 20), b""):
                        got += len(block)
                        if got > cap:
                            return 1
                        sinks[name].write(block)
                sinks[name].flush()
        except OSError:
            return 1
        return 0

    if target is None:
        code = work()
    else:
        pid = os.fork()
        if pid == 0:
            code = 1
            try:
                os.setgroups([])
                os.setresgid(target[1], target[1], target[1])
                os.setresuid(target[0], target[0], target[0])
                code = work()
            except BaseException:
                pass
            os._exit(code)
        _, status = os.waitpid(pid, 0)
        code = status
    return sinks if code == 0 else None


def pack_state(
    name: str, contract: dict, programs: Path, staged: Path, permits: dict, now: float
) -> str:
    """서버 하나의 화면 상태. 묶음 서버가 아니면 사용 가능."""
    pack = contract.get("pack")
    if not isinstance(pack, dict):
        return S_READY
    digest = str(pack.get("sha256", ""))
    if not os.path.exists(str(contract.get("executable", ""))):
        return S_NOPROG
    found = ready_cached(programs / PACKS / digest[:16], digest, programs / PACK_VERIFIED)
    if found == "bad":
        return S_BAD
    if found == "missing":
        return S_WORK if (staged / digest[:16]).is_dir() else S_NEED
    permit = permits.get(name) if isinstance(permits.get(name), dict) else {}
    until = parse_time(permit.get("permit_until"))
    if permit.get("pack_sha256") != digest or until is None or until <= now:
        return S_EXPIRED
    return S_READY


def server_evidence(home: Path, name: str) -> list[bool]:
    """서버 하나의 단계 근거(실행기 기록): 시작 검증 통과, 도구 목록 받음, 첫 호출 성공."""
    base = home / STATE_REL

    def listed(folder: str) -> bool:
        try:
            for path in (base / folder).glob("*.json"):
                try:
                    if json.loads(path.read_text(encoding="utf-8")).get("server") == name:
                        return True
                except (OSError, ValueError, AttributeError):
                    continue
        except OSError:
            pass
        return False

    return [listed(LAUNCHED), listed(TOOLS_DIR), (base / CALLED / name).is_file()]


def parse_time(text: object) -> float | None:
    """ISO 8601 시각(Z·소수 자리 길이 무관) -> 초. 읽지 못하면 None."""
    if not isinstance(text, str):
        return None
    fixed = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], text.strip())
    try:
        moment = datetime.fromisoformat(fixed.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).timestamp()  # noqa: UP017


# --- 게이트웨이 호출(키트 키) -----------------------------------------------------------------
GATEWAY_TIMEOUT = 10
ME_PATH = "/mint/v1/endpoint/me"
INTAKES_PATH = "/mint/v1/endpoint/intakes"
PACK_PATH = "/mint/v1/endpoint/packs"
NO_GATEWAY = "게이트웨이에 닿지 못함"


class Gateway:
    """키트 키로 단말 경로를 부른다. 닿지 못하면 상태 0."""

    def __init__(self, base: str, key: str, ca_pem: str | None = None) -> None:
        self.base, self.key, self.ca_pem = base.rstrip("/"), key, ca_pem

    def call(self, method: str, path: str, body: object = None, limit: int = 1 << 20):
        """(상태, 본문 바이트). 본문이 ``limit``을 넘으면 상태 -1."""
        import ssl

        data = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {self.key}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method
        )
        context = None
        if self.base.startswith("https:"):
            context = ssl.create_default_context(cadata=self.ca_pem or None)
        try:
            with urllib.request.urlopen(request, timeout=GATEWAY_TIMEOUT, context=context) as r:
                raw = r.read(limit + 1)
                return (r.status, raw) if len(raw) <= limit else (-1, b"")
        except urllib.error.HTTPError as error:
            return error.code, error.read(65536)
        except (OSError, ValueError):
            return 0, b""

    def json(self, method: str, path: str, body: object = None):
        status, raw = self.call(method, path, body)
        try:
            doc = json.loads(raw) if raw else None
        except ValueError:
            doc = None
        return status, doc

    def download(self, path: str, cap: int):
        """파일을 임시 파일로 받는다. (상태, 파일 또는 None)."""
        import ssl

        request = urllib.request.Request(
            self.base + path, headers={"Authorization": f"Bearer {self.key}"}
        )
        context = None
        if self.base.startswith("https:"):
            context = ssl.create_default_context(cadata=self.ca_pem or None)
        sink = tempfile.TemporaryFile()
        try:
            with urllib.request.urlopen(request, timeout=GATEWAY_TIMEOUT, context=context) as r:
                got = 0
                for block in iter(lambda: r.read(1 << 20), b""):
                    got += len(block)
                    if got > cap:
                        sink.close()
                        return -1, None
                    sink.write(block)
            sink.flush()
            return 200, sink
        except urllib.error.HTTPError as error:
            sink.close()
            return error.code, None
        except OSError:
            sink.close()
            return 0, None


def fetch_pack(gateway: Gateway, server: str, digest: str, progress=None) -> dict:
    """승인된 묶음의 manifest와 wheel을 받아 열린 임시 파일 목록(이름 -> 파일)으로.

    ``progress``가 있으면 파일 하나를 받을 때마다 「묶음 받는 중 n/m」을 알린다.
    """
    base = f"{PACK_PATH}/{urllib.parse.quote(server, safe='')}/{digest}/"
    blobs: dict = {}
    try:
        status, handle = gateway.download(base + "manifest.json", MANIFEST_MAX)
        if status != 200:
            raise PackError(pack_http_text(status))
        blobs["manifest.json"] = handle
        try:
            manifest = json.loads(handle.seek(0) or handle.read())
        except ValueError as exc:
            raise PackError("묶음 목록을 읽을 수 없습니다") from exc
        if manifest_digest(manifest) != digest:
            raise PackError("묶음 목록이 승인된 해시와 다릅니다")
        files = list(manifest_files(manifest))
        for number, item in enumerate(files, 1):
            if progress:
                progress(f"묶음 받는 중 {number}/{len(files)}")
            status, handle = gateway.download(base + item["name"], item["size"])
            if status != 200:
                raise PackError(pack_http_text(status))
            blobs[item["name"]] = handle
    except BaseException:
        for opened in blobs.values():
            opened.close()
        raise
    return blobs


def pack_http_text(status: int) -> str:
    if status == 0:
        return NO_GATEWAY
    if status in (401, 403):
        return KEY_REJECTED_TEXT
    if status == 404:
        return "승인된 묶음이 아니거나 범위가 바뀌었습니다"
    if status == -1:
        return "받은 파일이 목록보다 큽니다"
    return f"묶음을 받지 못했습니다(HTTP {status})"


# --- 도입 신청 명령 해석(단말은 서버를 실행하지 않는다) ------------------------------------------
SPEC_TEXT = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([A-Za-z0-9._,-]+)\])?"
    r"(?:(?:==|@)([A-Za-z0-9][A-Za-z0-9.+!_-]*))?$"
)
MODULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL", re.IGNORECASE)
WIN_ABS = re.compile(r"^[A-Za-z]:[\\/]")
MAX_ARGV = 64
GRADES = ("public", "internal", "confidential", "restricted")
GRADE_NAMES = {"공개": "public", "내부": "internal", "기밀": "confidential", "제한": "restricted"}
GRADE_TEXT = {value: name for name, value in GRADE_NAMES.items()}
GRADE_CHOICES = "·".join(GRADE_NAMES)


def parse_grade(text: str) -> str | None:
    """한국어 이름이나 내부 값을 내부 값으로. 모르면 None."""
    text = text.strip().lower()
    return GRADE_NAMES.get(text) or (text if text in GRADES else None)


class AddError(Exception):
    """신청 명령을 해석하지 못한 사유(사람이 읽는 문장)."""


def split_spec(text: str) -> tuple[str, list[str], str | None]:
    match = SPEC_TEXT.match(text)
    if not match:
        raise AddError("패키지는 이름==판본 형식으로 적으십시오")
    version = None if match.group(3) in (None, "latest") else match.group(3)
    extras = sorted(e for e in (match.group(2) or "").split(",") if e)
    return match.group(1), extras, version


def norm_dist(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def installed_version(name: str, home: Path) -> str | None:
    """이 단말의 uv·pipx 도구 환경에 깔린 판본(없으면 이 인터프리터의 것)."""
    for tool in (home / ".local/share/uv/tools" / name, home / ".local/share/pipx/venvs" / name):
        for pattern in ("lib/python*/site-packages/*.dist-info", "Lib/site-packages/*.dist-info"):
            for info in sorted(tool.glob(pattern)):
                dist, _, version = info.name[: -len(".dist-info")].rpartition("-")
                if norm_dist(dist) == norm_dist(name) and version:
                    return version
    try:
        from importlib import metadata

        return metadata.version(name)
    except Exception:
        return None


def dist_for_module(module: str) -> str:
    top = module.split(".")[0]
    try:
        from importlib import metadata

        found = metadata.packages_distributions().get(top)
        if found:
            return found[0]
    except Exception:
        pass
    return top.replace("_", "-")


GIT_FROM = re.compile(
    r"^git\+(https://(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)"
    r"/[A-Za-z0-9._-]+/([A-Za-z0-9._-]+?))(?:\.git)?@([0-9a-f]{40})$")


HAND_ADD = "`mint add 이름 -- uvx --from git+주소@커밋 실행이름`으로 신청하십시오"


def repo_command(url: str, fetch=None) -> list[str]:
    """GitHub 저장소 주소의 최신 커밋을 고정한 실행 명령(토큰). 못 찾으면 AddError."""
    owner, repo = repo_parts(url) or ("", "")
    if urllib.parse.urlsplit(url).hostname != "github.com":
        raise AddError("저장소 자동 확인은 GitHub만 지원합니다. " + HAND_ADD)

    def get(address: str):
        request = urllib.request.Request(address, headers={"User-Agent": "mint-kit"})
        with urllib.request.urlopen(request, timeout=8) as response:  # noqa: S310
            return response.read(1_000_000)

    fetch = fetch or get
    base = f"https://github.com/{owner}/{repo}"
    try:
        api = f"https://api.github.com/repos/{owner}/{repo}"
        branch = json.loads(fetch(api))["default_branch"]
        sha = json.loads(fetch(f"{api}/commits/{branch}"))["sha"]
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/"
        try:
            import tomllib

            doc = tomllib.loads(fetch(raw + "pyproject.toml").decode("utf-8"))
        except (urllib.error.HTTPError, ImportError, ValueError):
            doc = {}
        scripts = doc.get("project", {}).get("scripts") or {}
        if scripts:
            return ["uvx", "--from", f"git+{base}@{sha}", next(iter(scripts))]
        try:
            if json.loads(fetch(raw + "package.json")).get("bin"):
                raise AddError("Node.js 저장소는 화면(신청 등록)에서 신청하십시오")
        except urllib.error.HTTPError:
            pass
    except (OSError, ValueError, KeyError, TypeError):
        raise AddError("저장소 정보를 가져오지 못했습니다. " + HAND_ADD) from None
    raise AddError("실행 명령을 찾지 못했습니다. " + HAND_ADD)


NPM_REF = re.compile(
    r"^((?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)(?:@([A-Za-z0-9][A-Za-z0-9._+-]{0,63}))?$")
NPM_INTEGRITY = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
BIN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def npm_command_spec(rest: list[str], fetch=None) -> dict:
    """``npx -y 이름[@판본] [인자]``를 레지스트리의 정확한 판본과 dist.integrity로 고정한 명세로."""
    rest = list(rest)
    while rest and rest[0] in ("-y", "--yes"):
        rest.pop(0)
    if not rest or rest[0].startswith("-"):
        raise AddError("패키지 이름이 없거나 지원하지 않는 옵션입니다: npx -y 패키지@판본")
    found = NPM_REF.match(rest[0])
    if not found:
        raise AddError("npm 패키지는 `이름` 또는 `이름@판본` 형태로 적으십시오")
    name, argv = found.group(1), rest[1:]
    if len(argv) > MAX_ARGV or any(len(a) > 4096 or chr(0) in a for a in argv):
        raise AddError("인자가 너무 많거나 깁니다")

    def get(address: str):
        request = urllib.request.Request(address, headers={"User-Agent": "mint-kit"})
        with urllib.request.urlopen(request, timeout=8) as response:  # noqa: S310
            return response.read(1_000_000)

    try:
        doc = json.loads((fetch or get)(
            f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}/"
            f"{urllib.parse.quote(found.group(2) or 'latest')}"))
        version, integrity = doc["version"], doc["dist"]["integrity"]
    except urllib.error.HTTPError as exc:
        raise AddError("npm 레지스트리에 그 패키지·판본이 없습니다" if exc.code == 404
                       else "npm 레지스트리가 응답하지 않습니다") from None
    except (OSError, ValueError, KeyError, TypeError):
        raise AddError("npm 레지스트리에서 판본과 무결성 해시를 가져오지 못했습니다") from None
    if not (isinstance(version, str) and isinstance(integrity, str)
            and NPM_INTEGRITY.match(integrity)):
        raise AddError("npm 레지스트리에 무결성 해시(sha512)가 없습니다")
    short, bins = name.rsplit("/", 1)[-1], doc.get("bin")
    keys = [k for k in bins if isinstance(k, str)] if isinstance(bins, dict) else []
    command = short if short in keys or not keys else keys[0]
    return {"index": "npm", "name": name, "version": version, "integrity": integrity,
            "extras": [], "command": command if BIN_NAME.match(command) else short,
            "argv": argv}  # fmt: skip


def parse_command(tokens: list[str], home: Path, fetch=None) -> dict:
    """``uvx``·``pipx run``·``npx``·``python -m`` 명령을 신청 명세로 바꾼다. 실행하지 않는다."""
    if not tokens:
        raise AddError("실행할 명령을 적으십시오")
    exe = re.sub(r"\.(exe|cmd|bat)$", "", tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower())
    rest = list(tokens[1:])
    origin_flag = ""
    if exe == "npx":
        return npm_command_spec(rest, fetch)
    if exe == "uvx" or (exe == "uv" and rest[:2] == ["tool", "run"]):
        rest = rest[2:] if exe == "uv" else rest
        origin_flag = "--from"
    elif exe == "pipx" and rest[:1] == ["run"]:
        rest, origin_flag = rest[1:], "--spec"
    elif exe in ("python", "python3", "py") and rest[:1] == ["-m"] and len(rest) >= 2:
        module = rest[1]
        if not MODULE_NAME.match(module):
            raise AddError("모듈 이름이 올바르지 않습니다")
        return finish_spec(dist_for_module(module), [], None, module, rest[2:], home)
    else:
        raise AddError("P1은 PyPI 패키지만 신청할 수 있습니다")
    origin = None
    while rest and rest[0].startswith("-"):
        flag = rest.pop(0)
        if flag == origin_flag and rest:
            origin = rest.pop(0)
        elif flag.startswith(origin_flag + "="):
            origin = flag.split("=", 1)[1]
        else:
            raise AddError(f"지원하지 않는 옵션입니다: {flag[:30]}")
    if not rest:
        raise AddError("패키지 이름이 없습니다")
    first = rest.pop(0)
    if origin and (git := GIT_FROM.match(origin)):  # 커밋으로 고정한 저장소 출처
        if len(rest) > MAX_ARGV or any(len(a) > 4096 or chr(0) in a for a in rest):
            raise AddError("인자가 너무 많거나 깁니다")
        return {"index": "git", "git": git.group(1), "name": git.group(2), "version": git.group(3),
                "extras": [], "command": first, "argv": list(rest)}  # fmt: skip
    if origin:
        name, extras, version = split_spec(origin)
        return finish_spec(name, extras, version, first, rest, home)
    name, extras, version = split_spec(first)
    return finish_spec(name, extras, version, name, rest, home)


def finish_spec(name, extras, version, command, argv, home: Path) -> dict:
    version = version or installed_version(name, home)
    if not version:
        raise AddError("판본을 지정하십시오: 이름==판본")
    if len(argv) > MAX_ARGV or any(len(a) > 4096 or chr(0) in a for a in argv):
        raise AddError("인자가 너무 많거나 깁니다")
    return {"index": "pypi", "name": name, "version": version, "extras": extras,
            "command": command, "argv": list(argv)}  # fmt: skip


def harness_entry(home: Path, harness: str, name: str) -> dict | None:
    """하네스 설정에서 로컬 MCP 항목 하나(명령·인자·환경 변수)."""
    found: list[dict] = []

    def add(kind: str, servers: object) -> None:
        entry = servers.get(name) if isinstance(servers, dict) else None
        if kind == harness and isinstance(entry, dict):
            found.append(entry)

    read_mcp_sources(home, add)
    return found[0] if found else None


def entry_tokens(entry: dict) -> list[str]:
    command, args = entry.get("command"), entry.get("args")
    if not isinstance(command, str) or not command.strip():
        raise AddError("이 항목은 로컬 명령이 아닙니다")
    return [command, *[a for a in (args if isinstance(args, list) else []) if isinstance(a, str)]]


def path_candidates(argv: list[str]) -> list[str]:
    """인자 중 절대 경로(파일 접근 후보)."""
    return list(dict.fromkeys(
        a for a in argv if len(a) <= 1024 and (a.startswith("/") or WIN_ABS.match(a))
    ))


def build_intake(request_id, server_id, spec, access, network, hosts, env_names, purpose,
                 grade) -> dict:  # fmt: skip
    return {
        "request_id": request_id, "server_id": server_id, "spec": spec,
        "file_access": [{"path": p, "mode": m} for p, m in access],
        "network": network, "allowed_hosts": hosts if network == "hosts" else [],
        "env_names": env_names, "purpose": purpose, "data_grade": grade, "resources": [],
    }  # fmt: skip


def submit_text(status: int, doc: object) -> str:
    """제출 응답을 사람 문구로."""
    if status == 201:
        return "신청했습니다"
    detail = ""
    if isinstance(doc, dict):
        raw = doc.get("error") or doc.get("detail") or doc.get("message")
        detail = raw if isinstance(raw, str) else ""
    if status == 409:
        return "같은 서버가 진행 중이거나 이미 승인되었습니다"
    if status == 429:
        return "신청 한도를 넘었습니다. 잠시 뒤 다시 시도하십시오"
    if status in (400, 422):
        return "신청 내용이 맞지 않습니다" + (f": {detail[:80]}" if detail else "")
    if status in (401, 403, 404):
        return KEY_REJECTED_TEXT
    if status == 0:
        return NO_GATEWAY
    return f"신청하지 못했습니다(HTTP {status})"


def ask(question: str, default: str, read=input) -> str:
    try:
        answer = read(f"{question} [{default}] " if default else f"{question} ").strip()
    except EOFError:
        answer = ""
    return answer or default


def confirm(read=input, key=None) -> bool:
    """키 하나로 확정: Enter나 y는 신청, 그 밖은 취소. 줄 입력이면 Enter가 신청이다."""
    if key is not None:
        print("신청할까요? (Enter 신청, n 취소) ", end="", flush=True)
        answer = key()
        print(answer if len(answer) == 1 else "")
        return answer in ("y", "enter")
    return ask("신청할까요? (Enter 신청, n 취소)", "y", read).lower() in ("y", "yes")


LAUNCHERS = ("uvx", "uv", "pipx", "python", "python3", "py")
REMOTE_PORTS = (443, 8443)  # 서버 기본값. 관리자가 넓혔다면 서버가 받아 준다


def is_url(text: object) -> bool:
    return isinstance(text, str) and re.match(r"^https?://", text, re.IGNORECASE) is not None


def remote_problem(url: str) -> str | None:
    """원격 주소 규칙을 어긴 사유(사람 문구). 맞으면 None."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return "주소 형식이 올바르지 않습니다"
    if parts.scheme != "https":
        return "주소는 https로 시작해야 합니다"
    if not parts.hostname or len(url) > 2048 or any(c.isspace() or c == "\\" for c in url):
        return "주소 형식이 올바르지 않습니다"
    if parts.username is not None or parts.password is not None or "?" in url or "#" in url:
        return "주소에 계정·쿼리·조각을 넣을 수 없습니다"
    if (port or 443) not in REMOTE_PORTS:
        return f"포트 {port}은(는) 쓸 수 없습니다. 허용 포트: " + ", ".join(map(str, REMOTE_PORTS))
    if repo_parts(url):
        return ("소스 저장소 주소입니다(MCP 서버 주소가 아님). 원격 MCP라면 서버의 MCP 주소"
                "(예: …/mcp)를, 이 PC에서 실행하는 MCP라면"
                f" `mint add {remote_name(url)} -- <실행 명령>`으로 신청하십시오")
    return None


CODE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")


def repo_parts(url: str) -> tuple[str, str] | None:
    """소스 저장소 주소(``https://github.com/<소유자>/<저장소>``)면 (소유자, 저장소)."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    segs = [s for s in parts.path.split("/") if s]
    if (parts.hostname or "").lower() not in CODE_HOSTS or len(segs) < 2:
        return None
    if len(segs) > 2 and segs[2] not in ("tree", "blob", "-"):
        return None
    return segs[0], segs[1].removesuffix(".git")


def remote_name(url: str) -> str:
    """주소에서 서버 이름. 저장소 주소면 저장소 이름, 아니면 호스트(맨 앞 mcp·www·api 칸 제외).

    LiteLLM은 서버 이름에 하이픈을 받지 않으므로 영문·숫자·밑줄만 쓴다.
    """
    repo = repo_parts(url)
    if repo:
        base = repo[1]
    else:
        labels = (urllib.parse.urlsplit(url).hostname or "server").split(".")
        while len(labels) > 2 and labels[0] in ("mcp", "www", "api"):
            labels.pop(0)
        base = "_".join(labels)
    return re.sub(r"[^A-Za-z0-9_]+", "_", base).strip("_")[:128] or "server"


def inferred_hosts(argv: list[str], env_values: dict[str, str]) -> list[str]:
    """인자·환경 변수 값에 주소가 있으면 그 호스트(host:port). 없으면 빈 목록."""
    found: list[str] = []
    for value in [*argv, *env_values.values()]:
        if not is_url(value):
            continue
        try:
            parts = urllib.parse.urlsplit(value)
            host = f"{parts.hostname}:{parts.port or (443 if parts.scheme == 'https' else 80)}"
        except ValueError:
            continue
        if parts.hostname and host not in found:
            found.append(host)
    return found


def resolve_target(args, home: Path) -> tuple[str | None, str | None, list[str], list[str]]:
    """(서버 이름, 원격 주소, 명령 토큰, 하네스 항목의 환경 변수 이름). 대상은 주소 아니면 명령."""
    name, tokens = args.name, list(args.command or [])
    if args.source:
        harness, _, item = args.source.partition(":")
        entry = harness_entry(home, harness, item)
        if entry is None:
            raise AddError("그 하네스 설정에서 항목을 찾지 못했습니다")
        name = name or item
        if is_url(entry.get("url")) and not entry.get("command"):
            return name, entry["url"], [], []
        env_names = sorted(k for k in (entry.get("env") or {}) if isinstance(k, str))
        return name, None, entry_tokens(entry), env_names
    if is_url(name) and not tokens:
        return None, name, [], []
    if len(tokens) == 1 and is_url(tokens[0]):
        return name, tokens[0], [], []
    if name and name.lower() in LAUNCHERS:  # 이름 없이 명령만 적은 경우
        name, tokens = None, [args.name, *tokens]
    return name, None, tokens, []


def key_refused(gateway: Gateway, out=print) -> bool:
    """키가 거절되었으면 물어보기 전에 안내하고 참을 돌려준다."""
    if gateway.json("GET", ME_PATH)[0] in (401, 403, 404):
        out(KEY_REJECTED_TEXT)
        return True
    return False


def run_add(
    args, home: Path, gateway: Gateway, out=print, read=input, tty: bool = False, key=None
) -> int:
    """``mint add``. 대상(명령 또는 원격 주소)과 목적만 받는다. 서버는 실행하지 않는다."""
    if key_refused(gateway, out):
        return 1
    mark_fast(home / STATE_REL, time.time())  # 승인이 곧 올 테니 보고기가 짧은 주기로 돈다
    try:
        server_id, url, tokens, env_names = resolve_target(args, home)
        if url and repo_parts(url):  # 저장소 주소는 최신 커밋을 고정한 로컬 신청으로
            server_id = server_id or remote_name(url)
            tokens, url = repo_command(url), None
        spec = None if url else parse_command(tokens, home)
        server_id = server_id or (remote_name(url) if url else spec["name"])
        if url:
            server_id = server_id.replace("-", "_")  # LiteLLM은 서버 이름에 하이픈을 받지 않는다
        if not SERVER_NAME.match(server_id):
            raise AddError("서버 이름은 영문·숫자·._-로 적으십시오")
        if url and (why := remote_problem(url)):
            raise AddError(why)
        env_values, plain = parse_env(args.env or [])
    except AddError as exc:
        out(str(exc))
        return 2
    interactive = tty and not args.yes
    purpose = args.purpose or (ask("목적", "", read) if interactive else "")
    if not purpose:
        out("목적을 적으십시오" if interactive else "목적(--purpose)을 적으십시오")
        return 2
    secrets: list[str] = []
    if url:
        rows = [("이름", server_id), ("주소", url), ("목적", purpose[:70])]
        body = {"request_id": args.request_id or str(uuid.uuid4()), "server_id": server_id,
                "url": url, "transport": "sse" if url.rstrip("/").endswith("/sse") else "http",
                "purpose": purpose[:256]}  # fmt: skip
    else:
        env_names = sorted({*env_names, *plain})
        secrets = [n for n in env_names if SECRET_NAME.search(n)]
        candidates = path_candidates(spec["argv"])
        access = {p: "ro" for p in candidates}
        access.update({p: "ro" for p in args.ro or []})
        access.update({p: "rw" for p in args.rw or []})
        for path in env_paths(env_values):  # 경로처럼 보이는 환경 변수 값은 읽기로 자동
            if path not in access:
                access[path] = "ro"
                out(f"파일 접근에 읽기로 더했습니다: {path[:50]}")
        hosts = list(args.host or []) or (
            [] if args.network == "none" else inferred_hosts(spec["argv"], env_values))
        network = args.network or ("hosts" if hosts else None)
        if network == "hosts" and not hosts:
            out("hosts에는 허용 호스트(--host)가 필요합니다")
            return 2
        grade = parse_grade(args.grade or "internal")  # 등급은 내부 값이다(--grade로만 바꾼다)
        if grade is None:
            out(f"자료 등급은 {GRADE_CHOICES} 중 하나입니다")
            return 2
        package = spec["name"] + (f"[{','.join(spec['extras'])}]" if spec["extras"] else "")
        package = (f"{spec['git']}@{spec['version'][:12]}" if spec["index"] == "git"
                   else f"{package}@{spec['version']}" if spec["index"] == "npm"
                   else f"{package}=={spec['version']}")
        rows = [
            ("이름", server_id), ("패키지", package),
            ("명령", " ".join([spec["command"], *spec["argv"]])[:70]),
            ("파일 접근", ", ".join(
                f"{p} ({'쓰기' if m == 'rw' else '읽기'})" for p, m in access.items()) or "없음"),
            ("네트워크", "자동" if network is None
             else "없음" if network == "none" else ", ".join(hosts)),
            ("환경 변수", ", ".join([*env_names, *(f"{k}={v}" for k, v in env_values.items())])[:70]
             or "없음"), ("목적", purpose[:70]),
        ]  # fmt: skip
        if grade != "internal":
            rows.append(("자료 등급", GRADE_TEXT[grade]))
        body = build_intake(
            args.request_id or str(uuid.uuid4()), server_id, spec, list(access.items()), network,
            hosts, env_names, purpose, grade,
        )
        if env_values:
            body["env"] = env_values  # 서버 본문의 최상위 env(명세 안이 아니다)
    for label, value in rows:
        out(f"{pad(label, 10)}{value}")
    for name in secrets:
        out(f"{name}은(는) 비밀로 보입니다. 관리자가 비밀 참조로 등록합니다")
    status, doc = gateway.json("POST", INTAKES_PATH, body)
    out(submit_text(status, doc))
    if status == 201:
        out(f"신청 번호 {doc.get('id') if isinstance(doc, dict) else ''}".strip())
        return 0
    return 1


# --- 표시 폭(한글은 두 칸) ----------------------------------------------------------------------
def cell_width(text: str) -> int:
    return sum(
        0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in "WF" else 1
        for c in text
    )


def clip(text: str, width: int) -> str:
    if cell_width(text) <= width:
        return text
    out, used = "", 0
    for char in text:
        step = cell_width(char)
        if used + step > width - 2:
            break
        out, used = out + char, used + step
    return out + ".."


def pad(text: str, width: int) -> str:
    return text + " " * max(width - cell_width(text), 0)


STAGE_NAMES = {
    "received": "접수", "pack": "묶음 준비", "inspect": "검사 중", "passed": "검사 통과",
    "indeterminate": "판별 불가", "failed": "검사 실패", "approved": "승인", "rejected": "거절",
    "withdrawn": "철회",
}
STAGE_FLOW = ("received", "pack", "inspect")
NEXT_TEXT = {"wait": "검사가 끝나기를 기다림", "none": "없음"}


def stage_path(stage: object) -> str:
    """접수부터 지금 단계까지(예: 접수 > 묶음 준비 > 검사 중 > 판별 불가)."""
    if stage not in STAGE_NAMES:
        return "-"
    steps = list(STAGE_FLOW[: STAGE_FLOW.index(stage) + 1]) if stage in STAGE_FLOW else [
        *STAGE_FLOW, stage]
    return " > ".join(STAGE_NAMES[k] for k in steps)


def next_text(row: dict) -> str:
    value = str(row.get("next") or "")
    return NEXT_TEXT.get(value, value) or "-"


def row_label(row: dict) -> str:
    return STAGE_NAMES.get(str(row.get("stage"))) or intake_label(
        row.get("status"), row.get("decision"))


def intake_label(status: object, decision: object) -> str:
    if decision in ("approved", "approve"):
        return "승인"
    if decision in ("rejected", "reject", "denied"):
        return "거절"
    if decision == "withdrawn" or status == "withdrawn":
        return "철회"
    names = {
        "received": "접수", "checking": "검사 중", "building": "묶음 준비", "passed": "검사 통과",
        "indeterminate": "판별 불가", "failed": "검사 실패", "decided": "결정",
    }
    return names.get(str(status), str(status or "-"))


NEXT_BY_STATE = {
    S_NEED: "곧 자동으로 받습니다. 급하면 s 키",
    S_FAILED: "s 키로 다시 받으십시오",
    S_START: "하네스에서 서버를 시작하면 확인됩니다",
    S_WORK: "관리자 단계가 마칠 때까지 기다리십시오",
    S_EXPIRED: "r 키로 다시 보고하십시오",
    S_NOPROG: "관리자에게 런타임 설치를 요청하십시오",
    S_BAD: "s 키로 다시 받으십시오",
    S_WAIT: "r 키로 다시 보고하십시오",
}
TABS = ("상태", "내 서버", "도입 신청")
HELP = "1-3 탭  위/아래 선택  Enter 상세  n 신청  s 받기  c 점검  r 새로고침  o 웹  q 끝"


def next_step(model: dict) -> str:
    """화면에 이미 있는 값만으로 지금 가장 쓸모 있는 한 가지를 고른다."""
    if not model["connected"]:
        return "한 줄 설치 명령을 다시 붙여 넣으십시오"
    failed = next((r for r in model["servers"] if r["state"] == S_FAILED), None)
    if failed:
        why = f" ({clip(str(failed['reason']), 30)})" if failed.get("reason") else ""
        return f"{clip(failed['name'], 20)} 받기 실패{why}: 2 탭에서 s 키"
    if model.get("inspections"):
        return "3 탭에서 단말 검사를 제출하십시오"
    if model["intakes"] and model["intakes"][0].get("stage") == "failed":
        return "3 탭에서 검사 실패 사유를 확인하십시오"
    todo = next((r for r in model["servers"] if r["state"] in NEXT_BY_STATE), None)
    if todo:
        return f"{clip(todo['name'], 20)}: {NEXT_BY_STATE[todo['state']]}"
    return "할 일 없음"


def tab1_lines(model: dict) -> list[str]:
    key = {"ok": "유효", "rejected": "거절됨"}.get(model["key"], "확인하지 못함")
    lines = [
        ("게이트웨이", "연결됨" if model["connected"] else NO_GATEWAY),
        ("사용자", model.get("user") or "-"), ("키", key),
        ("설치 방식", model["mode"]), ("하네스", ", ".join(model["harnesses"]) or "-"),
        ("MCP 서버", f"{model['server_count']}개"),
    ]
    out = [f"{pad(a, 12)}{b}" for a, b in lines]
    problems = model["problems"]
    out.append(f"{pad('점검', 12)}{'이상 없음' if not problems else f'문제 {len(problems)}건'}")
    out += [f"  - {p}" for p in problems]
    out.append(f"{pad('다음 할 일', 12)}{next_step(model)}")
    return out


def tab2_lines(model: dict, ui: dict) -> list[str]:
    servers = model["servers"]
    if not servers:
        return ["나에게 승인된 서버가 없습니다"]
    out = [f"  {pad('서버', 26)}{pad('종류', 6)}{pad('상태', 22)}실행 허가"]
    for i, row in enumerate(servers):
        mark = ">" if i == ui["cursor"] else " "
        until = (row.get("permit_until") or "")[:16].replace("T", " ")
        out.append(
            f"{mark} {pad(clip(row['name'], 25), 26)}{pad(row['kind'], 6)}"
            f"{pad(row['state'], 22)}{until}"
        )
    if ui["detail"] and servers:
        row = servers[min(ui["cursor"], len(servers) - 1)]
        out += ["", f"{row['name']}  {row['state']}"]
        if row.get("pack_sha256"):
            out.append(f"  묶음 {row['pack_sha256'][:16]}")
        if row.get("reason") and row["state"] == S_FAILED:
            out.append("  사유 " + clip(str(row["reason"]), 70))
        if row["state"] in NEXT_BY_STATE:
            out.append("  " + NEXT_BY_STATE[row["state"]])
        if row.get("kind") == "묶음" and row.get("steps"):
            steps = zip(STEP_NAMES, row["steps"], strict=False)
            out += [f"  {n} {'예' if ok else '-'}" for n, ok in steps]
    return out


def tab3_lines(model: dict, ui: dict) -> list[str]:
    intakes, found = model["intakes"], model["found"]
    out = ["신청한 서버가 없습니다"]
    if intakes:
        out = [f"  {pad('서버', 26)}{pad('상태', 14)}다음 할 일"]
    for i, row in enumerate(intakes):
        mark = ">" if i == ui["cursor"] else " "
        need = model.get("inspections", {}).get(row.get("id"))
        later = inspect_text(need) if need else next_text(row)
        out.append(
            f"{mark} {pad(clip(str(row.get('server_id', '')), 25), 26)}{pad(row_label(row), 14)}"
            f"{clip(later, 36)}"
        )
    if ui["detail"] and ui["cursor"] < len(intakes):
        row = intakes[ui["cursor"]]
        need = model.get("inspections", {}).get(row.get("id"))
        reason, later = str(row.get("reason") or "-"), next_text(row)
        if need:  # 검사 상태가 서버 사유보다 앞선다
            reason = "단말 검사 제출함" if need.get("phase") == "submitted" else "단말 검사 필요"
            later = inspect_text(need, detail=True)
        out += ["", f"진행  {clip(stage_path(row.get('stage')), 70)}",
                f"사유  {clip(reason, 70)}", f"다음  {clip(later, 70)}"]  # fmt: skip
    if found:
        out += ["", "이 PC의 관리되지 않는 로컬 MCP (Enter로 신청)"]
        for j, item in enumerate(found):
            mark = ">" if len(intakes) + j == ui["cursor"] else " "
            blocked = "  관리 정책으로 막힘 · 신청 필요" if item.get("blocked") else ""
            out.append(f"{mark} {item['harness']}:{item['name']}{blocked}")
    return out


def screen_color(text: str, code: str, color: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if color else text


def screen_box(title: str, rows: list[str], width: int, color: bool) -> list[str]:
    inner = width - 4
    title = clip(title, inner - 3)
    border = lambda value: screen_color(value, "90", color)  # noqa: E731
    top = border("╭─ ") + screen_color(title, "1", color) + border(
        " " + "─" * max(0, width - cell_width(title) - 5) + "╮")
    lines = [top]
    for row in rows:
        row = clip("".join(c if c.isprintable() else " " for c in row), inner)
        role = "32" if any(x in row for x in ("사용 가능", "연결됨", "이상 없음")) else (
            "31" if any(x in row for x in ("차단", "막힘", "실패", "거절")) else
            "33" if any(x in row for x in ("대기", "필요", "검사 중", "동의")) else "0")
        lines.append(border("│ ") + screen_color(row, role, color) +
                     " " * (inner - cell_width(row)) + border(" │"))
    return [*lines, border("╰" + "─" * (width - 2) + "╯")]


def render_screen(model: dict, ui: dict, width: int = 80, height: int = 24,
                  color: bool = False) -> list[str]:
    """화면 한 장. ANSI 코드는 표시 폭에 포함하지 않는다."""
    width, height = max(width, 40), max(height, 12)
    state = "● 연결됨" if model["connected"] else "● " + NO_GATEWAY
    mark = screen_color(" MINT ", "1;7;94", color)
    title = " 엔드포인트 · MCP 연결 관리"
    head = mark + title + " " * max(1, width - 6 - cell_width(title) - cell_width(state))
    head += screen_color(state, "32" if model["connected"] else "31", color)
    # 상태 탭은 건수가 없다. 서버·신청 탭에만 건수를 붙인다.
    counts = (None, len(model["servers"]), len(model["intakes"]))
    bad = sum(1 for r in model["servers"] if r["state"] in (S_FAILED, S_BAD))
    waits = len(model.get("inspections") or {})
    extra = ("", f" 실패 {bad}" if bad else "", f" 검사 {waits}" if waits else "")
    names = [f"{i + 1} {t}" + (f" {counts[i]}{extra[i]}" if counts[i] is not None else "")
             for i, t in enumerate(TABS)]
    tabs = "  ".join(screen_color(f" {n} ", "7", color) if i == ui["tab"] else f" {n} "
                     for i, n in enumerate(names))
    if not color:
        tabs = "  ".join(f"[{n}]" if i == ui["tab"] else f" {n} " for i, n in enumerate(names))
    tab = ui["tab"]
    body = (tab1_lines(model), tab2_lines(model, ui), tab3_lines(model, ui))[tab]
    sections = []
    if tab == 2 and model["found"]:
        cut = next(i for i, line in enumerate(body) if line.startswith("이 PC의 관리되지"))
        sections = [(f"도입 신청 · {len(model['intakes'])}", body[:cut]),
                    (f"이 PC의 관리되지 않는 로컬 MCP · {len(model['found'])}", body[cut + 1:])]
    else:
        titles = ("연결 상태", "승인된 MCP 서버", "도입 신청")
        sections = [(titles[tab] if counts[tab] is None else f"{titles[tab]} · {counts[tab]}",
                     body)]
    available = height - 7
    # 선택 항목이 화면에 남도록 앞의 행부터 줄인다.
    cards = []
    for title, rows in sections:
        rows = [r for r in rows if r] or ["-"]
        cards.append((title, rows))
    limit = max(1, available - 2 * len(cards) - (len(cards) - 1))
    while sum(len(rows) for _, rows in cards) > limit:
        idx = max(range(len(cards)), key=lambda i: len(cards[i][1]))
        rows = cards[idx][1]
        if len(rows) <= 1:
            break
        selected = next((i for i, row in enumerate(rows) if row.startswith(">")), 0)
        rows.pop(1 if selected == 0 else 0)
    content = []
    for title, rows in cards:
        if content:
            content.append("")
        content.extend(screen_box(title, rows, width, color))
    keys = [("1-3", "화면"), ("↑↓", "선택"), ("Enter", "상세"), ("n", "신청"),
            ("s", "받기"), ("c", "점검"), ("r", "새로고침"), ("o", "웹"), ("q", "끝")]
    sizes = [cell_width(f" {k} ") + 1 + cell_width(v) for k, v in keys]
    # 한 줄에 들어가도록 간격을 좁히고, 그래도 넘치면 화살표 안내를 뺀다(↑↓는 어디서나 같다).
    gap = 2 if sum(sizes) + 2 * (len(keys) - 1) <= width else 1
    if sum(sizes) + gap * (len(keys) - 1) > width:
        keys = [k for k in keys if k[0] != "↑↓"]
    bars, line, used = [], "", 0
    for key, label in keys:
        item = f" {key} "
        size = cell_width(item) + 1 + cell_width(label)
        if used and used + gap + size > width:
            bars.append(line)
            line, used = "", 0
        line += (" " * gap if used else "") + screen_color(item, "7", color) + " " + label
        used += (gap if used else 0) + size
    bars.append(line)
    if ui.get("message"):
        bars[0] = clip(str(ui["message"]), width)
    content = content[:max(0, height - 3 - len(bars))]
    lines = [head, tabs, "", *content]
    lines += [""] * max(0, height - len(lines) - len(bars))
    return [*lines, *bars][:height]


def handle_key(key: str, ui: dict, model: dict) -> str | None:
    """키 하나를 화면 상태에 반영하고, 밖에서 해야 할 일 이름(없으면 None)을 돌려준다."""
    count = (0, len(model["servers"]), len(model["intakes"]) + len(model["found"]))[ui["tab"]]
    if key in ("1", "2", "3"):
        ui.update(tab=int(key) - 1, cursor=0, detail=False)
    elif key in ("left", "right"):
        ui.update(tab=(ui["tab"] + (1 if key == "right" else -1)) % 3, cursor=0, detail=False)
    elif key == "up":
        ui["cursor"] = max(ui["cursor"] - 1, 0)
    elif key == "down":
        ui["cursor"] = min(ui["cursor"] + 1, max(count - 1, 0))
    elif key == "enter":
        if ui["tab"] == 2 and ui["cursor"] >= len(model["intakes"]) and model["found"]:
            return "add_found"
        ui["detail"] = not ui["detail"] if count else False
    elif key == "esc":
        ui["detail"] = False
    elif key == "s" and ui["tab"] == 1 and model["servers"]:
        return "get"
    elif key == "s" and ui["tab"] == 2 and ui["cursor"] < len(model["intakes"]):
        row = model["intakes"][ui["cursor"]]
        need = model.get("inspections", {}).get(row.get("id"))
        return "inspect" if need and need.get("phase") != "submitted" else None
    elif key in ("n", "c", "r", "o", "q"):
        return {"n": "new", "c": "check", "r": "report", "o": "web", "q": "quit"}[key]
    return None


def read_key() -> str:
    """키 하나를 이름으로(1·2·3, left/right/up/down, enter, esc, 글자). 입력이 끝나면 q."""
    if os.name == "nt":
        import msvcrt

        char = msvcrt.getwch()
        if char in ("\x00", "\xe0"):
            return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(msvcrt.getwch(), "")
        return {"\r": "enter", "\x1b": "esc", "\x03": "q"}.get(char, char.lower())
    import select
    import termios
    import tty

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        raw = os.read(fd, 1)
        if not raw:
            return "q"
        if raw == b"\x1b":
            if select.select([fd], [], [], 0.05)[0]:
                raw += os.read(fd, 2)
            return {b"\x1b[A": "up", b"\x1b[B": "down", b"\x1b[C": "right",
                    b"\x1b[D": "left"}.get(raw, "esc")  # fmt: skip
        named = {b"\n": "enter", b"\r": "enter", b"\x03": "q"}
        return named.get(raw, raw.decode(errors="ignore").lower())
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def build_model(kit, state: dict, gateway: Gateway | None) -> dict:
    """화면이 그릴 값: 로컬 상태와 ``me`` 응답(닿지 못하면 로컬 정보만)."""
    result, problems = kit.check(state) if state else ({}, ["설치되어 있지 않습니다"])
    status, me = gateway.json("GET", ME_PATH) if gateway else (0, None)
    me = me if status == 200 and isinstance(me, dict) else None
    contracts = kit.local_contracts()
    permits = kit.local_permits()
    staged = kit.home / STATE_REL / PACKS
    now = time.time()
    servers = []
    names = list(contracts)
    for item in (me or {}).get("servers", []):
        if isinstance(item, dict) and isinstance(item.get("server_id"), str):
            if item["server_id"] not in names:
                names.append(item["server_id"])
    remote = {i["server_id"]: i for i in (me or {}).get("servers", []) if isinstance(i, dict)}
    for name in names:
        contract = contracts.get(name)
        info = remote.get(name, {})
        if contract is None:
            row_state, kind = S_WAIT, "묶음" if info.get("pack_sha256") else "로컬"
        else:
            row_state = pack_state(name, contract, kit.programs, staged, permits, now)
            kind = "묶음" if contract.get("pack") else "로컬"
            failed = kit.pack_errors().get(name)
            digest = (contract.get("pack") or {}).get("sha256")
            if row_state in (S_NEED, S_WORK) and isinstance(failed, dict) and (
                    failed.get("sha256") == digest):
                row_state = S_FAILED
            steps = server_evidence(kit.home, name) if kind == "묶음" else [True, True, False]
            if row_state == S_READY and kind == "묶음" and not steps[0]:
                row_state = S_START  # 준비만으로는 사용 가능이 아니다
        pack = contract.get("pack") if contract else None
        servers.append({
            "name": name, "kind": kind, "state": row_state, "steps": steps,
            "reason": (kit.pack_errors().get(name) or {}).get("reason", "") if contract else "",
            "pack_sha256": (pack or {}).get("sha256") or info.get("pack_sha256"),
            "permit_until": (permits.get(name) or {}).get("permit_until")
            or info.get("permit_until"),
        })  # fmt: skip
    mode = {"managed": "관리형", "user": "사용자 수준(관리되지 않음)"}.get(
        state.get("mode"), "설치 안 됨")
    intakes = [i for i in (me or {}).get("intakes", []) if isinstance(i, dict)]
    inspections: dict = {}  # 승인이 한 번이라 단말 검사 안내는 기본 흐름에 없다
    applied = {  # 진행 중이거나 승인된 신청은 다시 신청할 항목이 아니다
        i.get("server_id") for i in intakes
        if i.get("decision") not in ("rejected", "withdrawn") and i.get("stage") not in (
            "rejected", "withdrawn", "failed")
    }
    blocked = state.get("mode") == "managed"
    found = [
        {**item, "blocked": blocked and item["harness"] == "codex"}
        for item in (scan_local_mcp(kit.home, managed_names(state) | set(names))
                     if kit.home.exists() else [])
        if item["name"] not in applied
    ]
    return {
        "connected": me is not None, "user": (me or {}).get("user"),
        "key": "ok" if me is not None else "rejected" if status in (401, 403, 404) else "unknown",
        "mode": mode, "harnesses": kit.harnesses, "server_count": len(state.get("mcp_servers", [])),
        "problems": problems, "servers": servers,
        "intakes": intakes, "found": found, "inspections": inspections, "now": now,
        "result": result,
    }  # fmt: skip


def enable_vt() -> None:
    if os.name == "nt":
        os.system("")  # 콘솔의 ANSI 처리를 켠다


def run_screen(kit, state: dict, gateway: Gateway | None, actions, read=read_key, out=None) -> int:
    """대화형 화면. ``actions``는 밖에서 하는 일(get·check·report·new·web) 이름 -> 함수."""
    out = out or sys.stdout
    enable_vt()
    ui = {"tab": 0, "cursor": 0, "detail": False, "message": ""}
    model = build_model(kit, state, gateway)
    while True:
        size = shutil.get_terminal_size((80, 24))
        width, height = max(size.columns, 40), max(size.lines, 12)
        color = bool(getattr(out, "isatty", lambda: False)() and "NO_COLOR" not in os.environ
                     and os.environ.get("TERM") != "dumb")
        lines = render_screen(model, ui, width, height, color)
        out.write("\x1b[2J\x1b[H" + "\n".join(lines) + "\n")
        out.flush()
        ui["message"] = ""
        action = handle_key(read(), ui, model)
        if action == "quit":
            return 0
        if action:
            ui["message"] = clip(str(actions[action](model, ui) or ""), width)
            state = kit.load_state() or state
            model = build_model(kit, state, gateway)


# --- 단말 검사(검사 권한: 격리 실행으로 도구 목록만 받아 제출) ----------------------------------
INSPECTIONS_FILE = "inspections.json"  # 사용자 캐시: 보고 응답의 검사 권한과 진행 단계
INSPECT_PATH = "/mint/v1/endpoint/inspections"
INSPECT_PACKS = "inspect-packs"  # 검사용 묶음 폴더(실행 허가를 받는 폴더와 따로 둔다)
INSPECT_SECONDS = 30
INSPECT_TOOLS = 200
INSPECT_BYTES = 1 << 20
INSPECT_DETAIL = 2048
INSPECT_KEEP = 16
INSPECT_CONTRACT_BYTES = 64 << 10
INSPECT_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
INSPECT_SYSTEM = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
INSPECT_ETC = (
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
    "/etc/localtime",
)  # fmt: skip
INSPECT_PATH_ENV = "/usr/local/bin:/usr/bin:/bin"
PACK_ENTRY = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*):([A-Za-z_][A-Za-z0-9_]*)$"
)
NO_INSPECT_TEXT = "이 단말에서는 검사할 수 없습니다"
# 로더·인터프리터를 바꾸는 변수는 신청 환경 변수로 받지 않는다.
ENV_DENIED = re.compile(
    r"^(LD_|DYLD_|PYTHON|NODE_|PERL|RUBY|MALLOC_|PATH$|HOME$|TMPDIR$|SHELL$|IFS$|ENV$|BASH_ENV$|"
    r"CLASSPATH$|JAVA_TOOL_OPTIONS$|_JAVA_OPTIONS$|JDK_JAVA_OPTIONS$|GCONV_PATH$|LOCPATH$|"
    r"NLSPATH$|HOSTALIASES$)",
    re.IGNORECASE,
)
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def env_rule_error(name: str, value: str) -> str | None:
    """신청 환경 변수(이름=값) 하나가 규칙에 맞지 않는 사유. 맞으면 None."""
    if not ENV_NAME.match(name):
        return f"환경 변수 이름이 올바르지 않습니다: {name[:30]}"
    if ENV_DENIED.match(name):
        return f"{name}은(는) 쓸 수 없는 이름입니다"
    if SECRET_NAME.search(name):
        return f"{name}은(는) 비밀로 보여 받지 않습니다"
    if len(value) > 1024 or any(c in value for c in ("\x00", "\n", "\r")):
        return f"{name}의 값이 올바르지 않습니다"
    return None


def parse_env(items: list[str]) -> tuple[dict[str, str], list[str]]:
    """``--env`` 항목을 (이름=값, 이름만)으로. 규칙에 맞지 않으면 ``AddError``."""
    values: dict[str, str] = {}
    names: list[str] = []
    for item in items:
        name, eq, value = item.partition("=")
        if not eq:
            names.append(name)
            continue
        why = env_rule_error(name, value)
        if why:
            raise AddError(why)
        values[name] = value
    return values, names


def env_paths(values: dict[str, str]) -> list[str]:
    """값이 경로처럼 보이는 것(파일 접근 선언 후보)."""
    return list(dict.fromkeys(v for v in values.values() if v.startswith("/") or WIN_ABS.match(v)))


def load_inspections(home: Path, now: float | None = None) -> list[dict]:
    """상태 파일의 검사 권한(만료된 것은 뺀다)."""
    try:
        doc = json.loads((home / STATE_REL / INSPECTIONS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    items = doc.get("items") if isinstance(doc, dict) else None
    now = time.time() if now is None else now
    if not isinstance(items, list):
        return []
    return [
        i for i in items if isinstance(i, dict) and (parse_time(i.get("expires_at")) or 0) > now
    ]


def write_inspections(home: Path, items: list[dict]) -> None:
    path = home / STATE_REL / INSPECTIONS_FILE
    try:
        if items:
            write_atomic(path, json.dumps({"items": items}).encode(), 0o600)
        else:
            path.unlink(missing_ok=True)
    except OSError:
        return


def valid_inspection(item: object, now: float) -> dict | None:
    """응답의 검사 권한 하나에서 알려진 항목만(모양이 틀리거나 만료면 None)."""
    if not isinstance(item, dict):
        return None
    ident, intake, server = item.get("id"), item.get("intake_id"), item.get("server")
    digest, contract = item.get("pack_sha256"), item.get("contract")
    until = parse_time(item.get("expires_at"))
    if not (
        isinstance(ident, str) and INSPECT_ID.match(ident) and isinstance(intake, str)
        and 0 < len(intake) <= 128 and isinstance(server, str) and SERVER_NAME.match(server)
        and isinstance(digest, str) and SHA256_HEX.match(digest) and isinstance(contract, dict)
        and until is not None and until > now
        and len(json.dumps(contract)) <= INSPECT_CONTRACT_BYTES
    ):
        return None
    return {
        "id": ident, "intake_id": intake, "server": server, "pack_sha256": digest,
        "contract": contract, "expires_at": item["expires_at"],
    }  # fmt: skip


def save_inspections(home: Path, remote: object, now: float | None = None) -> None:
    """보고 응답의 ``inspections``를 상태 파일에 맞춘다. 응답에서 사라졌거나 만료된 검사는 지운다.

    이 목록은 하네스 설정·desired·시작 허가와 아무 관계가 없다(검사 화면과 ``mint inspect``만 쓴다).
    """
    now = time.time() if now is None else now
    old = {i["id"]: i for i in load_inspections(home, now) if isinstance(i.get("id"), str)}
    kept: list[dict] = []
    for raw in (remote if isinstance(remote, list) else [])[:INSPECT_KEEP]:
        item = valid_inspection(raw, now)
        if item is None:
            continue
        before = old.pop(item["id"], None) or {}
        if before.get("pack_sha256") == item["pack_sha256"]:
            item.update({k: before[k] for k in ("phase", "body") if k in before})
        kept.append(item)
    # 제출한 검사는 서버 목록에서 빠져도 만료까지 「제출함」으로 남긴다.
    kept += [i for i in old.values() if i.get("phase") == "submitted"][: INSPECT_KEEP - len(kept)]
    write_inspections(home, kept)


def set_inspection(home: Path, ident: str, **fields: object) -> None:
    items = load_inspections(home)
    for item in items:
        if item.get("id") == ident:
            for key, value in fields.items():
                if value is None:
                    item.pop(key, None)
                else:
                    item[key] = value
    write_inspections(home, items)


def inspect_text(item: dict, detail: bool = False) -> str:
    """탭 3의 「다음 할 일」 칸."""
    if item.get("phase") == "submitted":
        return "단말 검사 제출함" + (" · 관리자 검토 중" if detail else "")
    return "단말 검사 필요 · s로 시작"


def inspect_ready(bwrap: str | None = None) -> str | None:
    """이 단말에서 격리 검사를 할 수 있으면 bubblewrap 경로, 아니면 None."""
    found = bwrap or shutil.which("bwrap")
    return found if found and bwrap_probe(found) else None


def limit_mounts(contract: dict, folder: str, home: str) -> list[str]:
    """격리 안에 읽기 전용으로 붙일 경로(런타임, 묶음 폴더, 작업 폴더, 계약의 파일 접근)."""
    found: list[str] = []

    def add(path: object) -> None:
        if (
            isinstance(path, str) and path.startswith("/") and "\x00" not in path
            and not any(path == s or path.startswith(s + "/") for s in INSPECT_SYSTEM)
            and path not in found
        ):
            found.append(path)

    path = str(contract.get("executable") or "")
    chain = [path]
    for _ in range(8):
        if not os.path.islink(chain[-1]):
            break
        link = os.readlink(chain[-1])
        chain.append(os.path.normpath(os.path.join(os.path.dirname(chain[-1]), link)))
    for step in dict.fromkeys([*chain, os.path.realpath(path)]):
        prefix = os.path.dirname(os.path.dirname(step))
        broad = prefix.count("/") < 2 or prefix in ("/opt", "/srv", "/mnt") or (
            bool(home) and (home == prefix or home.startswith(prefix.rstrip("/") + "/"))
        )
        add(step if broad else prefix)
    add(folder)
    add(contract.get("cwd"))
    for entry in contract.get("file_access") or ():
        add(entry.get("path") if isinstance(entry, dict) else None)  # rw 선언도 읽기만
    ordered = sorted(found, key=lambda p: p.count("/"))
    return [
        p for i, p in enumerate(ordered)
        if not any(p.startswith(q.rstrip("/") + "/") for q in ordered[:i])
    ]


def inspect_launch(contract: dict, folder: str, home: str, bwrap: str) -> tuple[list[str], dict]:
    """(격리 명령, 환경). 네트워크 없음·빈 홈·읽기 전용 경로만. 만들 수 없으면 ``PackError``."""
    pack, runtime = contract.get("pack"), contract.get("executable")
    match = PACK_ENTRY.match(str(pack.get("entry"))) if isinstance(pack, dict) else None
    if not match or not isinstance(runtime, str) or not os.path.isfile(runtime):
        raise PackError("실행 계약을 열 수 없습니다")
    module, function = match.groups()
    run = (
        f"import runpy; runpy.run_module({module!r}, run_name='__main__', alter_sys=True)"
        if function == "__main__"
        else f"from {module} import {function}; sys.exit({function}())"
    )
    code = f"import sys; sys.path[:0] = [{folder!r}]; {run}"
    argv = [runtime, "-I", "-B", "-c", code, *[str(a) for a in contract.get("argv") or []]]
    cmd = [bwrap, "--unshare-all", "--unshare-net", "--die-with-parent", "--new-session",
           "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]  # fmt: skip
    for path in (*INSPECT_SYSTEM, *INSPECT_ETC):
        cmd += ["--ro-bind-try", path, path]
    if home and home != "/" and not any(home.startswith(s + "/") for s in INSPECT_SYSTEM):
        cmd += ["--tmpfs", home]
    for path in limit_mounts(contract, folder, home):
        cmd += ["--ro-bind-try", path, path]
    cmd += ["--chdir", str(contract.get("cwd") or "/"), "--", *argv]
    env = {"PATH": INSPECT_PATH_ENV, "HOME": home or "/", "LANG": "C.UTF-8"}
    for name, value in (contract.get("env") or {}).items():
        if isinstance(name, str) and isinstance(value, str) and not ENV_DENIED.match(name):
            env[name] = value
    return cmd, env


def user_process_count() -> int:
    """이 사용자의 실행 단위(스레드 포함) 수. 프로세스 수 상한은 이 값에 더해 건다."""
    uid = os.getuid()
    count = 0
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                if os.stat(f"/proc/{name}").st_uid == uid:
                    count += len(os.listdir(f"/proc/{name}/task"))
            except OSError:
                pass
    return count


def apply_limits(procs: int) -> None:
    """자식이 exec하기 전에: CPU 30초, 메모리(힙) 1 GiB, 프로세스는 지금 개수 + 64."""
    import resource

    # ponytail: RLIMIT_DATA라 JVM 같은 큰 가상 예약은 세지 않는다. cgroup이 있으면 거기로 옮긴다.
    for which, soft in (
        (resource.RLIMIT_CPU, INSPECT_SECONDS), (resource.RLIMIT_DATA, 1 << 30),
        (resource.RLIMIT_NPROC, procs + 64),
    ):
        hard = resource.getrlimit(which)[1]
        if hard != resource.RLIM_INFINITY:
            soft = min(soft, hard)
        resource.setrlimit(which, (soft, soft))


class InspectFail(Exception):
    def __init__(self, stage: str) -> None:
        super().__init__(stage)
        self.stage = stage


def inspect_exchange(proc, lines, deadline: float, tools: list) -> None:
    """initialize 뒤 tools/list를 끝까지(nextCursor 따라) 받아 ``tools``에 쌓는다."""
    import queue

    stage = ["initialize"]

    def send(doc: dict) -> None:
        try:
            proc.stdin.write(json.dumps(doc).encode() + b"\n")
            proc.stdin.flush()
        except OSError as exc:
            raise InspectFail(stage[0]) from exc

    def ask(ident: int, method: str, params: dict) -> dict:
        send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise InspectFail("timeout")
            try:
                line = lines.get(timeout=min(left, 0.5))
            except queue.Empty:
                continue
            if line is None:
                raise InspectFail(stage[0])
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            if isinstance(doc, dict) and doc.get("id") == ident:
                if not isinstance(doc.get("result"), dict):
                    raise InspectFail(stage[0])
                return doc["result"]

    ask(1, "initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "mint-inspect", "version": "1"},
    })  # fmt: skip
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    stage[0] = "tools"
    cursor, seen = None, set()
    for number in range(2, 60):
        result = ask(number, "tools/list", {} if cursor is None else {"cursor": cursor})
        page = result.get("tools")
        if not isinstance(page, list) or not all(isinstance(t, dict) for t in page):
            raise InspectFail("tools")
        tools.extend(page)
        if len(tools) > INSPECT_TOOLS or len(json.dumps(tools).encode()) > INSPECT_BYTES:
            raise InspectFail("limit")
        cursor = result.get("nextCursor")
        if not cursor:
            return
        if not isinstance(cursor, str) or cursor in seen:
            raise InspectFail("tools")
        seen.add(cursor)
    raise InspectFail("limit")


def inspect_run(
    cmd: list[str], env: dict, digest: str, seconds: float = INSPECT_SECONDS, limits: bool = True
) -> dict:
    """격리 명령을 띄워 도구 목록을 끝까지 받는다. 결과 본문(제출 형식)을 돌려준다."""
    import queue
    import threading

    procs = user_process_count() if limits else 0
    proc = subprocess.Popen(
        cmd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, preexec_fn=(lambda: apply_limits(procs)) if limits else None,
    )  # fmt: skip
    lines: queue.Queue = queue.Queue()
    tail = bytearray()

    def read_out() -> None:
        try:
            for raw in iter(lambda: proc.stdout.readline(INSPECT_BYTES * 2), b""):
                lines.put(raw)
        except (OSError, ValueError):
            pass
        lines.put(None)

    def read_err() -> None:
        try:
            for raw in iter(lambda: proc.stderr.read(4096), b""):
                tail.extend(raw)
                del tail[: -INSPECT_DETAIL * 2]
        except (OSError, ValueError):
            pass

    for target in (read_out, read_err):
        threading.Thread(target=target, daemon=True).start()
    tools: list = []
    stage, done = "done", True
    try:
        inspect_exchange(proc, lines, time.monotonic() + seconds, tools)
    except InspectFail as exc:
        stage, done = exc.stage, False
    exited = proc.poll()
    try:
        os.killpg(proc.pid, signal.SIGKILL)  # 격리 도구의 이름공간은 부모가 죽으면 함께 끝난다
    except OSError:
        pass
    proc.kill()
    proc.wait()
    text = bytes(tail[-INSPECT_DETAIL:]).decode("utf-8", errors="replace")
    return {
        "pack_sha256": digest, "complete": done, "tools": tools if done else [],
        "detail": {"stage": stage, "exit_code": exited, "stderr_tail": text},
    }  # fmt: skip


def refusal_body(digest: str, stage: str, text: str) -> dict:
    return {
        "pack_sha256": digest, "complete": False, "tools": [],
        "detail": {"stage": stage, "exit_code": None, "stderr_tail": text[:INSPECT_DETAIL]},
    }  # fmt: skip


def inspect_body(item: dict, folder: Path, home: Path) -> dict:
    """묶음 폴더가 준비된 검사 하나를 격리 실행하고 제출할 본문을 만든다(격리 못 하면 거절 본문)."""
    digest = item["pack_sha256"]
    bwrap = inspect_ready()
    if bwrap is None:
        return refusal_body(digest, "sandbox", "격리 도구를 쓸 수 없어 검사를 시작하지 않았습니다")
    try:
        cmd, env = inspect_launch(item["contract"], str(folder), str(home), bwrap)
        return inspect_run(cmd, env, digest)
    except PackError as exc:
        return refusal_body(digest, "pack", str(exc))
    except OSError as exc:
        return refusal_body(digest, "start", f"검사를 시작하지 못했습니다({type(exc).__name__})")


def find_inspection(home: Path, target: str) -> dict | None:
    items = load_inspections(home)
    for field in ("id", "intake_id", "server"):
        for item in items:
            if item.get(field) == target:
                return item
    return None


def run_inspect(
    kit, gateway: Gateway | None, target: str, out=print, body_of=inspect_body, progress=None
) -> int:
    """``mint inspect``: 검사 권한 하나를 받기·검증·격리 실행·제출까지 한 번에."""
    if gateway is None:
        out("키가 없습니다. 한 줄 설치 명령을 붙여 넣으십시오")
        return 1
    item = find_inspection(kit.home, target)
    if item is None:
        out("검사할 항목이 없습니다")
        return 1
    if item.get("phase") == "submitted":
        out("검사 제출함")
        return 0
    if not sys.platform.startswith("linux"):
        out(NO_INSPECT_TEXT)
        return 1
    ident = item["id"]
    progress = progress or (lambda text: None)
    base = f"{INSPECT_PATH}/{urllib.parse.quote(ident, safe='')}"
    digest = item["pack_sha256"]
    folder = kit.home / STATE_REL / INSPECT_PACKS / digest[:16]
    body = item.get("body")
    if body is None:
        blobs: dict = {}
        try:
            if ready_status(folder, digest) != "ok":
                blobs = fetch_pack(gateway, item["server"], digest, progress)
                install_blobs(digest, blobs, folder.parent)
            progress("검사 시작")
            status, _ = gateway.json("POST", base + "/start")
            if status == 409:
                out("이미 시작했거나 만료되었습니다")
                return 1
            if status != 200:
                out(pack_http_text(status) if status in (0, -1) else f"시작 실패({status})")
                return 1
            set_inspection(kit.home, ident, phase="started")
            progress("도구 목록 받는 중")
            body = body_of(item, folder, kit.home)
            set_inspection(kit.home, ident, phase="result", body=body)
        except (PackError, OSError) as exc:
            out(str(exc)[:80])
            return 1
        finally:
            for handle in blobs.values():
                handle.close()
            shutil.rmtree(folder, ignore_errors=True)
    # 응답을 잃으면 저장해 둔 같은 본문을 다시 보낸다.
    progress("제출 중")
    status, _ = gateway.json("POST", base + "/result", body)
    if status == 200:
        set_inspection(kit.home, ident, phase="submitted", body=None)
        out("검사 제출함")
        return 0
    if status in (404, 409):
        out("이미 제출했거나 만료되었습니다")
        return 1
    out("제출하지 못했습니다. 다시 시도하십시오" if status in (0, -1) else f"제출 실패({status})")
    return 1


# --- 대화형 명령(screen·add·requests·get) ------------------------------------------------------
CLI_COMMANDS = ("screen", "add", "requests", "get", "inspect", "relink", "app")


def open_installed(folder: Path):
    """(Kit, 상태, Gateway 또는 None). 설치 기록을 못 찾으면 상태는 빈 값."""
    if sys.platform == "win32":
        account = Account(os.environ.get("USERNAME", ""), Path(os.path.expanduser("~")), 0, 0)
        privileged = is_admin()
    else:
        import pwd

        entry = pwd.getpwuid(os.getuid())
        account = Account(entry.pw_name, Path(entry.pw_dir), entry.pw_uid, entry.pw_gid)
        privileged = os.geteuid() == 0
    kit = Kit(folder, None, privileged, account, False, strict=False)
    state = kit.load_state()
    if not state:
        other = Kit(folder, None, not privileged, account, False, strict=False)
        state = other.load_state()
        kit = other if state else kit
    if not kit.config.get("key"):
        try:
            kit.config["key"] = (kit.home / KEY_REL).read_text(encoding="utf-8").strip()
        except OSError:
            pass
    key, url = kit.config.get("key"), kit.config.get("decide_url")
    gateway = Gateway(url, key, kit.config.get("ca_pem")) if key and url else None
    return kit, state, gateway


def can_write(path: Path) -> bool:
    """``path``(아직 없으면 가장 가까운 상위 폴더)에 이 사용자가 쓸 수 있는가."""
    while not path.exists() and path != path.parent:
        path = path.parent
    return os.access(path, os.W_OK)


def run_get(kit, gateway: Gateway | None, server: str, out=print, progress=None) -> int:
    """``mint get``: 승인된 묶음을 받아 검증하고 풀어 준비한다. 반쯤 된 상태는 남기지 않는다."""
    if gateway is None:
        out("키가 없습니다. 한 줄 설치 명령을 붙여 넣으십시오")
        return 1
    status, me = gateway.json("GET", ME_PATH)
    if status != 200 or not isinstance(me, dict):
        out(pack_http_text(status))
        return 1
    entry = next(
        (s for s in me.get("servers", []) if isinstance(s, dict) and s.get("server_id") == server),
        None,
    )
    digest = entry.get("pack_sha256") if entry else None
    if entry is None:
        out("나에게 승인된 서버가 아닙니다")
        return 1
    if not isinstance(digest, str) or not SHA256_HEX.match(digest):
        out("받을 묶음이 없는 서버입니다")
        return 1
    packs = kit.programs / PACKS
    if ready_status(packs / digest[:16], digest) == "ok":
        out("이미 준비되어 있습니다")
        return 0
    blobs: dict = {}
    try:
        blobs = fetch_pack(gateway, server, digest, progress)
        check_blobs(digest, blobs)
        if can_write(kit.programs):
            install_blobs(digest, blobs, packs)
            out("준비했습니다. 실행 허가는 다음 보고 때 받습니다")
        else:
            stage_blobs(blobs, kit.home / STATE_REL / PACKS / digest[:16])
            out("받아서 검증했습니다. 관리자 단계가 준비를 마칩니다")
    except (PackError, OSError) as exc:
        out(str(exc))
        return 1
    finally:
        for handle in blobs.values():
            handle.close()
    return 0


def run_requests(gateway: Gateway | None, out=print) -> int:
    status, me = gateway.json("GET", ME_PATH) if gateway else (0, None)
    if status != 200 or not isinstance(me, dict):
        out(NO_GATEWAY if status == 0 else submit_text(status, me))
        return 1
    rows = [i for i in me.get("intakes", []) if isinstance(i, dict)]
    if not rows:
        out("신청한 서버가 없습니다")
        return 0
    out(f"{pad('서버', 28)}{pad('상태', 14)}다음 할 일")
    for row in rows:
        out(f"{pad(clip(str(row.get('server_id', '')), 27), 28)}{pad(row_label(row), 14)}"
            f"{clip(next_text(row), 36)}")  # fmt: skip
    return 0


def check_lines(result: dict, problems: list[str]) -> list[str]:
    """``mint check``의 사람용 표."""
    mode = {"managed": "관리형", "user": "사용자 수준(관리되지 않음)"}.get(
        result.get("mode"), "설치 안 됨")
    rows = [
        ("설치 방식", mode), ("MCP 서버", f"{len(result.get('mcp_servers', []))}개"),
        ("훅 신뢰", {"untrusted": "신뢰 안 함", "trusted": "신뢰함"}.get(
            str(result.get("hook_trust")), "해당 없음")),
        ("점검", "이상 없음" if not problems else f"문제 {len(problems)}건"),
    ]  # fmt: skip
    return [f"{pad(a, 12)}{b}" for a, b in rows] + [f"  - {p}" for p in problems]


def interactive_add(kit, gateway, home: Path, source: str | None, read=input, key=None) -> str:
    """화면에서 고른 신청: 대상 하나와 목적만 묻는다. 결과의 마지막 줄을 돌려준다."""
    lines: list[str] = []
    name, tokens = None, []
    if source is None:
        import shlex

        if key_refused(gateway):
            return KEY_REJECTED_TEXT
        typed = ask("주소 또는 실행 명령", "", read)
        name, tokens = (typed, []) if is_url(typed) else (None, shlex.split(typed))
    args = argparse.Namespace(
        source=source, name=name, command=tokens, purpose=None, grade=None, network=None,
        host=[], env=[], ro=[], rw=[], yes=False, request_id=None,
    )
    run_add(
        args, home, gateway, out=lambda t: (lines.append(t), print(t))[0], read=read, tty=True,
        key=key,
    )
    return lines[-1] if lines else ""


def run_relink(url: str, out=print) -> int:
    """한 줄 설치 명령의 주소로 새 묶음을 받아 설치기를 돌린다(키만 새 것으로 바뀐다)."""
    import base64

    found = re.match(r"^(https?://\S+/kit/[^/\s]+)(?:/[^/\s]*)?$", url.strip())
    if not found:
        out("주소가 올바르지 않습니다. 직원 화면의 설치 명령 주소를 붙여 넣으십시오")
        return 1
    windows = sys.platform == "win32"
    try:
        with urllib.request.urlopen(
            f"{found.group(1)}/{'kit.zip' if windows else 'kit.tar.gz'}", timeout=60
        ) as reply:
            raw = base64.b64decode(reply.read())
    except urllib.error.HTTPError:
        out("코드가 만료되었거나 이미 쓰였습니다. 직원 화면에서 새 명령을 만드십시오")
        return 1
    except (OSError, ValueError):
        out("MINT 화면에 닿지 못했습니다")
        return 1
    folder = Path(tempfile.mkdtemp(prefix="mint-relink-"))
    try:
        if windows:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                archive.extractall(folder)
            command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                       str(folder / "mint-kit" / "install.ps1")]
        else:
            import tarfile

            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
                for member in archive.getmembers():
                    if not member.isfile() or ".." in Path(member.name).parts:
                        out("받은 묶음이 올바르지 않습니다")
                        return 1
                archive.extractall(folder)
            command = ["bash", str(folder / "mint-kit" / "install.sh")]
        return subprocess.call(command)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# --- 앱 자격(자체 스크립트) -------------------------------------------------------------------
# 사람이 쓰는 키와 따로, 스크립트마다 자격을 둔다. 자격의 MCP 권한은 직원의 기존 승인 범위라
# 새 승인이 없다. 키는 이 PC의 사용자 설정 폴더에만 두고, 스크립트에는 `mint app run`이 실행할 때
# 환경 변수로만 넘긴다(스크립트·설정 파일에 키를 적지 않게).
APPS_PATH = "/mint/v1/endpoint/apps"
APPS_REL = ".config/mint/apps"
APP_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
APP_DAYS = 30


def app_file(home: Path, name: str) -> Path:
    return home / APPS_REL / f"{name}.json"


def read_app(home: Path, name: str) -> dict | None:
    try:
        app = json.loads(app_file(home, name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return app if isinstance(app, dict) and isinstance(app.get("key"), str) else None


def app_env(app: dict) -> dict[str, str]:
    """스크립트에 넘길 환경 변수. OpenAI·Anthropic SDK(DeepSeek 같은 OpenAI 호환 포함)가 읽는다."""
    base, key = str(app["base_url"]).rstrip("/"), str(app["key"])
    return {
        "OPENAI_API_KEY": key, "OPENAI_BASE_URL": base + "/v1",
        "ANTHROPIC_API_KEY": key, "ANTHROPIC_BASE_URL": base,
        "MINT_APP": str(app["name"]), "MINT_APP_KEY": key,
        "MINT_GATEWAY_URL": base, "MINT_MCP_URL": str(app.get("mcp_url") or base + "/mcp"),
    }  # fmt: skip


def app_expired(app: dict, now: float | None = None) -> bool:
    until = parse_time(app.get("expires_at"))
    return until is not None and until <= (time.time() if now is None else now)


def app_command(command: list[str] | None) -> list[str]:
    """``mint app run 이름 -- 명령``의 명령 부분(앞의 ``--``는 뺀다)."""
    command = list(command or [])
    return command[1:] if command[:1] == ["--"] else command


def app_mcp_config(kit: Kit, state: dict, app: dict) -> dict:
    """스크립트의 MCP 설정: 게이트웨이(원격 승인 서버)와 승인된 로컬 서버(실행기 중재)."""
    python = state.get("python") or sys.executable.replace("\\", "/")
    agent = f"{kit.logical_programs}/{AGENT}"
    contracts = f"{kit.logical_programs}/contracts.json"
    common = ["--url", kit.config["decide_url"], "--key-file", f"~/{KEY_REL}",
              "--state-dir", f"~/{STATE_REL}"]  # fmt: skip
    if kit.config.get("ca_pem"):
        common += ["--ca-file", f"{kit.logical_programs}/ca.pem"]
    servers: dict = {
        "litellm_gateway": {
            "type": "http", "url": app_env(app)["MINT_MCP_URL"],
            "headers": {"Authorization": "Bearer ${MINT_APP_KEY}"},
        },
    }  # fmt: skip
    for name in sorted(kit.local_contracts()):
        servers[name] = {"command": python, "args": [
            agent, "run", "--contracts", contracts, "--server", name, "--mediate",
            "--client", f"app-{app['name']}", *common]}  # fmt: skip
    return {"mcpServers": servers}


def app_error(what: str, status: int, doc: object) -> str:
    """앱 자격 명령의 실패 문구. 서버가 준 한국어 사유가 있으면 그대로 붙인다."""
    raw = doc.get("detail") if isinstance(doc, dict) else None
    if status == 0:
        return NO_GATEWAY
    if status in (401, 403):
        return KEY_REJECTED_TEXT
    reason = raw if isinstance(raw, str) and raw else f"HTTP {status}"
    return f"앱 자격을 {what} 못했습니다: {reason[:120]}"


def run_app(args, kit: Kit, state: dict, gateway: Gateway | None, out=print, call=None) -> int:
    """``mint app new|list|rm|run|env|mcp``."""
    action, home = args.app_action, kit.home
    name = getattr(args, "name", None)
    if name is not None and not APP_NAME.fullmatch(name):
        out("앱 이름은 영문 소문자·숫자·하이픈 40자 이내로 적으십시오")
        return 2
    if action in ("run", "env", "mcp"):
        return use_app(args, kit, state, out, call)
    if gateway is None:
        out("키가 없습니다. 한 줄 설치 명령을 붙여 넣으십시오")
        return 1
    if action == "new":
        return new_app(args, kit, gateway, out)
    if action == "list":
        return list_apps(home, gateway, out)
    if action == "rm":
        return remove_app(name, home, gateway, out)
    return 2


def use_app(args, kit: Kit, state: dict, out, call) -> int:
    name = args.name
    app = read_app(kit.home, name)
    if app is None:
        out(f"이 PC에 「{name}」 앱 자격이 없습니다. mint app new {name} 으로 만드십시오")
        return 1
    if app_expired(app):
        out(f"「{name}」 자격이 만료되었습니다. mint app rm {name} 뒤 다시 만드십시오")
        return 1
    if args.app_action == "env":
        powershell = args.shell == "powershell" or (args.shell is None and kit.windows)
        for key, value in app_env(app).items():
            out(f"$env:{key} = '{value}'" if powershell else f"export {key}={shlex.quote(value)}")
        return 0
    if args.app_action == "mcp":
        out(json.dumps(app_mcp_config(kit, state or {}, app), indent=2, ensure_ascii=False))
        return 0
    command = app_command(args.command)
    if not command:
        out(f"실행할 명령을 적으십시오: mint app run {name} -- python 스크립트.py")
        return 2
    command[0] = shutil.which(command[0]) or command[0]  # Windows의 npx·npm은 .cmd라 찾아 줘야 뜬다
    try:
        return (call or subprocess.call)(command, env={**os.environ, **app_env(app)})
    except OSError as exc:
        out(f"명령을 실행하지 못했습니다: {command[0]} ({type(exc).__name__})")
        return 127


def new_app(args, kit: Kit, gateway: Gateway, out) -> int:
    name, home = args.name, kit.home
    current = read_app(home, name)
    if current and not app_expired(current):
        out(f"이 PC에 이미 「{name}」 자격이 있습니다. mint app run {name} -- 명령 으로 쓰십시오")
        return 1
    status, doc = gateway.json("POST", APPS_PATH, {"name": name, "days": args.days or APP_DAYS})
    if status != 201 or not isinstance(doc, dict) or not isinstance(doc.get("key"), str):
        out(app_error("만들지", status, doc))
        return 1
    base = doc.get("base_url") or kit.config["decide_url"]
    app = {
        "id": doc.get("id"), "name": name, "key": doc["key"], "key_alias": doc.get("key_alias"),
        "expires_at": doc.get("expires_at"), "base_url": base,
        "mcp_url": doc.get("mcp_url") or str(base).rstrip("/") + "/mcp",
    }  # fmt: skip
    path = app_file(home, name)
    write_atomic(path, json.dumps(app, indent=1).encode(), 0o600)
    keep_private(path, kit.account.name)
    servers = ", ".join(s for s in doc.get("servers") or [] if isinstance(s, str))
    out(f"「{name}」 앱 자격을 만들었습니다(만료 {str(doc.get('expires_at') or '')[:10]}).")
    out(f"원격 MCP: {servers or '승인된 서버 없음'} · 로컬 서버는 실행기를 거칩니다")
    out(f"실행: mint app run {name} -- python 스크립트.py")
    out("스크립트는 OPENAI_BASE_URL·OPENAI_API_KEY 같은 환경 변수를 읽습니다(키를 적지 마십시오)")
    return 0


def list_apps(home: Path, gateway: Gateway, out) -> int:
    status, doc = gateway.json("GET", APPS_PATH)
    apps = doc.get("apps") if status == 200 and isinstance(doc, dict) else None
    if not isinstance(apps, list):
        out(app_error("읽지", status, doc))
        return 1
    if not apps:
        out("앱 자격이 없습니다. mint app new 이름 으로 만드십시오")
        return 0
    out(f"{pad('앱', 24)}{pad('만료', 12)}{pad('상태', 10)}이 PC")
    for item in apps:
        name = str(item.get("name", ""))
        text = "회수됨" if item.get("revoked_at") else ("만료" if app_expired(item) else "사용 중")
        here = "키 있음" if read_app(home, name) else "—"
        out(f"{pad(clip(name, 23), 24)}{pad(str(item.get('expires_at') or '')[:10], 12)}"
            f"{pad(text, 10)}{here}")
    return 0


def remove_app(name: str, home: Path, gateway: Gateway, out) -> int:
    app = read_app(home, name)
    app_id = app.get("id") if app else None
    if not app_id:
        status, doc = gateway.json("GET", APPS_PATH)
        listed = doc.get("apps") if status == 200 and isinstance(doc, dict) else None
        if not isinstance(listed, list):  # 서버에서 찾지 못했으면 회수했다고 하지 않는다
            kept = " · 이 PC의 키는 그대로 두었습니다" if app else ""
            out(app_error("찾지", status, doc) + kept)
            return 1
        app_id = next((a.get("id") for a in listed if isinstance(a, dict)
                       and a.get("name") == name and not a.get("revoked_at")), None)
    if app_id:
        status, doc = gateway.json("DELETE", f"{APPS_PATH}/{app_id}")
        if status not in (200, 204, 404):
            out(app_error("회수하지", status, doc) + " · 이 PC의 키는 그대로 두었습니다")
            return 1
    elif app is None:
        out(f"「{name}」 앱 자격이 없습니다. mint app list 로 확인하십시오")
        return 1
    app_file(home, name).unlink(missing_ok=True)
    out(f"「{name}」 앱 자격을 회수하고 이 PC의 키를 지웠습니다")
    return 0


def cli_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="mint")
    parser.add_argument("--kit", default=str(KIT))
    sub = parser.add_subparsers(dest="command_name", required=True)
    sub.add_parser("screen")
    sub.add_parser("requests")
    sub.add_parser("relink").add_argument("url")
    get = sub.add_parser("get")
    get.add_argument("server")
    inspect = sub.add_parser("inspect")
    inspect.add_argument("target")
    add = sub.add_parser("add")
    add.add_argument("name", nargs="?")
    add.add_argument("command", nargs="*")
    add.add_argument("--from", dest="source")
    add.add_argument("--purpose")
    add.add_argument("--grade")
    add.add_argument("--network", choices=["none", "hosts"])
    add.add_argument("--host", action="append")
    add.add_argument("--env", action="append")
    add.add_argument("--ro", action="append")
    add.add_argument("--rw", action="append")
    add.add_argument("--yes", action="store_true")
    add.add_argument("--request-id")
    app = sub.add_parser("app").add_subparsers(dest="app_action", required=True)
    new = app.add_parser("new")
    new.add_argument("name")
    new.add_argument("--days", type=int, choices=range(1, 91), metavar="1-90")
    app.add_parser("list")
    app.add_parser("rm").add_argument("name")
    run = app.add_parser("run")
    run.add_argument("name")
    run.add_argument("command", nargs=argparse.REMAINDER)
    env = app.add_parser("env")
    env.add_argument("name")
    env.add_argument("--shell", choices=["sh", "powershell"])
    app.add_parser("mcp").add_argument("name")
    args = parser.parse_args(argv)
    if args.command_name == "relink":
        return run_relink(args.url)
    kit, state, gateway = open_installed(Path(args.kit))
    if args.command_name == "get":
        return run_get(kit, gateway, args.server, progress=print)
    if args.command_name == "requests":
        return run_requests(gateway)
    if args.command_name == "inspect":
        if gateway is not None and find_inspection(kit.home, args.target) is None and state:
            kit.report(state, "installed")  # 받아 둔 검사 권한이 없으면 한 번 보고해서 받는다
        return run_inspect(kit, gateway, args.target, progress=print)
    if args.command_name == "app":
        return run_app(args, kit, state, gateway)
    if args.command_name == "add":
        if gateway is None:
            print("키가 없습니다. 한 줄 설치 명령을 붙여 넣으십시오")
            return 1
        tty = sys.stdin.isatty()
        return run_add(args, kit.home, gateway, tty=tty, key=read_key if tty else None)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(json.dumps(state or {"mode": "none"}, indent=1))
        return 0

    def live(text: str) -> None:  # 오래 걸리는 동안 화면 맨 아래 줄에 진행을 보인다
        sys.stdout.write("\r\x1b[K" + clip(text, 78))
        sys.stdout.flush()

    def get_action(model, ui):
        if not model["servers"]:
            return ""
        lines: list[str] = []
        run_get(kit, gateway, model["servers"][ui["cursor"]]["name"], lines.append, live)
        return lines[-1] if lines else ""

    def inspect_action(model, ui):
        lines: list[str] = []
        row = model["intakes"][ui["cursor"]]
        run_inspect(kit, gateway, row["id"], out=lines.append, progress=live)
        return lines[-1] if lines else ""

    def check_action(model, ui):
        _, problems = kit.check(state)
        return "이상 없음" if not problems else f"문제 {len(problems)}건"

    def report_action(model, ui):
        if not kit.report(state, "installed"):
            return NO_GATEWAY
        kit.refresh_approvals(state)
        return "보고했습니다"

    def new_action(model, ui):
        return interactive_add(kit, gateway, kit.home, None, key=read_key)

    def found_action(model, ui):
        item = model["found"][ui["cursor"] - len(model["intakes"])]
        return interactive_add(
            kit, gateway, kit.home, f"{item['harness']}:{item['name']}", key=read_key)

    def web_action(model, ui):
        parts = urllib.parse.urlsplit(kit.config.get("decide_url", ""))
        return f"직원 화면: {parts.scheme}://{parts.netloc}/staff"

    actions = {
        "get": get_action, "inspect": inspect_action, "check": check_action,
        "report": report_action, "new": new_action, "add_found": found_action, "web": web_action,
    }  # fmt: skip
    return run_screen(kit, state, gateway, actions)


def report_installed(
    folder: Path,
    *,
    home: Path | None = None,
    user: str | None = None,
    if_due: bool = False,
    jitter: int = 0,
    tick: bool = False,
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
        fast = None
        for path in (stamp.parent / FAST_FILE, home / STATE_REL / FAST_FILE):
            try:
                fast = max(fast or 0.0, float(path.read_text()[:64]))
            except (OSError, ValueError):
                pass
        try:
            note = (stamp.parent / UPDATE_NOTE).read_text(encoding="utf-8").strip()
        except OSError:
            note = ""
        return {"last": last, "key": key, "fast": fast, "note": note}

    seen = run(read_side) or {}
    if (if_due or tick) and not report_due(
        seen.get("last"), now(), report_gap(seen.get("fast"), now(), tick)
    ):
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
    if seen.get("note") and seen["note"] != "needed":
        kit.update_error = seen["note"]
    marker = stamp.parent / KEY_REJECTED
    if not kit.report(state, "installed"):
        run(lambda: stamp.unlink(missing_ok=True))  # 닿지 못했으면 다음 기회에 다시 보낸다.
        if set(last_http_error) & {401, 403}:
            run(lambda: marker.write_text("1"))
        return 1
    run(lambda: marker.unlink(missing_ok=True))
    retired = kit.answer.get("retired")
    names: list[str] = []
    changed = False
    updated = self_update(kit, folder, state, stamp.parent / UPDATE_NOTE, run) == "updated"
    kit.drop_to = target
    if isinstance(retired, list):
        names = [n for n in retired if isinstance(n, str)][:MAX_PENDING]
        run(lambda: save_retired(home, names, now(), folder if system else None))
        changed = bool(kit.remediate(state, names))
    revoke = kit.answer.get("revoke")
    if isinstance(revoke, list):
        gone = [n for n in revoke if isinstance(n, str) and SERVER_NAME.match(n)][:MAX_PENDING]
        names = [*names, *gone]
        changed = bool(kit.remediate(state, gone)) or changed
        changed = bool(kit.drop_contracts(state, gone)) or changed
    desired = kit.answer.get("desired")
    if isinstance(desired, list):
        changed = bool(kit.refresh(state, desired, names)) or changed
        changed = kit.apply_permits(state, desired, set(names)) or changed
        changed = kit.apply_versions(state, desired, set(names)) or changed
        changed = bool(kit.auto_fetch(state, desired, set(names))) or changed
        if system and kit.windows and any(
                isinstance(i, dict) and isinstance(i.get("contract"), dict)
                and i["contract"].get("npm") for i in desired):
            open_node_to_sandbox(kit.home)
        changed = bool(kit.promote_packs()) or changed
    changed = kit.refresh_approvals(state) or changed
    changed = apply_user_answer(kit, run, home, folder, target is not None or system) or changed
    if needs_fast(kit.answer, changed, now()):
        fast_file = stamp.parent / FAST_FILE

        def write_fast() -> None:
            fast_file.parent.mkdir(parents=True, exist_ok=True)
            fast_file.write_text(str(now() + FAST_WINDOW))

        run(write_fast)
    if changed or updated:
        kit.report(state, "installed")  # 지우거나 더한 것을 곧바로 알린다.
        if system and state.get("sync_task"):
            capture(["schtasks", "/Run", "/TN", state["sync_task"]])  # 사용자 Codex 설정을 맞춘다
    return 0


def sync_user_side(kit: Kit, state: dict) -> list[str]:
    """Windows 관리형 사용자 작업: SYSTEM 보고기가 만지지 않는 사용자 프로필 몫을 한다.

    사용자 쪽 현황(AI 도구·평문 키·장애 중 통과 호출)을 보고하고, 응답의 관리 연결 중지·신청
    요청을 반영하며, 훅 없는 AI 도구를 잇는다. 이어진 도구 이름을 돌려준다.
    """
    try:
        kit.config["key"] = (kit.home / KEY_REL).read_text(encoding="utf-8").strip()
    except OSError:
        return []
    if kit.report(state, "installed"):
        apply_user_answer(kit, lambda fn: fn(), kit.home, kit.programs, False)
    else:
        kit.connect_clients()
    return sorted(c for c, r in read_client_record(kit.home).items() if r.get("names"))


def submit_requests(kit: Kit, requests: list) -> list[str]:
    """직원이 「내 단말」에서 누른 신청을 ``mint add --from 도구:이름``과 같은 경로로 올린다.

    이 PC 설정에 그 이름의 항목이 있을 때만 올린다(사용자 권한으로 돈다). 올린 이름을 돌려준다.
    """
    items = {i["name"]: i["harness"] for i in scan_mcp(kit.home)["local_mcp"]}
    config = kit.config
    gateway = Gateway(config["decide_url"], config.get("key") or "", config.get("ca_pem"))
    sent = []
    for request in requests[:8]:
        name = request.get("name") if isinstance(request, dict) else None
        purpose = request.get("purpose") if isinstance(request, dict) else None
        if not (isinstance(name, str) and name in items and isinstance(purpose, str) and purpose):
            continue
        args = argparse.Namespace(
            name=None, command=[], source=f"{items[name]}:{name}", purpose=purpose[:256],
            grade=None, network=None, host=None, env=None, ro=None, rw=None, yes=True,
            request_id=None,
        )  # fmt: skip
        if run_add(args, kit.home, gateway, out=lambda *_: None) == 0:
            sent.append(name)
    return sent


def apply_user_answer(kit: Kit, run, home: Path, folder: Path, privileged: bool) -> bool:
    """응답의 관리 연결 중지·연결 복구·신청 요청을 반영한다. 바뀐 것이 있으면 참.

    중지 표지는 사용자 캐시와(관리자 권한 보고기면) 설치 폴더에 둔다. 설치 폴더의 표지는 사용자가
    지울 수 없다. 중지되면 실행기가 띄운 서버를 끈다. 훅 없는 AI 도구의 연결은 매 보고마다 맞춘다
    (같으면 쓰지 않는다). SYSTEM 보고기는 사용자 프로필을 만지지 않으므로 사용자 작업이 한다.
    """
    changed = False
    pause = kit.answer.get("paused")
    if isinstance(pause, bool):
        gen = kit.answer.get("pause_gen")
        gen = gen if isinstance(gen, int) and gen >= 0 else 0
        before = read_paused_gen(folder if kit.system_mode else home / STATE_REL)
        if not kit.system_mode:
            run(lambda: set_paused(home / STATE_REL, pause, gen) or True)
        if privileged:
            set_paused(folder, pause, gen)
        changed = (before is not None) != pause or (pause and before != gen)
        if pause and not kit.system_mode:
            stopped = run(lambda: kit.stop_launched(None))
            changed = bool(stopped) or changed
    if kit.system_mode:
        return changed
    run(lambda: kit.connect_clients())
    requests = kit.answer.get("intake_requests")
    if isinstance(requests, list) and requests:
        changed = bool(run(lambda: submit_requests(kit, requests))) or changed
    return changed


def self_update(kit: Kit, folder: Path, state: dict, note: Path, run) -> str:
    """보고 응답의 서버 판본이 다르면 서명된 묶음을 검증해 교체한다. 결과: updated·current·failed.

    고정 공개 키가 없는 옛 설치는 바꾸지 않고 「다시 설치」 안내만 남긴다. 실패하면 옛 코드를
    그대로 두고 사유만 기록한다(다음 보고에 실린다).
    """
    version = kit.answer.get("kit_version")
    if not isinstance(version, str) or version == kit.config.get("kit_version"):
        run(lambda: note.unlink(missing_ok=True))
        return "current"
    reason = (
        kit.apply_update(folder, state, kit.answer.get("kit_update"))
        if kit.config.get("update_key")
        else "needed"
    )
    if reason is None:
        run(lambda: note.unlink(missing_ok=True))
        return "updated"
    run(lambda: note.write_text(reason, encoding="utf-8"))
    return "failed"


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


def cursor_version(home: Path) -> str | None:
    return tool_version(find_tool("cursor", home))


def grok_version(home: Path) -> str | None:
    return tool_version(find_tool("grok", home))


def codex_version(home: Path) -> str | None:
    return tool_version(find_codex(home))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in CLI_COMMANDS:
        return cli_main(argv)
    parser = argparse.ArgumentParser(description="MINT endpoint kit")
    parser.add_argument(
        "action", nargs="?", default="install",
        choices=["install", "uninstall", "status", "check", "sync", "report"],
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--if-due", action="store_true")
    parser.add_argument("--tick", action="store_true")
    parser.add_argument("--jitter", type=int, default=0)
    parser.add_argument("--user-level", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--user")
    parser.add_argument("--home")
    parser.add_argument("--root")
    parser.add_argument("--kit", default=str(KIT))
    args = parser.parse_args(argv)
    if args.action == "report":
        def once() -> int:
            return report_installed(
                Path(args.kit), if_due=args.if_due, tick=args.tick, jitter=args.jitter,
                home=Path(args.home) if args.home else None, user=args.user,
            )

        code = once()
        # 예약 작업은 최소 1분이라, 반영을 기다리는 동안은 한 번 불린 김에 20초 간격으로 더 돈다.
        for _ in range(2 if args.tick and sys.platform == "win32" else 0):
            if not fast_marked(Path(args.kit), Path(args.home) if args.home else None):
                break
            time.sleep(FAST_GAP)
            code = once()
        return code
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
    if args.action in ("status", "check", "sync"):
        state = kit.load_state()
        if not state and not kit.managed:
            # 관리형 설치는 시스템 경로에 있다. 일반 사용자도 상태 파일을 읽을 수 있다.
            managed = Kit(Path(args.kit), root, True, account, False, strict=False)
            state = managed.load_state()
            if state:
                kit = managed
        if args.action == "status":
            print(json.dumps(state or {"mode": "none"}, indent=1))
            return 0
        if args.action == "sync":
            result = kit.sync_codex_block(state) if state else {}
            if state and kit.windows and kit.managed:
                result["clients"] = sync_user_side(kit, state)
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if not state:
            print(json.dumps({"mode": "none"}, indent=1))
            return 1
        result, problems = kit.check(state)
        result.pop("files", None)
        if args.json:
            print(json.dumps(result, indent=1, ensure_ascii=False))
        else:
            print(NL.join(check_lines(result, problems)))
        return 1 if problems else 0
    if args.action == "install":
        try:  # 같은 PC에 다시 설치: 새 키로 보고한 뒤 이 PC의 옛 키만 해제한다
            old_key = (kit.home / KEY_REL).read_text(encoding="utf-8").strip()
        except OSError:
            old_key = ""
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
        if reported and old_key and old_key != kit.config.get("key"):
            retire_key(kit, old_key)
        if state.get("gateway"):
            print(f"게이트웨이 MCP 서버 {state['gateway']}을(를) 하네스 설정에 넣었습니다.")
        if state["mode"] == "user" and "codex" in kit.harnesses:
            print(
                "참고: Codex는 사용자 수준 훅을 신뢰하기 전에는 실행하지 않습니다. Codex에서 훅을 "
                "검토해 신뢰해야 호출 전 판정이 시작됩니다(`mint check`로 확인)."
            )
        return 0
    if not kit.config.get("key"):
        # 설치된 복사본(`mint uninstall`)의 kit.json에는 키가 없다. 지우기 전에 키 파일에서 읽는다.
        try:
            kit.config["key"] = (kit.home / KEY_REL).read_text(encoding="utf-8").strip()
        except OSError:
            pass
    result = kit.uninstall()
    reported = kit.report({"mode": result.get("mode")}, "removed")
    kept = result.get("kept") or []
    print(f"제거 완료. 바뀌어 남긴 파일 {len(kept)}개. MINT 보고 {'성공' if reported else '실패'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

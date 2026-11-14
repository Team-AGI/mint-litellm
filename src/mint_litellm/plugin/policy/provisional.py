"""승인된 도구 계약이 없는 서버의 임시 계약. 이름·설명·인자 이름으로 행위 유형·위험 등급을 추정한다.

추정은 결정적인 낱말 규칙이다. 가장 엄격한 유형을 먼저 보며(자격 접근, 실행, 외부 전송, 삭제,
쓰기, 읽기 순) 읽기로 볼 근거가 없으면 쓰기로, 명령 인자가 있으면 실행으로 본다. 임시 계약은
삭제·외부 전송 확인, 경로 제한, 위험 등급 승인 같은 보호 규칙에만 쓰고 승인 규칙이나 허용 판정을
넓히지 않는다.
"""

import re
from collections.abc import Iterable
from typing import NamedTuple

# 앞선 유형이 우선한다(더 엄격하다).
_VERBS: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "credential_access",
        frozenset(
            {
                "credential",
                "credentials",
                "secret",
                "secrets",
                "password",
                "passwd",
                "token",
                "tokens",
                "apikey",
                "keychain",
                "vault",
            }
        ),
    ),
    (
        "exec",
        frozenset(
            {
                "exec",
                "execute",
                "run",
                "shell",
                "eval",
                "bash",
                "cmd",
                "command",
                "spawn",
                "script",
                "terminal",
                "subprocess",
                "sudo",
                "invoke",
                "launch",
            }
        ),
    ),
    (
        "external_send",
        frozenset(
            {
                "send",
                "post",
                "email",
                "mail",
                "upload",
                "webhook",
                "publish",
                "notify",
                "tweet",
                "share",
                "push",
                "forward",
                "broadcast",
            }
        ),
    ),
    (
        "delete",
        frozenset(
            {
                "delete",
                "remove",
                "drop",
                "destroy",
                "erase",
                "wipe",
                "purge",
                "truncate",
                "rm",
                "unlink",
                "kill",
                "terminate",
                "revoke",
                "clear",
                "reset",
                "uninstall",
            }
        ),
    ),
    (
        "write",
        frozenset(
            {
                "create",
                "add",
                "set",
                "write",
                "update",
                "edit",
                "rename",
                "modify",
                "put",
                "patch",
                "save",
                "append",
                "insert",
                "move",
                "copy",
                "apply",
                "commit",
                "import",
                "define",
                "make",
                "change",
                "replace",
                "label",
                "comment",
                "mkdir",
                "install",
                "deploy",
                "start",
                "stop",
                "enable",
                "disable",
                "assign",
                "register",
                "new",
                "touch",
                "chmod",
                "restore",
            }
        ),
    ),
    (
        "read",
        frozenset(
            {
                "get",
                "list",
                "read",
                "search",
                "find",
                "show",
                "view",
                "fetch",
                "query",
                "decompile",
                "disassemble",
                "describe",
                "info",
                "status",
                "count",
                "check",
                "lookup",
                "resolve",
                "browse",
                "ls",
                "cat",
                "ping",
                "version",
                "xrefs",
                "dump",
                "inspect",
                "analyze",
                "peek",
            }
        ),
    ),
)
_GRADE = {
    "read": "low",
    "write": "medium",
    "delete": "high",
    "external_send": "high",
    "exec": "high",
    "credential_access": "critical",
}
# 명령을 받는 인자 이름. 도구 이름이 읽기·쓰기처럼 보여도 실행으로 올린다.
_COMMAND_KEYS = frozenset({"command", "cmd", "script", "shell", "code", "expression"})


class Provisional(NamedTuple):
    action_type: str
    risk_grade: str


def _tokens(text: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    words = [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]
    return words + [w[:n] for w in words for n in (-1, -2) if w.endswith("s")]


def _kind(words: Iterable[str]) -> str | None:
    found = set(words)
    return next((kind for kind, verbs in _VERBS if found & verbs), None)


def infer(name: str, description: str = "", keys: Iterable[str] = ()) -> Provisional:
    """도구 이름(우선)·설명 첫 문장(이름에 낱말이 없을 때)·입력 항목 이름으로 임시 계약을 만든다."""
    names = {k for key in keys for k in _tokens(str(key))}
    names |= {str(key).lower() for key in keys}
    kind = _kind(_tokens(name)) or _kind(_tokens(re.split(r"[.!?\n]", description, maxsplit=1)[0]))
    if names & _COMMAND_KEYS and kind not in ("credential_access", "exec"):
        kind = "exec"
    kind = kind or "write"  # 알 수 없으면 읽기로 보지 않는다
    return Provisional(kind, _GRADE[kind])

"""승인된 실행 계약과 새로 보고된 실행 계약의 권한 변화를 파일·실행·네트워크 축으로 가른다.

계약이 직접 담는 값은 실행 파일·인자·작업 디렉터리·환경 변수·비밀 참조뿐이다. 경로로 보이는
인자·환경 값은 파일, 주소(``://``)로 보이는 인자·환경 값은 네트워크, 나머지는 실행으로 본다.
계약에 선언되지 않은 실제 파일·네트워크 접근은 알 수 없다.
"""

import re
from typing import Any

AXES = ("file", "exec", "network")
AXIS_LABEL = {"file": "파일 접근", "exec": "실행", "network": "네트워크"}
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"]+")
_PATH = re.compile(r"^(/|[A-Za-z]:[\\])")


def _place(axes: dict[str, set[str]], text: str, label: str) -> None:
    """값 하나를 축에 넣는다. 주소가 들어 있으면 주소만 네트워크, 경로면 파일, 아니면 실행."""
    urls = _URL.findall(text)
    if urls:
        axes["network"].update(urls)
    elif _PATH.match(text):
        axes["file"].add(f"{label}{text}")
    else:
        axes["exec"].add(f"{label}{text}")


def items(doc: dict[str, Any]) -> dict[str, set[str]]:
    axes: dict[str, set[str]] = {a: set() for a in AXES}
    axes["exec"].add(f"실행 파일 {doc.get('executable')}")
    axes["exec"].add(f"실행 파일 내용 {doc.get('executable_sha256')}")
    if doc.get("script_sha256"):
        axes["exec"].add(f"스크립트 내용 {doc['script_sha256']}")
    # 작업 디렉터리를 비워 두면 비교하지 않으므로 지정이 없는 쪽이 더 넓다.
    axes["file"].add(f"작업 디렉터리 {doc.get('cwd') or '제한 없음'}")
    for arg in doc.get("argv") or ():
        _place(axes, arg, "인자 ")
    for key, value in sorted((doc.get("env") or {}).items()):
        _place(axes, value, f"환경 변수 {key}=")
    for key in sorted(doc.get("secret_refs") or {}):
        axes["exec"].add(f"비밀 참조 {key}")
    return axes


def classify(approved: dict[str, Any], reported: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """축별 ``{verdict, added, removed}``. 더해진 항목이 하나라도 있으면 확대(``widened``)이다."""
    old, new = items(approved), items(reported)
    result = {}
    for axis in AXES:
        added, removed = sorted(new[axis] - old[axis]), sorted(old[axis] - new[axis])
        verdict = "widened" if added else "narrowed" if removed else "unchanged"
        result[axis] = {"verdict": verdict, "added": added, "removed": removed}
    return result


def widened_axes(result: dict[str, dict[str, Any]]) -> list[str]:
    return [a for a in AXES if result[a]["verdict"] == "widened"]


def summary(result: dict[str, dict[str, Any]]) -> str:
    """경보·콘솔에 쓰는 한국어 요약. 확대된 축은 더해진 항목을 나열한다."""
    parts = []
    for axis in AXES:
        r = result[axis]
        if r["verdict"] == "widened":
            parts.append(f"{AXIS_LABEL[axis]} 확대: {', '.join(r['added'])}")
        elif r["verdict"] == "narrowed":
            parts.append(f"{AXIS_LABEL[axis]} 축소")
    return "; ".join(parts) or "권한 변화 없음"

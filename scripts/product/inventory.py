"""콘솔 화면에서 실제 동작(양식 제출·확인 창·링크)과 라우트를 뽑아 CSV로 쓴다.

사람이 관리하는 SCREEN_ACTION_MATRIX와 대조하는 기준이다. 손으로 고치지 않는다.
실행: python scripts/product/inventory.py  (docs/product/generated/에 쓴다)
"""

import csv
import re
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONSOLE = ROOT / "src" / "mint_litellm" / "console"
OUT = ROOT / "docs" / "product" / "generated"

ROUTE = re.compile(r'@(\w+)\.(get|post|put|delete)\(\s*"([^"]+)"')
# app.py의 include_router 접두어: JSON API 묶음
API_PREFIX = {("api.py", "router"): "/api/v1", ("reports.py", "api_router"): "/api/v1"}
FUNC = re.compile(r"\ndef (\w+)\(|\nasync def (\w+)\(")
TEMPLATE_USE = re.compile(r'["\']([\w/]+\.html)["\']')
FORM = re.compile(r'<form\b[^>]*?\baction="([^"]+)"[^>]*>(.*?)</form>', re.S)
BUTTON = re.compile(r"<button\b[^>]*>(.*?)</button>", re.S)
CONFIRM = re.compile(
    r"confirm_dialog\(\s*([^,]+),\s*'([^']*)',\s*'([^']*)',\s*(?:'[^']*'|[^,]+),\s*([^,]+?),\s*actor"
)
LINK = re.compile(r'<a\b[^>]*\bhref="(/[^"#?]*)')
TAG = re.compile(r"<[^>]+>|\{[{%#].*?[}%#]\}", re.S)


def norm(path: str) -> str:
    """경로의 변수 부분을 {}로 바꾼다(라우트·템플릿 표기를 같은 꼴로).

    앞부분이 변수인 경로(base ~ id ~ '/x')는 *로 시작하고 뒷부분만 맞춰 본다.
    """
    path = re.sub(r"^[A-Za-z_][\w.]*\s*~\s*[\w.]+\s*~\s*'", "*/{}", path)
    path = re.sub(r"'\s*~\s*.*?~\s*'", "{}", path)  # '/a/' ~ x ~ '/b'
    path = re.sub(r"'\s*~\s*[^~]+$", "{}", path)  # '/a/' ~ x
    path = path.strip("'\" ")
    path = re.sub(r"\{\{.*?\}\}", "{}", path)
    path = re.sub(r"\{[a-z_]+(:path)?\}", "{}", path)
    path = re.sub(r"\{%.*?%\}", "", path)
    return path.split("?")[0].rstrip("/") or "/"


def matches(target: str, key: str) -> bool:
    """{}는 아무 한 마디와 맞는다(템플릿이 변수로 만든 경로)."""
    a, b = target.strip("/").split("/"), key.strip("/").split("/")
    if a[0] == "*":
        a, b = a[1:], b[-(len(a) - 1):]
    return len(a) == len(b) and all(x == y or "{}" in (x, y) for x, y in zip(a, b, strict=True))


def label(html: str) -> str:
    text = TAG.sub(" ", html)
    return re.sub(r"\s+", " ", text).strip()[:60]


def routes() -> list[dict]:
    rows = []
    for py in sorted(CONSOLE.rglob("*.py")):
        text = py.read_text(encoding="utf-8")
        # 경로 상수(`REQUESTS = "/staff/..."`)로 등록한 라우트도 문자열로 바꿔 읽는다
        for name, value in re.findall(r'^([A-Z_]+) = "(/[^"]*)"$', text, re.M):
            use = rf"(@\w+\.(?:get|post|put|delete)\(\s*){name}\b"
            text = re.sub(use, rf'\g<1>"{value}"', text)
        found = list(ROUTE.finditer(text))
        for i, m in enumerate(found):
            end = found[i + 1].start() if i + 1 < len(found) else len(text)
            body = text[m.end() : end]  # 다음 라우트까지가 이 처리기다
            fn = FUNC.search(body)
            templates = sorted(set(TEMPLATE_USE.findall(body)))
            path = API_PREFIX.get((py.name, m.group(1)), "") + m.group(3)
            rows.append(
                {
                    "method": m.group(2).upper(),
                    "path": path,
                    "key": norm(path),
                    "file": py.relative_to(ROOT).as_posix(),
                    "handler": (fn.group(1) or fn.group(2)) if fn else "",
                    "templates": " ".join(templates),
                }
            )
    # PC 키트가 부르는 단말 경로: 이름은 routes.py 상수로 등록된다
    endpoint = ROOT / "src" / "mint_litellm" / "endpoint"
    names = runpy.run_path(str(endpoint / "routes.py"))
    text = (endpoint / "decide.py").read_text(encoding="utf-8")
    for m in re.finditer(r"@router\.(get|post|put|delete)\((\w+)", text):
        path = names[m.group(2)]
        fn = FUNC.search(text[m.end():])
        rows.append({"method": m.group(1).upper(), "path": path, "key": norm(path),
                     "file": "src/mint_litellm/endpoint/decide.py",
                     "handler": (fn.group(1) or fn.group(2)) if fn else "", "templates": ""})
    return rows


def actions() -> list[dict]:
    rows = []
    for tpl in sorted((CONSOLE / "templates").rglob("*.html")):
        text = tpl.read_text(encoding="utf-8")
        name = tpl.relative_to(CONSOLE / "templates").as_posix()
        if name == "macros.html":
            continue  # 공용 확인 창 틀: 실제 대상은 부르는 화면에 있다
        for m in FORM.finditer(text):
            method = "POST" if re.search(r'method="post"', m.group(0)[:300], re.I) else "GET"
            buttons = [label(b) for b in BUTTON.findall(m.group(2))] or [""]
            for b in buttons:
                rows.append(
                    {
                        "screen": name,
                        "kind": "form",
                        "method": method,
                        "target": norm(m.group(1)),
                        "label": b,
                    }
                )
        for m in CONFIRM.finditer(text):
            rows.append(
                {
                    "screen": name,
                    "kind": "confirm",
                    "method": "POST",
                    "target": norm(m.group(4)),
                    "label": m.group(2),
                }
            )
        for m in LINK.finditer(text):
            rows.append(
                {
                    "screen": name,
                    "kind": "link",
                    "method": "GET",
                    "target": norm(m.group(1)),
                    "label": "",
                }
            )
    return rows


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    r, a = routes(), actions()
    with open(OUT / "ROUTES.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(r[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(r)
    seen = set()
    unique = []
    for row in a:  # 같은 화면의 같은 링크는 한 번만
        k = tuple(row.values())
        if k not in seen:
            seen.add(k)
            unique.append(row)
    with open(OUT / "SCREEN_INVENTORY.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(unique[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(unique)
    print(f"routes {len(r)}, actions {len(unique)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

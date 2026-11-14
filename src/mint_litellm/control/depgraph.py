"""패키지의 의존 패키지(전이 의존성) 목록을 deps.dev 형식 API로 구한다.

``GET {주소}/v3/systems/{npm|pypi}/packages/{이름}/versions/{버전}:dependencies`` 응답의 ``nodes``
(``versionKey``·``relation``)와 ``edges``(``fromNode``·``toNode``)에서 자기 자신을 뺀 모든 노드를
의존 패키지로 삼고, 자기 자신에서 가장 짧게 닿는 경로를 "A → B" 꼴로 적는다. 주소는 설정
(``MINT_DEPS_GRAPH_URL``, 기본 공개 deps.dev, 비우면 조회하지 않음)이다. 컨테이너 이미지는 조회할
공개 API가 없어 다루지 않는다.
"""

import re
from collections import deque
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

SYSTEM = {"npm": "npm", "pypi": "pypi"}
# 같은 패키지 버전의 그래프는 이 시간 안에는 다시 받지 않는다.
TTL = timedelta(days=1)
# 한 주기에 새로 받는 패키지 버전의 상한. 넘으면 다음 주기에 이어 받는다.
FETCH_LIMIT = 100
# 한 패키지가 끌고 오는 의존 패키지의 상한(넘는 부분은 버린다).
MAX_DEPS = 5000

Dep = tuple[str, str, str]  # (이름, 버전, 경로)


def _quote_name(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return quote(name, safe="")


def parse(doc: dict[str, Any], name: str, version: str) -> list[Dep]:
    """응답에서 자기 자신을 뺀 의존 패키지와 경로. 형식이 어긋나면 ValueError."""
    nodes, edges = doc.get("nodes") or [], doc.get("edges") or []
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("의존 그래프 응답의 형식이 다릅니다.")
    keys: list[tuple[str, str] | None] = []
    root = None
    for i, node in enumerate(nodes):
        vk = (node or {}).get("versionKey") or {}
        n, v = vk.get("name"), vk.get("version")
        keys.append((str(n), str(v)) if n and v else None)
        if (node or {}).get("relation") == "SELF" and root is None:
            root = i
    if root is None:
        raise ValueError("의존 그래프 응답에 자기 자신 노드가 없습니다.")
    children: dict[int, list[int]] = {}
    for e in edges:
        a, b = (e or {}).get("fromNode"), (e or {}).get("toNode")
        if (
            isinstance(a, int)
            and isinstance(b, int)
            and 0 <= a < len(nodes)
            and 0 <= b < len(nodes)
        ):
            children.setdefault(a, []).append(b)
    parent: dict[int, int | None] = {root: None}
    queue = deque([root])
    while queue:
        at = queue.popleft()
        for to in children.get(at, ()):
            if to not in parent:
                parent[to] = at
                queue.append(to)
    out: list[Dep] = []
    for i in parent:
        if i == root or keys[i] is None or keys[i] == (name, version):
            continue
        chain, at = [], i
        while at is not None:
            chain.append(keys[at][0] if keys[at] else "?")
            at = parent[at]
        chain[-1] = name  # 시작은 우리가 고른 이름(조회처가 이름을 정규화해도 그대로 보이게)
        out.append((keys[i][0], keys[i][1], " → ".join(reversed(chain))))
    return out[:MAX_DEPS]


def fetch_one(http: httpx.Client, base: str, ecosystem: str, name: str, version: str) -> list[Dep]:
    """한 패키지 버전의 의존 패키지. 조회처가 모르는 패키지(404)는 의존이 없는 것으로 본다."""
    url = (
        f"{base}/v3/systems/{SYSTEM[ecosystem]}/packages/{_quote_name(ecosystem, name)}"
        f"/versions/{quote(version, safe='')}:dependencies"
    )
    response = http.get(url)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return parse(response.json(), name, version)


def resolve(
    http: httpx.Client,
    base: str,
    tops: list[tuple[str, str, str]],
    cached: dict[tuple[str, str, str], datetime],
    now: datetime,
) -> tuple[dict[tuple[str, str, str], list[Dep]], Exception | None]:
    """오래됐거나 없는 패키지 버전의 그래프를 새로 받는다. (새로 받은 것, 처음 난 오류).

    오류가 나면 거기서 멈추고 이미 받은 것만 돌려준다(나머지는 알고 있는 그래프를 그대로 쓴다).
    """
    fresh: dict[tuple[str, str, str], list[Dep]] = {}
    for key in tops:
        if key in cached and now - cached[key] < TTL:
            continue
        if len(fresh) >= FETCH_LIMIT:
            break
        try:
            fresh[key] = fetch_one(http, base, *key)
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as error:
            return fresh, error
    return fresh, None

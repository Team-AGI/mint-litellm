"""계약 변경 요약: 승인본과 관측본의 차이를 사람이 읽는 한 줄 문장으로 만든다."""

import json
from typing import Any

DEPLOYMENT_FIELDS = {
    "url_sha256": "서버 주소",
    "transport": "전송 방식",
    "auth_type": "인증 방식",
    "issuer": "인증 발급자",
    "oauth_scopes": "인증 범위",
    "allowed_tools": "허용 도구",
    "image_digest": "이미지",
    "source_commit": "소스 커밋",
    "registry_missing": "레지스트리 항목",
}
_SHOWN = 5


def _load(value: Any) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _names(items: set[str]) -> str:
    shown = sorted(items)[:_SHOWN]
    extra = len(items) - len(shown)
    return ", ".join(shown) + (f" 외 {extra}개" if extra > 0 else "")


def _schema_keys(schema: Any) -> set[str]:
    props = schema.get("properties") if isinstance(schema, dict) else None
    return set(props) if isinstance(props, dict) else set()


def _schema_parts(label: str, old: Any, new: Any) -> list[str]:
    if old == new:
        return []
    before, after = _schema_keys(old), _schema_keys(new)
    parts = []
    if after - before:
        parts.append(f"{label} 항목 추가({_names(after - before)})")
    if before - after:
        parts.append(f"{label} 항목 삭제({_names(before - after)})")
    changed = {k for k in before & after if old["properties"][k] != new["properties"][k]}
    if changed:
        parts.append(f"{label} 항목 변경({_names(changed)})")
    required = (old or {}).get("required") != (new or {}).get("required")
    if required and not parts:
        parts.append(f"{label} 필수 항목 변경")
    return parts or [f"{label} 변경"]


def tool_summary(approved: Any, observed: Any) -> str:
    """도구 하나의 변경 요약. 승인본이 없으면 추가, 관측본이 없으면 삭제이다."""
    old, new = _load(approved), _load(observed)
    if not old and new:
        return "도구 추가"
    if old and not new:
        return "도구 삭제"
    parts = _schema_parts("입력", old.get("input_schema"), new.get("input_schema"))
    if old.get("description") != new.get("description"):
        parts.append("설명 변경")
    if old.get("annotations") != new.get("annotations"):
        parts.append("주석 변경")
    if "output_schema" in old and old["output_schema"] != new.get("output_schema"):
        parts += _schema_parts("출력", old["output_schema"], new.get("output_schema"))
    return ", ".join(parts)


def deployment_summary(fields: list[str], old: dict | None = None, new: dict | None = None) -> str:
    """배포 계약의 바뀐 항목 요약. 허용 도구는 추가·삭제된 이름까지 적는다."""
    parts = []
    for field in sorted(fields):
        label = DEPLOYMENT_FIELDS.get(field, field)
        if field == "allowed_tools" and old is not None and new is not None:
            before, after = set(old.get(field) or ()), set(new.get(field) or ())
            if after - before:
                parts.append(f"도구 추가({_names(after - before)})")
            if before - after:
                parts.append(f"도구 삭제({_names(before - after)})")
            if after != before:
                continue
        parts.append(f"{label} 변경")
    return ", ".join(parts)

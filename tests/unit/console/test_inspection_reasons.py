"""검사 사유 표시: 모든 사유 코드의 한국어 이름과 관리자 상세. 데이터베이스가 필요 없다."""

import re
from pathlib import Path

from mint_litellm.console import labels
from mint_litellm.console.templating import templates

ROOT = Path(__file__).parents[3]
CODE = re.compile(
    r"(?:Outcome\(\s*\"[a-z]+\",\s*|PackError\(\s*|\"reason\":\s*|reason\s*=\s*)\"([A-Z][A-Z_]+)\""
)
EXTRA = {"INSPECTION_FAILED", "INSPECTION_INCOMPLETE", "TIMEOUT", "OAUTH2_FLOW_UNCONFIRMED"}


def source_codes() -> set[str]:
    files = [*(ROOT / "src/mint_litellm/control").rglob("*.py"),
             ROOT / "deploy/inspector/inspect.py"]
    return {m for f in files for m in CODE.findall(f.read_text(encoding="utf-8"))} | EXTRA


def test_every_check_reason_code_in_the_source_has_a_korean_name():
    codes = source_codes()
    assert {"PACK_RESOLVE_FAILED", "NO_DEFINITIONS", "INSPECTION_UNAVAILABLE"} <= codes
    missing = sorted(c for c in codes if c not in labels.CHECK_REASON)
    assert not missing
    assert all(re.search("[가-힣]", t) for t in labels.CHECK_REASON.values())


def test_local_check_names_and_inspection_stages_are_translated():
    for name in ("exec_shape", "pack_build", "inspection"):
        assert re.search("[가-힣]", labels.CHECK[name])
    assert set(labels.INSPECTION_STAGE) == {"start", "initialize", "tools_list"}


def cell(**inputs) -> str:
    source = (ROOT / "src/mint_litellm/console/templates/intake_detail.html").read_text(
        encoding="utf-8")
    start = source.index("<td>{{ L.pick(L.CHECK_REASON, c.reason_code) }}")
    template = templates.env.from_string(source[start: source.index("</td>", start) + 5])
    check = {"reason_code": "INSPECTION_FAILED", "inputs": inputs}
    return template.render(c=check, L=labels)


def test_the_admin_sees_a_readable_reason_and_a_folded_detail():
    html = cell(detail={"stage": "start", "exit_code": 1,
                        "stderr_tail": "ValueError: GHIDRA_INSTALL_DIR is not set"})
    assert "검사 중 서버가 실패함" in html and "<details>" in html
    assert "서버 시작" in html and "종료 코드 1" in html
    assert "GHIDRA_INSTALL_DIR is not set" in html


def test_no_detail_means_no_fold_and_markup_in_output_is_escaped():
    assert "<details>" not in cell()
    assert "<script>" not in cell(detail={"stage": "start", "exit_code": None,
                                          "stderr_tail": "<script>x</script>"})

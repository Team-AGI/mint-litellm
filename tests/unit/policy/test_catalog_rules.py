import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_catalog_lists_every_rule_the_bundle_can_apply():
    rego = (ROOT / "policy/bundle/mint/policy.rego").read_text(encoding="utf-8")
    ids = set(re.findall(r'"((?:POL-[A-Z]-\d\d)|R\d)"', rego))
    catalog = json.loads((ROOT / "policy/catalog.json").read_text(encoding="utf-8"))
    assert {rule["id"] for rule in catalog["rules"]} == ids
    for rule in catalog["rules"]:
        if rule["id"].startswith("POL-"):
            assert rule["observable"] is True and rule["output"] == "Block"


def _catalog():
    return json.loads((ROOT / "policy/catalog.json").read_text(encoding="utf-8"))


def test_catalog_maps_the_rules_to_the_policies_they_really_enforce():
    refs = {rule["id"]: rule["reference_policies"] for rule in _catalog()["rules"]}
    assert refs["R1"] == ["POL-I-03", "POL-E-01", "POL-E-03"]
    # 고위험 도구 호출 승인(위험 등급 반영·본인 확인 대상)과 동의 확인
    assert refs["R2"] == ["POL-I-02", "POL-I-10"]
    assert refs["R4"] == ["POL-R-21", "POL-R-22"]
    for rule_id, policies in refs.items():
        if rule_id.startswith("POL-"):
            assert policies == [rule_id]


def test_endpoint_policies_are_counted_only_where_a_rule_or_a_check_backs_them():
    catalog = _catalog()
    entries = catalog["rules"] + catalog["checks"]
    counted = {p for entry in entries for p in entry["reference_policies"]}
    # 로컬 서버 실행 계약(호출 통제 부분), 폐기 항목 잔존(보고 기반), 관리형 설치(관리형에서만)
    assert {"POL-R-18", "POL-R-20", "POL-D-02", "POL-E-06"} <= counted
    # 프로세스·자동 시작 점검(보고 기반)이 D-04를 받친다. I-08은 경보 없이 계약 해시에 묶인다.
    assert "POL-D-04" in counted
    assert all(check["output"] == "alert" for check in catalog["checks"])


# --- 구현 상태 집계(집계 원천은 이 카탈로그의 policies 절) -----------------------------

CLASSES = {"unconditional", "conditional", "partial", "semi_auto_evidence"}


def _policies():
    return _catalog()["policies"]


def _count(cls):
    return sum(1 for p in _policies() if p["class"] == cls)


def test_every_counted_policy_is_listed_once_with_a_known_class():
    ids = [p["id"] for p in _policies()]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"POL-[IREOD]-\d\d", i) for i in ids)
    assert {p["class"] for p in _policies()} <= CLASSES
    # 셌다고 하면서 집행 위치를 대지 못하는 항목은 없다.
    assert all(p["enforced_by"] for p in _policies())
    # 부분·조건부는 어디까지만 되는지 적어야 한다.
    assert all(p.get("limit") for p in _policies() if p["class"] in {"conditional", "partial"})


def _defined_names(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def test_enforcing_locations_point_inside_files_that_exist():
    """경로:줄 또는 경로::이름(함수·클래스·대입 이름) 형식. 이름 형식은 줄이 밀려도 유지된다."""
    for policy in _policies():
        for ref in policy["enforced_by"]:
            if "::" in ref:
                path, _, symbol = ref.partition("::")
                assert symbol in _defined_names(ROOT / path), (policy["id"], ref)
                continue
            path, _, line = ref.rpartition(":")
            lines = (ROOT / path).read_text(encoding="utf-8").splitlines()
            assert 1 <= int(line) <= len(lines), (policy["id"], ref)


def test_the_five_class_count_is_pinned():
    auto = _count("unconditional") + _count("conditional") + _count("partial")
    # 2단계 완료 기준 42(확인 26·조건부 10·부분 6)에서 엔드포인트 4, 재사용 설정 점검 13,
    # 3단계로 미룬 집행 4, 입력 쪽 비밀 차단(E-05), 통합 시험으로 LiteLLM 동작을 확인해 닫은
    # 재사용 2(R-17·E-24)를 더하고, 결과 상한 기본값으로 E-16이 무조건으로 옮겨 가며
    # 목적지 통제(O-12), 프로세스·자동 시작 점검(D-04), 선언 파일 접근(I-08),
    # 토큰 대상·전달(R-05·R-06), 패키지 기록·취약점 조회·치명 취약점 기한(O-06·O-07·O-08),
    # 서버 폐기 때 사용자 자격 삭제와 읽어 확인(D-03)이 늘었다. 승인 재확인(O-14)은 기본 집행이라
    # 무조건으로, 경보 시험(O-17)은 새 도구 경보가 계약 관리 서버에만 열려 조건부로 옮겼다.
    # 폐기 서버 항목 잔존(D-02)은 관리형 설치에서 묶음이 지우고 실행기가 시작하지 않아
    # 부분에서 조건부로, 인스턴스 사이 불일치(O-09)는 유예 뒤 차단으로 조건부로 옮겼다.
    # 서버 실행기가 계약에서 만든 격리 안에서 서버를 시작해 파일·네트워크 접근 통제(O-13)와
    # 선언 파일 접근(I-08)은 Linux·Windows 관리형 설치에서 조건부이다.
    # 서버 실행기가 승인된 계약과 맞을 때만 서버를 시작하고 폐기 서버를 거부해 로컬 서버 시작
    # 통제(R-18·R-20)는 관리형 설치에서 부분에서 조건부로 옮겼다.
    assert (_count("unconditional"), _count("conditional"), _count("partial")) == (38, 21, 14)
    assert auto == 73
    # 목표(90개 중 72개 이상) 산정은 반자동 수동 증거를 함께 센다.
    assert _count("semi_auto_evidence") == 12
    assert auto + _count("semi_auto_evidence") == 85


def test_policies_that_are_not_counted_stay_out_of_the_count():
    counted = {p["id"] for p in _policies()}
    not_counted = {p["id"]: p["reason"] for p in _catalog()["not_counted"]}
    assert not counted & set(not_counted)
    assert not not_counted  # 현재 세지 않는 정책은 없다
    assert all(not_counted.values())


def test_every_policy_backed_by_a_rule_or_a_check_is_counted():
    catalog = _catalog()
    refs = {p for e in catalog["rules"] + catalog["checks"] for p in e["reference_policies"]}
    counted = {p["id"] for p in _policies()}
    assert {r for r in refs if r.startswith("POL-")} <= counted


def test_the_reuse_policies_counted_are_the_ones_the_self_check_maps():
    from mint_litellm.types.settings import REUSE_POLICIES

    reuse = {p["id"] for p in _policies() if p["pr"] == 65}
    # 번호가 없는 재사용 정책도 점검 표에 들 수 있다. 표에 있는 정책은 모두 집계에 든다.
    assert reuse <= set(REUSE_POLICIES) <= {p["id"] for p in _policies()}


def test_the_semi_automated_evidence_policies_are_the_evidence_kinds():
    from mint_litellm.control.services.evidence import KINDS

    evidence = {p["id"] for p in _policies() if p["class"] == "semi_auto_evidence"}
    # 승인 조건·예외를 받는 보조 증빙(unpinned·exception)은 반자동 정책의 증빙이 아니다.
    own = {k.policy for k in KINDS.values() if k.gate not in {"unpinned", "exception"}}
    assert evidence == own

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
    # 실행 계약에 마운트·권한 필드가 없고 프로세스 점검이 없어 아직 세지 않는다.
    assert not {"POL-I-08", "POL-D-04"} & counted
    assert all(check["output"] == "alert" for check in catalog["checks"])

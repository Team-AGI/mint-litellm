import json

from mint_litellm.control.change_summary import deployment_summary, tool_summary


def tool(props=None, description="d", **extra):
    return json.dumps({"description": description,
                       "input_schema": {"properties": props or {}}, **extra})


def test_added_and_removed_tools():
    assert tool_summary(None, {"description": "x"}) == "도구 추가"
    assert tool_summary(tool(), None) == "도구 삭제"


def test_input_schema_keys_are_named():
    old = tool({"a": {"type": "string"}, "b": {"type": "string"}})
    new = {"description": "d", "input_schema": {"properties": {
        "b": {"type": "integer"}, "c": {"type": "string"}}}}
    assert tool_summary(old, new) == "입력 항목 추가(c), 입력 항목 삭제(a), 입력 항목 변경(b)"


def test_description_and_output_changes():
    old = tool(output_schema={"properties": {"x": {}}})
    new = {"description": "e", "input_schema": {"properties": {}},
           "output_schema": {"properties": {"x": {}, "y": {}}}}
    assert tool_summary(old, new) == "설명 변경, 출력 항목 추가(y)"


def test_long_name_lists_are_cut():
    new = {"input_schema": {"properties": {f"k{i}": {} for i in range(8)}}}
    assert "외 3개" in tool_summary(tool(), new)


def test_deployment_fields_and_allowed_tools():
    assert deployment_summary(["url_sha256", "auth_type"]) == "인증 방식 변경, 서버 주소 변경"
    text = deployment_summary(
        ["allowed_tools"], {"allowed_tools": ["a", "b"]}, {"allowed_tools": ["b", "c"]})
    assert text == "도구 추가(c), 도구 삭제(a)"

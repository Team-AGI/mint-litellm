"""MCP 서버 이름: LiteLLM이 하이픈을 받지 않으므로 밑줄, 저장소 주소는 저장소 이름과 안내."""

import pytest

from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import staff_intakes
from mint_litellm.endpoint.kit import mint_kit


@pytest.mark.parametrize("name", [staff_intakes.server_name, mint_kit.remote_name])
def test_names_have_no_hyphen_and_follow_the_repository(name):
    assert name("https://mcp.context7.com/mcp") == "context7_com"
    assert name("https://mcp.deepwiki.com/mcp") == "deepwiki_com"
    assert name("https://github.com/bethington/ghidra-mcp") == "ghidra_mcp"
    assert name("https://gitlab.com/a/b-c.git") == "b_c"


def test_a_repository_address_is_explained_instead_of_failing_at_litellm():
    form = {"url": "https://github.com/bethington/ghidra-mcp", "purpose": "분석"}
    with pytest.raises(ControlError, match="소스 저장소 주소입니다.*mint add ghidra_mcp"):
        staff_intakes.validate(form)
    assert "소스 저장소 주소" in mint_kit.remote_problem("https://github.com/bethington/ghidra-mcp")
    assert mint_kit.remote_problem("https://mcp.context7.com/mcp") is None

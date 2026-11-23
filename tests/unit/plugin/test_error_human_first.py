from mint_litellm.types.errors import MintError, error_for_reason
from mint_litellm.types.reason_codes import Reason


def test_mcp_error_text_leads_with_guidance_and_stays_parseable():
    error = error_for_reason(Reason.SCHEMA_ERROR.value, "ref-1").model_copy(
        update={"guidance": "관리자가 막은 도구입니다."}
    )
    text = error.detail(human_first=True)
    assert text.split("\n", 1)[0] == "관리자가 막은 도구입니다."
    assert MintError.from_detail(text) == error
    assert error.detail().startswith("{")  # HTTP 본문 계약은 그대로

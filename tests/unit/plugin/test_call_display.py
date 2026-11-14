"""승인 화면의 인자 표시는 저장 전에 비밀·개인정보를 가리고 길이를 자른다."""

from mint_litellm.plugin.call_display import MAX_FIELDS, MAX_VALUE_CHARS, call_display


def test_secrets_and_personal_data_are_masked_and_long_values_cut():
    shown = call_display({
        "query": "mail a@b.co key AKIAABCDEFGHIJKLMNOP",
        "password": "hunter2",
        "body": {"k": "v" * 1000},
        "n": 3,
    })
    text = str(shown)
    assert "hunter2" not in text and "AKIAABCDEFGHIJKLMNOP" not in text
    assert shown["password"] == "[MASKED]"
    assert "[MASKED:" in shown["query"]
    assert len(shown["body"]) <= MAX_VALUE_CHARS + 1 and shown["body"].endswith("…")
    assert shown["n"] == "3"


def test_the_number_of_fields_is_bounded():
    shown = call_display({f"k{i}": i for i in range(MAX_FIELDS + 5)})
    assert len(shown) == MAX_FIELDS + 1 and shown["…"] == "5"

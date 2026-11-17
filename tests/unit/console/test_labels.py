from mint_litellm.console import labels


def test_pick_shows_only_the_text_of_a_status_label():
    # 상태 표에서 고른 값이 화면에 객체 표기로 새면 안 된다.
    assert labels.pick(labels.DECISION, "rejected") == "거절됨"
    assert labels.pick(labels.DECISION, None) == "—"
    assert labels.pick(labels.DECISION, "unknown") == "unknown"

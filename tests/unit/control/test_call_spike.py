"""호출량 급증 판정: 기준 없음, 최소 호출 수 미달, 급증, 평소 수준 회복."""

from mint_litellm.control.call_spike import is_spike

BUCKETS = 288  # 5분 구간 하루치


def test_no_baseline_still_needs_the_minimum():
    assert is_spike(50, 0, BUCKETS, 3, 50)
    assert not is_spike(49, 0, BUCKETS, 3, 50)


def test_below_the_minimum_is_never_a_spike():
    assert not is_spike(40, 10, BUCKETS, 3, 50)  # 평균의 수백 배여도 50건 미만이면 아니다


def test_three_times_the_average_is_a_spike():
    history = 100 * BUCKETS  # 구간당 평균 100건
    assert not is_spike(299, history, BUCKETS, 3, 50)
    assert is_spike(300, history, BUCKETS, 3, 50)


def test_back_to_normal_is_not_a_spike():
    history = 100 * BUCKETS
    assert is_spike(500, history, BUCKETS, 3, 50)
    assert not is_spike(110, history, BUCKETS, 3, 50)

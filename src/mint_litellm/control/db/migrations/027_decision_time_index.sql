-- 호출량 급증 탐지가 판정 사건만 시간 범위로 읽도록 부분 색인을 둔다(사건 표 자체는 바꾸지 않는다).
CREATE INDEX events_decisions_by_time ON mint.events (instance_id, inserted_at)
    WHERE kind = 'decision_evaluated';

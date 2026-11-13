-- 대량 추출 탐지가 응답 사건만 시간 범위로 읽도록 부분 색인을 둔다(사건 표 자체는 바꾸지 않는다).
CREATE INDEX events_responses_by_time ON mint.events (instance_id, inserted_at)
    WHERE kind = 'call_response_received';

-- 승인 운영 지표가 기간 안의 요청을 인스턴스·요청 시각으로 훑는다. 행이 늘어도 기간 조회가
-- 표 전체를 읽지 않게 한다.
CREATE INDEX call_approvals_requested
    ON mint.call_approvals (instance_id, requested_at);

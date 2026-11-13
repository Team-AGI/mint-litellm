-- 지표 롤업. 판정·결과·판정 시간 구간의 누적 건수를 작은 표에 두고, 작업 실행기가 워터마크 뒤의
-- 사건만 읽어 더한다. 사건 표는 바꾸지 않는다(추가만 가능한 성질과 트리거는 그대로).

CREATE TABLE mint.metric_state (
    instance_id  mint.ident PRIMARY KEY,
    -- 이 시각까지(포함) 들어온 사건이 metric_counts에 모두 반영되어 있다. 비어 있으면 아직 없다.
    watermark_at timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mint.metric_counts (
    instance_id mint.ident NOT NULL,
    family      text NOT NULL CHECK (family IN ('decision', 'call_result', 'latency')),
    -- decision: (서버, 결과)  call_result: ('', 결과)  latency: ('', 구간 이름 또는 'all')
    label_a     text NOT NULL,
    label_b     text NOT NULL,
    n           bigint NOT NULL CHECK (n >= 0),
    total_us    bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (instance_id, family, label_a, label_b)
);

REVOKE ALL ON mint.metric_state, mint.metric_counts FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.metric_state TO mint_control;
GRANT SELECT, INSERT, UPDATE, DELETE ON mint.metric_counts TO mint_control;

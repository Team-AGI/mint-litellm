-- SIEM 전달 대상. 대상마다 설정, 전달 위치(봉인 순번), 상태·건수를 한 행에 둔다.
-- 비밀은 저장하지 않고 읽을 곳(secret_ref: env:<이름> 또는 file:<경로>)만 둔다.
CREATE TABLE mint.siem_targets (
    instance_id          mint.ident NOT NULL,
    name                 text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_-]{0,31}$'),
    kind                 text NOT NULL
        CHECK (kind IN ('syslog', 'cef', 'hec', 'elastic', 'otlp')),
    endpoint             text NOT NULL CHECK (length(endpoint) BETWEEN 1 AND 512),
    secret_ref           text CHECK (secret_ref IS NULL OR length(secret_ref) <= 512),
    options              jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(options) = 'object'),
    -- 이 순번까지(포함) 보냈다. 봉인 순번은 되살린 사건도 뒤에 붙으므로 빠짐이 없다.
    cursor_seq           bigint NOT NULL DEFAULT 0 CHECK (cursor_seq >= 0),
    sent_total           bigint NOT NULL DEFAULT 0,
    failed_total         bigint NOT NULL DEFAULT 0,
    last_delivered_at    timestamptz,
    last_attempt_at      timestamptz,
    last_error           text CHECK (last_error IS NULL OR length(last_error) <= 100),
    failing_since        timestamptz,
    consecutive_failures integer NOT NULL DEFAULT 0,
    next_attempt_at      timestamptz,
    -- 시험 전송 요청과 결과. 비밀은 작업 실행기만 읽으므로 요청은 행에 남기고 실행기가 처리한다.
    test_requested_at    timestamptz,
    last_test_at         timestamptz,
    last_test_error      text CHECK (last_test_error IS NULL OR length(last_test_error) <= 100),
    created_by           text NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, name)
);

REVOKE ALL ON mint.siem_targets FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON mint.siem_targets TO mint_control;

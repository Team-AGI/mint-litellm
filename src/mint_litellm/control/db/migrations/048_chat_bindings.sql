-- 채팅 승인: 채팅 사용자와 운영자의 결속(관리자가 지정)과 이미 처리한 요청 서명(재전송 방지).
CREATE TABLE mint.operator_chat_bindings (
    instance_id   mint.ident NOT NULL,
    operator_name text NOT NULL,
    channel       text NOT NULL CHECK (channel IN ('slack')),
    external_id   text NOT NULL CHECK (length(external_id) BETWEEN 1 AND 64),
    bound_by      text NOT NULL,
    bound_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (instance_id, operator_name, channel),
    UNIQUE (instance_id, channel, external_id),
    FOREIGN KEY (instance_id, operator_name) REFERENCES mint.operators (instance_id, name)
);

CREATE TABLE mint.chat_requests_seen (
    instance_id mint.ident NOT NULL,
    digest      text NOT NULL,
    seen_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (instance_id, digest)
);

REVOKE ALL ON mint.operator_chat_bindings, mint.chat_requests_seen FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON mint.operator_chat_bindings TO mint_control;
GRANT SELECT, INSERT, DELETE ON mint.chat_requests_seen TO mint_control;

-- 관리자가 도구별로 지정한 호출별 검토. 행이 있는 도구만 호출마다 승인을 받는다.
CREATE TABLE mint.call_review_tools (
    instance_id mint.ident NOT NULL,
    server_id   text NOT NULL,
    tool        text NOT NULL,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (instance_id, server_id, tool)
);

REVOKE ALL ON mint.call_review_tools FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON mint.call_review_tools TO mint_control;
GRANT SELECT ON mint.call_review_tools TO mint_plugin;

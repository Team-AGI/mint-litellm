-- 시작하기 점검표가 사건으로 남기지 않는 일회성 완료 표시(알림 시험 전송, 감사 보고서 생성).
CREATE TABLE mint.setup_marks (
    instance_id mint.ident NOT NULL,
    mark        text NOT NULL CHECK (mark IN ('webhook_test', 'audit_report')),
    marked_by   text NOT NULL,
    marked_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (instance_id, mark)
);

REVOKE ALL ON mint.setup_marks FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.setup_marks TO mint_control;

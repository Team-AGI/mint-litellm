-- 사람이 확인하는 정책의 증빙. 행은 추가만 하고 고치지 않는다.
-- 같은 (대상 구분, 대상, 종류)에서 가장 최근에 붙인 행이 현재 증빙이다.
-- 대상은 구분마다 다른 표를 가리키므로 외래 키를 두지 않고 서비스 계층이 존재를 확인한다.
CREATE TABLE mint.policy_evidence (
    id              uuid PRIMARY KEY,
    instance_id     mint.ident NOT NULL,
    kind            text NOT NULL CHECK (kind ~ '^[a-z][a-z_]*$'),
    subject_kind    text NOT NULL CHECK (subject_kind IN ('intake', 'server', 'relation')),
    subject_id      text NOT NULL CHECK (length(subject_id) > 0),
    result          text NOT NULL DEFAULT 'confirmed'
                    CHECK (result IN ('confirmed', 'not_applicable')),
    summary         text NOT NULL CHECK (length(summary) BETWEEN 1 AND 2000),
    document_ref    text CHECK (document_ref IS NULL OR length(document_ref) BETWEEN 1 AND 2048),
    document_sha256 text CHECK (document_sha256 IS NULL OR document_sha256 ~ '^[0-9a-f]{64}$'),
    attached_by     text NOT NULL CHECK (length(attached_by) > 0),
    attached_at     timestamptz NOT NULL DEFAULT now(),
    valid_until     timestamptz,
    CHECK (valid_until IS NULL OR valid_until > attached_at)
);

CREATE INDEX policy_evidence_latest
    ON mint.policy_evidence (instance_id, subject_kind, subject_id, kind, attached_at DESC);

CREATE TRIGGER policy_evidence_1_append_only BEFORE UPDATE OR DELETE ON mint.policy_evidence
    FOR EACH ROW EXECUTE FUNCTION mint.reject_mutation();
CREATE TRIGGER policy_evidence_2_truncate BEFORE TRUNCATE ON mint.policy_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION mint.reject_mutation();

GRANT SELECT, INSERT ON mint.policy_evidence TO mint_control;

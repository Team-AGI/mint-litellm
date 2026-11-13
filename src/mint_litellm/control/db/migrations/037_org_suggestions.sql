-- 조직 연결 제안: 점검 작업이 LiteLLM 팀·사용자를 읽어 규칙으로 만든 제안. 사람이 적용하기
-- 전에는 아무것도 묶이지 않는다. 주체당 한 행이며 무시한 제안은 다시 열리지 않는다.
CREATE TABLE mint.org_suggestions (
    id           uuid PRIMARY KEY,
    instance_id  mint.ident NOT NULL,
    subject_type text NOT NULL CHECK (subject_type IN ('team', 'user')),
    subject_id   text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 256),
    org_id       mint.ident NOT NULL,
    rule         text NOT NULL CHECK (rule IN ('team_metadata', 'team_alias', 'email_domain')),
    matched      text NOT NULL CHECK (length(matched) BETWEEN 1 AND 512),
    calls        integer NOT NULL DEFAULT 0 CHECK (calls >= 0),
    status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'applied', 'ignored')),
    decided_by   text,
    decided_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (instance_id, org_id) REFERENCES mint.orgs (instance_id, org_id),
    UNIQUE (instance_id, subject_type, subject_id)
);

-- 사용자 이메일 도메인과 조직의 대응. 운영자가 고친다.
CREATE TABLE mint.org_suggest_domains (
    instance_id mint.ident NOT NULL,
    domain      text NOT NULL CHECK (domain = lower(domain) AND length(domain) BETWEEN 1 AND 253),
    org_id      mint.ident NOT NULL,
    PRIMARY KEY (instance_id, domain),
    FOREIGN KEY (instance_id, org_id) REFERENCES mint.orgs (instance_id, org_id)
);

REVOKE ALL ON mint.org_suggestions, mint.org_suggest_domains FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON mint.org_suggestions, mint.org_suggest_domains
    TO mint_control;

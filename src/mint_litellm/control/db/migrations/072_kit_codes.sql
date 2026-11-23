-- 단말 한 줄 설치 명령의 1회용 코드. 코드는 SHA-256만 저장하고 한 번 쓰면 닫힌다.
CREATE TABLE mint.kit_codes (
    code_hash   text PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    instance_id mint.ident NOT NULL,
    user_id     text NOT NULL CHECK (length(user_id) > 0),
    team_id     text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);

REVOKE ALL ON mint.kit_codes FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.kit_codes TO mint_control;

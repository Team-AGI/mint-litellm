-- 한 사람의 비밀번호·개인 키·SSO 신원을 같은 LiteLLM 사용자에 잇는 명부. LiteLLM이 정본이고 여기는 사본이다.
CREATE TABLE mint.directory_users (
    instance_id  mint.ident NOT NULL,
    user_id      text NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    email        text CHECK (length(email) <= 320),
    litellm_role text NOT NULL CHECK (length(litellm_role) BETWEEN 1 AND 64),
    team_ids     jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(team_ids) = 'array'),
    -- 로그인이 자동으로 만든 운영자 행의 이름. 사람이 만든 운영자 행은 건드리지 않는다.
    auto_operator mint.ident,
    gone_at      timestamptz,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    synced_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, user_id)
);

-- 자격마다 한 줄: ref는 콘솔 세션의 key_token과 같은 값(키는 SHA-256, 비밀번호는 pw:, SSO는 sso: 접두사).
CREATE TABLE mint.directory_credentials (
    instance_id   mint.ident NOT NULL,
    kind          text NOT NULL CHECK (kind IN ('password', 'key', 'sso')),
    ref           text NOT NULL CHECK (length(ref) BETWEEN 1 AND 128),
    user_id       text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    gone_at       timestamptz,
    PRIMARY KEY (instance_id, kind, ref),
    FOREIGN KEY (instance_id, user_id) REFERENCES mint.directory_users (instance_id, user_id)
);
CREATE INDEX directory_credentials_by_user ON mint.directory_credentials (instance_id, user_id);

REVOKE ALL ON mint.directory_users, mint.directory_credentials FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.directory_users, mint.directory_credentials TO mint_control;

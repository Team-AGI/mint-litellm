-- 관리 화면에서 정한 알림(웹훅) 주소. 주소에 비밀이 있어 암호문으로만 둔다.
CREATE TABLE mint.webhook_settings (
    instance_id mint.ident PRIMARY KEY,
    sealed      bytea NOT NULL CHECK (octet_length(sealed) BETWEEN 29 AND 16384),
    updated_by  text NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON mint.webhook_settings FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON mint.webhook_settings TO mint_control;
GRANT SELECT ON mint.webhook_settings TO mint_worker;

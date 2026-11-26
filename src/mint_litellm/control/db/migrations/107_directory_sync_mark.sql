-- 정기 명부 동기화의 마지막 시각(로그인이 갱신하는 사람별 synced_at과 따로 둔다).
CREATE TABLE mint.directory_sync (
    instance_id text PRIMARY KEY,
    synced_at   timestamptz NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON mint.directory_sync TO mint_control;

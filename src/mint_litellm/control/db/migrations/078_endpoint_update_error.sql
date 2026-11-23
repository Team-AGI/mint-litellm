-- 단말이 보고한 키트 자동 갱신 실패 사유(성공하면 비운다).
ALTER TABLE mint.endpoint_installs ADD COLUMN update_error text CHECK (char_length(update_error) <= 80);
GRANT UPDATE (update_error) ON mint.endpoint_installs TO mint_plugin;

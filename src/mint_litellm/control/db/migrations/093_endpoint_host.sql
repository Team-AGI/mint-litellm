-- 단말 목록에서 어느 PC인지 알아보게 PC 이름과 OS를 보고에 싣는다(단말의 주장이다).
ALTER TABLE mint.endpoint_installs
    ADD COLUMN host text CHECK (host IS NULL OR length(host) <= 255),
    ADD COLUMN os text CHECK (os IS NULL OR length(os) <= 64);
GRANT UPDATE (host, os) ON mint.endpoint_installs TO mint_plugin;

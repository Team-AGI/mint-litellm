-- 단말이 설치 보고에 담아 보내는 프로세스·자동 시작 인벤토리(단말의 주장). 보고가 없던 행과
-- 이전 묶음의 행은 비어 있다(NULL). processes: [{server, count}], autostart: [{kind, name, server}].
-- 새 열은 기존 표의 권한을 그대로 따르고, 판정 프로세스 역할은 보고 열만 바꿀 수 있다. 고정 열과
-- 고정 트리거는 건드리지 않는다.
ALTER TABLE mint.endpoint_installs
    ADD COLUMN processes jsonb CHECK (processes IS NULL OR jsonb_typeof(processes) = 'array'),
    ADD COLUMN autostart jsonb CHECK (autostart IS NULL OR jsonb_typeof(autostart) = 'array');

GRANT UPDATE (processes, autostart) ON mint.endpoint_installs TO mint_plugin;

-- 단말이 설치 보고에 담아 보내는, 묶음 실행기 밖에서 직접 돈 MCP 서버 패키지(단말의 주장).
-- 항목: {package, ecosystem, count}. 패키지 식별자만 받고 인자·경로·사용자 이름은 받지 않는다.
-- 보고가 없던 행과 이전 묶음의 행은 비어 있다(NULL).
ALTER TABLE mint.endpoint_installs
    ADD COLUMN outside_processes jsonb
        CHECK (outside_processes IS NULL OR jsonb_typeof(outside_processes) = 'array');

GRANT UPDATE (outside_processes) ON mint.endpoint_installs TO mint_plugin;

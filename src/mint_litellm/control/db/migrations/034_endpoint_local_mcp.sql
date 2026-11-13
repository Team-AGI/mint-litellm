-- 단말이 설치 보고에 담아 보내는, MINT가 관리하지 않는 로컬 MCP 설정 항목(단말의 주장).
-- 항목: {harness, name, kind, target, package, first_seen}. 실행 파일 이름이나 호스트만 받고
-- 인자·환경 변수·토큰은 받지 않는다. 보고가 없던 행과 이전 묶음의 행은 비어 있다(NULL).
ALTER TABLE mint.endpoint_installs
    ADD COLUMN local_mcp jsonb CHECK (local_mcp IS NULL OR jsonb_typeof(local_mcp) = 'array');

GRANT UPDATE (local_mcp) ON mint.endpoint_installs TO mint_plugin;

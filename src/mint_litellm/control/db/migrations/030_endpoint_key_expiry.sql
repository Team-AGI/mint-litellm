-- 단말 설치 묶음 키의 만료. expires_at이 지난 키의 보고는 판정 프로세스가 거부하고, 만료 전
-- 14일 안에 들어온 보고가 만료 시각을 ttl_days만큼 늘린다(키 값은 그대로이다).
-- 두 열은 함께 채워지거나 함께 비어 있다. 비어 있으면 만료가 없다.
-- 이미 발급된 해제되지 않은 키는 이 마이그레이션 시점부터 90일 뒤에 만료된다.
-- 새 열은 기존 표의 권한을 따르고, 판정 프로세스 역할은 만료 시각만 바꿀 수 있다(ttl_days는
-- 읽기만 한다). 고정 열과 고정 트리거는 건드리지 않는다.
ALTER TABLE mint.endpoint_installs
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN ttl_days integer CHECK (ttl_days BETWEEN 30 AND 365),
    ADD CONSTRAINT endpoint_installs_expiry_pair CHECK ((expires_at IS NULL) = (ttl_days IS NULL));

UPDATE mint.endpoint_installs
    SET expires_at = clock_timestamp() + interval '90 days', ttl_days = 90
    WHERE revoked_at IS NULL;

GRANT UPDATE (expires_at) ON mint.endpoint_installs TO mint_plugin;

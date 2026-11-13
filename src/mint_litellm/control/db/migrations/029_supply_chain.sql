-- 공급망 통제: 로컬 실행(stdio) 서버가 쓰는 패키지의 기록, 알려진 취약점 조회 결과, 치명 취약점의
-- 조치 기한 차단 표지.

-- 서버의 실행 계약에서 뽑은 패키지(제공처·이름·버전). 계약이 바뀔 때마다 그 계약의 행을 더하며 고치지
-- 않는다. 서버의 현재 패키지는 서버 행의 현재 계약 해시와 같은 행이다. version은 지정한 문자열이고
-- (범위·태그 포함) 지정이 없으면 비어 있다. pinned는 정확히 하나의 버전으로 정해졌는지이다.
CREATE TABLE mint.server_packages (
    id                   uuid PRIMARY KEY,
    instance_id          mint.ident NOT NULL,
    server_id            text NOT NULL,
    exec_contract_sha256 text NOT NULL CHECK (exec_contract_sha256 ~ '^[0-9a-f]{64}$'),
    ecosystem            text NOT NULL CHECK (ecosystem IN ('npm', 'pypi', 'container', 'executable')),
    name                 text NOT NULL CHECK (length(name) BETWEEN 1 AND 4096),
    version              text CHECK (version IS NULL OR length(version) BETWEEN 1 AND 4096),
    pinned               boolean NOT NULL,
    registry             text NOT NULL CHECK (length(registry) BETWEEN 1 AND 1024),
    recorded_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (instance_id, server_id, exec_contract_sha256, ecosystem, name),
    FOREIGN KEY (instance_id, server_id) REFERENCES mint.servers (instance_id, server_id)
);

CREATE TRIGGER server_packages_1_append_only BEFORE UPDATE OR DELETE ON mint.server_packages
    FOR EACH ROW EXECUTE FUNCTION mint.reject_mutation();
CREATE TRIGGER server_packages_2_truncate BEFORE TRUNCATE ON mint.server_packages
    FOR EACH STATEMENT EXECUTE FUNCTION mint.reject_mutation();

-- 취약점 조회 결과. (패키지 버전, 취약점)마다 한 행이며, 처음 확인한 시각(first_seen_at)은 고치지
-- 못한다(치명 취약점의 48시간 기한은 이 시각부터 센다). 조회에서 사라지면 cleared_at을 찍는다.
-- severity는 critical·high·medium·low·unknown이며 cvss는 계산하거나 받은 점수이다.
CREATE TABLE mint.package_vulns (
    id            uuid PRIMARY KEY,
    instance_id   mint.ident NOT NULL,
    ecosystem     text NOT NULL CHECK (ecosystem IN ('npm', 'pypi')),
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 4096),
    version       text NOT NULL CHECK (length(version) BETWEEN 1 AND 4096),
    vuln_id       text NOT NULL CHECK (length(vuln_id) BETWEEN 1 AND 256),
    severity      text NOT NULL
                  CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    cvss          numeric(3, 1) CHECK (cvss IS NULL OR cvss BETWEEN 0 AND 10),
    exploited     boolean NOT NULL DEFAULT false,
    summary       text CHECK (summary IS NULL OR length(summary) <= 1000),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    cleared_at    timestamptz,
    UNIQUE (instance_id, ecosystem, name, version, vuln_id)
);

CREATE TRIGGER package_vulns_2_frozen BEFORE UPDATE ON mint.package_vulns
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'id', 'instance_id', 'ecosystem', 'name', 'version', 'vuln_id', 'first_seen_at');
CREATE TRIGGER package_vulns_3_no_delete BEFORE DELETE ON mint.package_vulns
    FOR EACH ROW EXECUTE FUNCTION mint.reject_mutation();

-- 치명 취약점의 조치 기한이 지나 호출을 막는 서버의 표지(막기 시작한 시각). 판정은 서버 행을 읽는다.
ALTER TABLE mint.servers ADD COLUMN vuln_blocked_at timestamptz;

REVOKE ALL ON mint.server_packages, mint.package_vulns FROM PUBLIC;
GRANT SELECT, INSERT ON mint.server_packages TO mint_control;
GRANT SELECT, INSERT, UPDATE ON mint.package_vulns TO mint_control;

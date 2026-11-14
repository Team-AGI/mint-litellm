-- 패키지 의존 그래프 조회 결과. 고정된 패키지 버전(ecosystem, name, version)마다 의존하는 패키지
-- (dep_name, dep_version)와 거기까지의 경로(path, "A → B → C")를 적는다. 패키지 자신을 가리키는 행
-- (dep가 자기 자신)은 조회했다는 표지이자 조회 시각이며, 같은 조회에서 적은 행은 resolved_at이 같다.
-- 다시 조회하면 행을 덮어쓰고 resolved_at을 새로 찍으므로 resolved_at이 자신의 행과 다른 행은 옛 그래프이다.
CREATE TABLE mint.package_deps (
    instance_id mint.ident NOT NULL,
    ecosystem   text NOT NULL CHECK (ecosystem IN ('npm', 'pypi')),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 4096),
    version     text NOT NULL CHECK (length(version) BETWEEN 1 AND 4096),
    dep_name    text NOT NULL CHECK (length(dep_name) BETWEEN 1 AND 4096),
    dep_version text NOT NULL CHECK (length(dep_version) BETWEEN 1 AND 4096),
    path        text NOT NULL CHECK (length(path) BETWEEN 1 AND 8192),
    resolved_at timestamptz NOT NULL,
    PRIMARY KEY (instance_id, ecosystem, name, version, dep_name, dep_version)
);

REVOKE ALL ON mint.package_deps FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.package_deps TO mint_control;

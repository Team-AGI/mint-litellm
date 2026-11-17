-- 검사용 승인: 단말에서만 시작되는 로컬 서버의 도구 목록을 단말이 대신 받아 올리게 하는 별도 권한.
-- 승인이 아니다. 서버 상태·승인·배포 대상·호출 허가에 들어가지 않고, 키 하나·묶음 하나·1회로 묶인다.
-- 신청 명세의 환경 변수 값(env)도 이 판에서 받는다.

CREATE TABLE mint.endpoint_inspections (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id     mint.ident NOT NULL,
    intake_id       uuid NOT NULL REFERENCES mint.intakes (id),
    server_id       text NOT NULL,
    key_token       text NOT NULL CHECK (length(key_token) BETWEEN 1 AND 128),
    pack_sha256     text NOT NULL CHECK (pack_sha256 ~ '^[0-9a-f]{64}$'),
    contract_sha256 text NOT NULL CHECK (contract_sha256 ~ '^[0-9a-f]{64}$'),
    status          text NOT NULL DEFAULT 'issued' CHECK (status IN (
        'issued', 'consumed', 'submitted', 'verified', 'expired', 'revoked', 'invalid')),
    issued_by       text NOT NULL,
    issued_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    submitted_at    timestamptz,
    verified_at     timestamptz,
    revoked_at      timestamptz,
    revoked_by      text,
    result          jsonb CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),
    result_sha256   text CHECK (result_sha256 ~ '^[0-9a-f]{64}$'),
    outcome         text CHECK (length(outcome) <= 64),
    CHECK ((result IS NULL) = (result_sha256 IS NULL)),
    CHECK (status NOT IN ('submitted', 'verified') OR result IS NOT NULL),
    CHECK (expires_at > issued_at)
);
-- 신청마다 열린(발급·소비) 권한은 하나뿐이다.
CREATE UNIQUE INDEX endpoint_inspections_one_open ON mint.endpoint_inspections (intake_id)
    WHERE status IN ('issued', 'consumed');
CREATE INDEX endpoint_inspections_by_key ON mint.endpoint_inspections (instance_id, key_token)
    WHERE status IN ('issued', 'consumed');
CREATE TRIGGER endpoint_inspections_2_frozen BEFORE UPDATE ON mint.endpoint_inspections
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'intake_id', 'server_id', 'key_token', 'pack_sha256', 'contract_sha256',
        'issued_by', 'issued_at', 'expires_at');
GRANT SELECT, INSERT ON mint.endpoint_inspections TO mint_control;
GRANT UPDATE (status, revoked_at, revoked_by, verified_at, outcome)
    ON mint.endpoint_inspections TO mint_control;
GRANT SELECT ON mint.endpoint_inspections TO mint_endpoint_owner;
GRANT UPDATE (status, consumed_at, submitted_at, result, result_sha256)
    ON mint.endpoint_inspections TO mint_endpoint_owner;

-- 신청 명세의 환경 변수: 빈 환경에서 허용한 변수만. 로더·인터프리터를 바꾸는 변수와 비밀 이름은
-- 받지 않고, 경로 같은 값은 같은 신청의 읽기 전용 파일 접근 선언 안이어야 한다.
CREATE FUNCTION mint.endpoint_env_valid(p_env jsonb, p_access jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE k text; v jsonb; s text; a jsonb; inside boolean; base text;
BEGIN
    IF jsonb_typeof(p_env) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(p_env)) > 32 THEN RETURN false; END IF;
    FOR k, v IN SELECT * FROM jsonb_each(p_env) LOOP
        IF k !~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'
           OR k ~* '(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)'
           OR upper(k) ~ '^(LD_|DYLD_|PYTHON|NODE_|PERL|RUBY|JAVA_TOOL|_JAVA|PIP_|UV_)'
           OR upper(k) IN ('PATH', 'PATHEXT', 'IFS', 'ENV', 'BASH_ENV', 'CLASSPATH', 'HOME',
                           'USERPROFILE', 'APPDATA', 'SHELL', 'GCONV_PATH', 'LOCPATH', 'NLSPATH',
                           'HOSTALIASES', 'TMPDIR', 'TEMP', 'TMP')
        THEN RETURN false; END IF;
        IF jsonb_typeof(v) <> 'string' THEN RETURN false; END IF;
        s := v #>> '{}';
        IF length(s) > 1024 OR s ~ '[[:cntrl:]]' THEN RETURN false; END IF;
        IF s ~ '(^|[/\\])\.\.([/\\]|$)' THEN RETURN false; END IF;
        IF s ~ '^(/|~|\.(/|\\|$)|[A-Za-z]:[/\\])' THEN
            inside := false;
            FOR a IN SELECT * FROM jsonb_array_elements(coalesce(p_access, '[]'::jsonb)) LOOP
                IF coalesce(a->>'mode', 'ro') = 'ro' THEN
                    base := rtrim(a->>'path', '/\');
                    IF s = a->>'path' OR starts_with(s, base || '/') OR starts_with(s, base || '\')
                    THEN inside := true; END IF;
                END IF;
            END LOOP;
            IF NOT inside THEN RETURN false; END IF;
        END IF;
    END LOOP;
    RETURN true;
END $$;

DROP FUNCTION mint.endpoint_submit_intake(text, uuid, jsonb);
DROP FUNCTION mint.endpoint_payload_valid(jsonb);

CREATE FUNCTION mint.endpoint_payload_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE spec jsonb; e jsonb; net text;
BEGIN
    IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR octet_length(p::text) > 262144 THEN RETURN false; END IF;
    IF coalesce(p->>'server_id', '') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' THEN RETURN false; END IF;
    IF jsonb_typeof(p->'purpose') IS DISTINCT FROM 'string'
       OR length(btrim(p->>'purpose')) NOT BETWEEN 1 AND 256 THEN RETURN false; END IF;
    IF coalesce(p->>'data_grade', '') NOT IN ('public', 'internal', 'confidential', 'restricted')
    THEN RETURN false; END IF;
    IF p ? 'resources' AND (jsonb_typeof(p->'resources') IS DISTINCT FROM 'array'
       OR length(p->>'resources') > 4000) THEN RETURN false; END IF;
    spec := p->'spec';
    IF jsonb_typeof(spec) IS DISTINCT FROM 'object'
       OR spec->>'index' IS DISTINCT FROM 'pypi'
       OR coalesce(spec->>'name', '') !~ '^[A-Za-z0-9]([A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$'
       OR coalesce(spec->>'version', '') !~ '^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}$'
       OR coalesce(spec->>'command', '') !~ '^[A-Za-z0-9_][A-Za-z0-9._:-]{0,127}$'
    THEN RETURN false; END IF;
    IF spec ? 'extras' THEN
        IF jsonb_typeof(spec->'extras') IS DISTINCT FROM 'array' OR jsonb_array_length(spec->'extras') > 16
        THEN RETURN false; END IF;
        FOR e IN SELECT * FROM jsonb_array_elements(spec->'extras') LOOP
            IF jsonb_typeof(e) <> 'string' OR (e #>> '{}') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
            THEN RETURN false; END IF;
        END LOOP;
    END IF;
    IF spec ? 'argv' THEN
        IF jsonb_typeof(spec->'argv') IS DISTINCT FROM 'array' OR jsonb_array_length(spec->'argv') > 64
        THEN RETURN false; END IF;
        FOR e IN SELECT * FROM jsonb_array_elements(spec->'argv') LOOP
            IF jsonb_typeof(e) <> 'string' OR length(e #>> '{}') > 4096
            THEN RETURN false; END IF;
        END LOOP;
    END IF;
    IF p ? 'file_access' THEN
        IF jsonb_typeof(p->'file_access') IS DISTINCT FROM 'array' OR jsonb_array_length(p->'file_access') > 64
        THEN RETURN false; END IF;
        FOR e IN SELECT * FROM jsonb_array_elements(p->'file_access') LOOP
            IF jsonb_typeof(e) <> 'object' OR jsonb_typeof(e->'path') IS DISTINCT FROM 'string'
               OR length(e->>'path') NOT BETWEEN 1 AND 1024
               OR coalesce(e->>'mode', 'ro') NOT IN ('ro', 'rw') THEN RETURN false; END IF;
        END LOOP;
    END IF;
    net := p->>'network';
    IF net IS NULL OR net NOT IN ('none', 'hosts') THEN RETURN false; END IF;
    IF p ? 'allowed_hosts' AND (jsonb_typeof(p->'allowed_hosts') IS DISTINCT FROM 'array'
       OR jsonb_array_length(p->'allowed_hosts') > 64) THEN RETURN false; END IF;
    IF (net = 'hosts') <> (coalesce(jsonb_array_length(p->'allowed_hosts'), 0) > 0) THEN RETURN false; END IF;
    FOR e IN SELECT * FROM jsonb_array_elements(coalesce(p->'allowed_hosts', '[]')) LOOP
        IF jsonb_typeof(e) <> 'string' OR length(e #>> '{}') NOT BETWEEN 1 AND 255
        THEN RETURN false; END IF;
    END LOOP;
    IF p ? 'env_names' THEN
        IF jsonb_typeof(p->'env_names') IS DISTINCT FROM 'array' OR jsonb_array_length(p->'env_names') > 64
        THEN RETURN false; END IF;
        FOR e IN SELECT * FROM jsonb_array_elements(p->'env_names') LOOP
            IF jsonb_typeof(e) <> 'string' OR (e #>> '{}') !~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'
            THEN RETURN false; END IF;
        END LOOP;
    END IF;
    IF p ? 'observed_tools' AND (jsonb_typeof(p->'observed_tools') IS DISTINCT FROM 'array'
       OR jsonb_array_length(p->'observed_tools') > 200) THEN RETURN false; END IF;
    IF p ? 'env' AND NOT mint.endpoint_env_valid(p->'env', p->'file_access') THEN RETURN false; END IF;
    RETURN true;
END $$;

-- 키로 신원을 정하는 신청 생성. 본문에 신원 값이 있어도 쓰지 않는다.
-- 오류: MINT-KEY(키 없음·폐기·만료) MINT-INVALID(형식) MINT-CONFLICT(식별자 재사용·진행 중·승인됨)
--       MINT-QUOTA(한도, SQLSTATE MT429).
CREATE FUNCTION mint.endpoint_submit_intake(p_key_token text, p_request_id uuid, p_payload jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    k mint.endpoint_installs;
    matches integer;
    iid text; uid text; org text;
    sid text := p_payload->>'server_id';
    pack jsonb;
    previous mint.intakes;
    server mint.servers;
    request_hash text;
    today date := (clock_timestamp() AT TIME ZONE 'UTC')::date;
    user_today integer; org_today integer; running integer;
BEGIN
    IF p_key_token IS NULL OR p_request_id IS NULL OR NOT mint.endpoint_payload_valid(p_payload)
    THEN RAISE EXCEPTION 'MINT-INVALID: invalid intake input' USING ERRCODE = 'check_violation'; END IF;
    request_hash := encode(sha256(convert_to(p_payload::text, 'UTF8')), 'hex');

    SELECT count(*) INTO matches FROM mint.endpoint_installs WHERE key_token = p_key_token;
    IF matches <> 1 THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 잠가 읽어 폐기와 겹치지 않게 하고, 폐기·만료를 이 트랜잭션에서 다시 확인한다.
    SELECT * INTO k FROM mint.endpoint_installs WHERE key_token = p_key_token FOR SHARE;
    IF NOT FOUND OR k.revoked_at IS NOT NULL
       OR (k.expires_at IS NOT NULL AND k.expires_at <= clock_timestamp()) THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    iid := k.instance_id; uid := k.user_id;

    -- 같은 제출의 재전송만 재사용하며 다른 사용자의 신청을 알려 주지 않는다.
    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-intake:' || p_request_id, 0));
    SELECT * INTO previous FROM mint.intakes WHERE id = p_request_id;
    IF FOUND THEN
        IF previous.instance_id = iid AND previous.requested_by = uid AND previous.source = 'endpoint'
           AND previous.staff_request_sha256 = request_hash THEN RETURN previous.id; END IF;
        RAISE EXCEPTION 'MINT-CONFLICT: request identifier reused' USING ERRCODE = 'unique_violation';
    END IF;

    org := mint.endpoint_org(iid, k.team_id, uid);
    IF org IS NULL THEN
        RAISE EXCEPTION 'MINT-KEY: no active organization' USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM 1 FROM mint.orgs WHERE instance_id = iid AND org_id = org AND status = 'active' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MINT-KEY: no active organization' USING ERRCODE = 'insufficient_privilege';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-server:' || sid, 0));
    SELECT * INTO server FROM mint.servers WHERE instance_id = iid AND server_id = sid FOR SHARE;
    IF FOUND THEN
        IF server.identity_kind <> 'stdio'
           OR server.status NOT IN ('pending', 'awaiting_approval', 'rejected') THEN
            RAISE EXCEPTION 'MINT-CONFLICT: server already registered' USING ERRCODE = 'unique_violation';
        END IF;
        IF EXISTS (SELECT 1 FROM mint.intakes WHERE instance_id = iid AND server_id = sid
                   AND status <> 'decided') THEN
            RAISE EXCEPTION 'MINT-CONFLICT: server request in progress' USING ERRCODE = 'unique_violation';
        END IF;
    END IF;

    -- 한도: 조직·사용자 순으로 잠가 집계와 증가를 한 번에 한다.
    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-quota-org:' || org, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-quota-user:' || uid, 0));
    SELECT coalesce(sum(q.count) FILTER (WHERE q.user_id = uid), 0),
           coalesce(sum(q.count) FILTER (WHERE q.org_id = org), 0)
      INTO user_today, org_today FROM mint.endpoint_intake_quota q
      WHERE q.instance_id = iid AND q.day = today AND (q.user_id = uid OR q.org_id = org);
    SELECT count(*) INTO running FROM mint.intakes WHERE instance_id = iid AND requested_by = uid
      AND source = 'endpoint' AND status IN ('received', 'checking');
    IF user_today >= 20 OR org_today >= 100 OR running >= 3 THEN
        RAISE EXCEPTION 'MINT-QUOTA: intake limit reached' USING ERRCODE = 'MT429';
    END IF;
    INSERT INTO mint.endpoint_intake_quota(instance_id, org_id, user_id, day, count)
        VALUES (iid, org, uid, today, 1)
        ON CONFLICT (instance_id, org_id, user_id, day)
        DO UPDATE SET count = mint.endpoint_intake_quota.count + 1;

    IF server.id IS NULL THEN
        INSERT INTO mint.servers(id, instance_id, server_id, status, transport, auth_type,
          identity_kind, registered_by)
          VALUES (gen_random_uuid(), iid, sid, 'pending', 'stdio', 'none', 'stdio', uid);
    END IF;
    -- 신청 명세는 평평한 한 객체이다: 패키지 명세(index·name·version·extras·command·argv)와
    -- 선언 권한(file_access·network·allowed_hosts·env_names), 단말이 본 참고 도구 목록.
    pack := (p_payload->'spec') || jsonb_build_object(
        'file_access', coalesce(p_payload->'file_access', '[]'::jsonb),
        'network', p_payload->>'network',
        'allowed_hosts', coalesce(p_payload->'allowed_hosts', '[]'::jsonb),
        'env_names', coalesce(p_payload->'env_names', '[]'::jsonb),
        'env', coalesce(p_payload->'env', '{}'::jsonb),
        'observed_tools', coalesce(p_payload->'observed_tools', '[]'::jsonb));
    INSERT INTO mint.intakes(id, instance_id, org_id, server_id, source, purpose, data_grade,
      allowed_resources, provider, owner_user_id, readiness, data_return_terms, requested_by,
      staff_request_sha256, endpoint_key_token)
      VALUES (p_request_id, iid, org, sid, 'endpoint', btrim(p_payload->>'purpose'),
      p_payload->>'data_grade', coalesce(p_payload->'resources', '[]'::jsonb), 'pypi', uid,
      jsonb_build_object('credential_notice', '자격 증명이 바뀌면 관리자에게 알립니다',
        'revocation_record', '철회는 MINT 기록으로 남깁니다', 'audit_access_days', 90),
      '사용을 끝내면 단말에서 서버를 제거합니다', uid, request_hash, p_key_token);
    INSERT INTO mint.deployment_contracts(id, instance_id, server_id, canonical_text, sha256,
      url, url_sha256, transport, auth_type, proposed_by, identity_kind, pack_spec)
      VALUES (p_request_id, iid, sid, pack::text, encode(sha256(convert_to(pack::text, 'UTF8')), 'hex'),
      NULL, NULL, 'stdio', 'none', uid, 'stdio', pack);
    INSERT INTO mint.jobs(id, instance_id, kind, target_ref, idempotency_key)
      VALUES (gen_random_uuid(), iid, 'intake_run', p_request_id::text || '/endpoint',
      'intake_run:' || p_request_id || ':1');
    INSERT INTO mint.events(event_id, instance_id, kind, source_key, actor, payload)
      SELECT s.e, iid, 'intake_received', s.k, uid,
             jsonb_build_object('intake_id', p_request_id, 'server_id', sid, 'source', 'endpoint',
                                'requested_by', uid)
      FROM (SELECT gen_random_uuid() AS e,
                   'intake:' || p_request_id || ':1:intake_received' AS k) s
      WHERE mint.claim_event_key(iid, s.k, s.e);
    RETURN p_request_id;
END $$;

-- ---------------------------------------------------------------------------
-- 검사 권한 함수. 오류 체계는 신청 함수와 같다:
--   MINT-KEY(키 없음·폐기·만료, 42501) MINT-INVALID(형식, 23514)
--   MINT-CONFLICT(소비·만료·철회·다른 본문, 23505) MINT-NOTFOUND(없음·다른 키, P0002)
-- ---------------------------------------------------------------------------

-- 권한이 가리키는 묶음·계약이 지금 후보와 같은가(재빌드·계약 변경이면 거짓).
CREATE FUNCTION mint.endpoint_inspection_bound(p_instance text, p_intake uuid, p_pack text,
                                               p_contract text)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, mint, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM mint.intakes t
        JOIN LATERAL (SELECT d.pack_sha256, d.exec_contract FROM mint.deployment_contracts d
                      WHERE d.instance_id = t.instance_id AND d.server_id = t.server_id
                        AND d.status = 'candidate' ORDER BY d.id DESC LIMIT 1) c ON true
        WHERE t.instance_id = p_instance AND t.id = p_intake AND t.status <> 'decided'
          AND c.pack_sha256 = p_pack AND c.exec_contract IS NOT NULL
          AND encode(sha256(convert_to(c.exec_contract::text, 'UTF8')), 'hex') = p_contract);
$$;

-- 키에 유효한(발급·소비, 기간 안) 검사 권한. 키가 유효하지 않으면 비어 있다.
CREATE FUNCTION mint.endpoint_inspections_list(p_instance text, p_key_token text)
RETURNS TABLE(id uuid, intake_id uuid, server_id text, pack_sha256 text, contract jsonb,
              expires_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
#variable_conflict use_column
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mint.endpoint_installs i
                   WHERE i.instance_id = p_instance AND i.key_token = p_key_token
                     AND i.revoked_at IS NULL
                     AND (i.expires_at IS NULL OR i.expires_at > clock_timestamp()))
    THEN RETURN; END IF;
    RETURN QUERY
    SELECT e.id, e.intake_id, e.server_id, e.pack_sha256, c.exec_contract, e.expires_at
    FROM mint.endpoint_inspections e
    JOIN LATERAL (SELECT d.exec_contract FROM mint.deployment_contracts d
                  WHERE d.instance_id = e.instance_id AND d.server_id = e.server_id
                    AND d.status = 'candidate' ORDER BY d.id DESC LIMIT 1) c ON true
    WHERE e.instance_id = p_instance AND e.key_token = p_key_token
      AND e.status IN ('issued', 'consumed') AND e.expires_at > clock_timestamp()
      AND mint.endpoint_inspection_bound(e.instance_id, e.intake_id, e.pack_sha256,
                                         e.contract_sha256)
    ORDER BY e.issued_at;
END $$;

-- 같은 키만, 원자적 1회. 이미 소비·만료·철회·무효이면 충돌이다.
CREATE FUNCTION mint.endpoint_inspection_start(p_instance text, p_key_token text, p_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE r mint.endpoint_inspections;
BEGIN
    PERFORM 1 FROM mint.endpoint_installs i
      WHERE i.instance_id = p_instance AND i.key_token = p_key_token AND i.revoked_at IS NULL
        AND (i.expires_at IS NULL OR i.expires_at > clock_timestamp()) FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT * INTO r FROM mint.endpoint_inspections e
      WHERE e.id = p_id AND e.instance_id = p_instance AND e.key_token = p_key_token FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MINT-NOTFOUND: no such inspection' USING ERRCODE = 'no_data_found';
    END IF;
    IF r.status <> 'issued' OR r.expires_at <= clock_timestamp()
       OR NOT mint.endpoint_inspection_bound(r.instance_id, r.intake_id, r.pack_sha256,
                                             r.contract_sha256) THEN
        RAISE EXCEPTION 'MINT-CONFLICT: inspection cannot be started' USING ERRCODE = 'unique_violation';
    END IF;
    UPDATE mint.endpoint_inspections SET status = 'consumed', consumed_at = clock_timestamp()
      WHERE id = r.id;
    RETURN true;
END $$;

-- 결과 제출: 소비된 것만. 같은 본문 해시의 재전송은 같은 응답, 다른 본문은 충돌이다.
-- 처리(후보 저장·검사)는 작업이 한다.
CREATE FUNCTION mint.endpoint_inspection_submit(p_instance text, p_key_token text, p_id uuid,
                                                p_body jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE r mint.endpoint_inspections; body_hash text; t jsonb;
BEGIN
    IF p_id IS NULL OR jsonb_typeof(p_body) IS DISTINCT FROM 'object'
       OR octet_length(p_body::text) > 1048576
       OR coalesce(p_body->>'pack_sha256', '') !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(p_body->'complete') IS DISTINCT FROM 'boolean'
       OR jsonb_typeof(p_body->'tools') IS DISTINCT FROM 'array'
       OR jsonb_array_length(p_body->'tools') > 200
       OR (p_body ? 'detail' AND jsonb_typeof(p_body->'detail') IS DISTINCT FROM 'object')
    THEN RAISE EXCEPTION 'MINT-INVALID: invalid inspection result' USING ERRCODE = 'check_violation'; END IF;
    FOR t IN SELECT * FROM jsonb_array_elements(p_body->'tools') LOOP
        IF jsonb_typeof(t) <> 'object' THEN
            RAISE EXCEPTION 'MINT-INVALID: invalid inspection result' USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    body_hash := encode(sha256(convert_to(p_body::text, 'UTF8')), 'hex');

    PERFORM 1 FROM mint.endpoint_installs i
      WHERE i.instance_id = p_instance AND i.key_token = p_key_token AND i.revoked_at IS NULL
        AND (i.expires_at IS NULL OR i.expires_at > clock_timestamp()) FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT * INTO r FROM mint.endpoint_inspections e
      WHERE e.id = p_id AND e.instance_id = p_instance AND e.key_token = p_key_token FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MINT-NOTFOUND: no such inspection' USING ERRCODE = 'no_data_found';
    END IF;
    IF r.status IN ('submitted', 'verified') THEN
        IF r.result_sha256 = body_hash THEN RETURN true; END IF;
        RAISE EXCEPTION 'MINT-CONFLICT: a different result was already submitted'
            USING ERRCODE = 'unique_violation';
    END IF;
    IF r.status <> 'consumed' OR r.expires_at <= clock_timestamp()
       OR p_body->>'pack_sha256' <> r.pack_sha256
       OR NOT mint.endpoint_inspection_bound(r.instance_id, r.intake_id, r.pack_sha256,
                                             r.contract_sha256) THEN
        RAISE EXCEPTION 'MINT-CONFLICT: inspection result cannot be accepted'
            USING ERRCODE = 'unique_violation';
    END IF;
    UPDATE mint.endpoint_inspections SET status = 'submitted', submitted_at = clock_timestamp(),
        result = p_body, result_sha256 = body_hash WHERE id = r.id;
    INSERT INTO mint.jobs(id, instance_id, kind, target_ref, idempotency_key)
      VALUES (gen_random_uuid(), p_instance, 'endpoint_inspection', r.id::text,
              'endpoint_inspection:' || r.id);
    RETURN true;
END $$;

-- 묶음 내려받기 허용: 이 키·이 묶음의 유효한 검사 권한이 있으면 후보 묶음의 목록을 돌려준다.
CREATE FUNCTION mint.endpoint_inspection_pack(p_instance text, p_key_token text, p_server text,
                                              p_pack text)
RETURNS TABLE(server_id text, pack_sha256 text, pack_manifest jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
#variable_conflict use_column
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mint.endpoint_installs i
                   WHERE i.instance_id = p_instance AND i.key_token = p_key_token
                     AND i.revoked_at IS NULL
                     AND (i.expires_at IS NULL OR i.expires_at > clock_timestamp()))
    THEN RETURN; END IF;
    RETURN QUERY
    SELECT e.server_id, e.pack_sha256, c.pack_manifest
    FROM mint.endpoint_inspections e
    JOIN LATERAL (SELECT d.pack_manifest FROM mint.deployment_contracts d
                  WHERE d.instance_id = e.instance_id AND d.server_id = e.server_id
                    AND d.status = 'candidate' ORDER BY d.id DESC LIMIT 1) c ON true
    WHERE e.instance_id = p_instance AND e.key_token = p_key_token AND e.server_id = p_server
      AND e.pack_sha256 = p_pack AND e.status IN ('issued', 'consumed')
      AND e.expires_at > clock_timestamp()
      AND mint.endpoint_inspection_bound(e.instance_id, e.intake_id, e.pack_sha256,
                                         e.contract_sha256)
    LIMIT 1;
END $$;

-- 소유 역할과 권한
GRANT CREATE ON SCHEMA mint TO mint_endpoint_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('GRANT mint_endpoint_owner TO %I WITH SET TRUE',current_user);
    END IF;
END $$;
ALTER FUNCTION mint.endpoint_env_valid(jsonb,jsonb) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_payload_valid(jsonb) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_submit_intake(text,uuid,jsonb) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_inspection_bound(text,uuid,text,text) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_inspections_list(text,text) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_inspection_start(text,text,uuid) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_inspection_submit(text,text,uuid,jsonb) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_inspection_pack(text,text,text,text) OWNER TO mint_endpoint_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_endpoint_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('REVOKE SET OPTION FOR mint_endpoint_owner FROM %I',current_user);
    END IF;
END $$;
REVOKE ALL ON FUNCTION mint.endpoint_env_valid(jsonb,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_payload_valid(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_submit_intake(text,uuid,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_inspection_bound(text,uuid,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_inspections_list(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_inspection_start(text,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_inspection_submit(text,text,uuid,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_inspection_pack(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_env_valid(jsonb,jsonb), mint.endpoint_payload_valid(jsonb),
    mint.endpoint_inspection_bound(text,uuid,text,text) TO mint_endpoint_owner;
GRANT EXECUTE ON FUNCTION mint.endpoint_submit_intake(text,uuid,jsonb),
    mint.endpoint_inspections_list(text,text), mint.endpoint_inspection_start(text,text,uuid),
    mint.endpoint_inspection_submit(text,text,uuid,jsonb),
    mint.endpoint_inspection_pack(text,text,text,text) TO mint_plugin;

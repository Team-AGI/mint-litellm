-- 네트워크를 지정하지 않은 단말 신청도 받는다(지정하지 않으면 자동). 이전 신청의 네트워크 값은
-- 직원이 정한 것인지 알 수 없어 따로 표시한다(새 신청은 지정한 값만 값으로 본다).
ALTER TABLE mint.intakes ADD COLUMN network_legacy boolean NOT NULL DEFAULT true;
ALTER TABLE mint.intakes ALTER COLUMN network_legacy SET DEFAULT false;

CREATE OR REPLACE FUNCTION mint.endpoint_payload_valid(p jsonb) RETURNS boolean
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
    IF net IS NOT NULL AND net NOT IN ('none', 'hosts') THEN RETURN false; END IF;
    IF p ? 'allowed_hosts' AND (jsonb_typeof(p->'allowed_hosts') IS DISTINCT FROM 'array'
       OR jsonb_array_length(p->'allowed_hosts') > 64) THEN RETURN false; END IF;
    IF (net IS NOT DISTINCT FROM 'hosts') <> (coalesce(jsonb_array_length(p->'allowed_hosts'), 0) > 0) THEN RETURN false; END IF;
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

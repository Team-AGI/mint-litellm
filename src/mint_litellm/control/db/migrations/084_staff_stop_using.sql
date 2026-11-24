-- 직원 본인의 「사용 그만두기」: 본인 사용자 범위의 거부만 만들고 풀 수 있다.
-- 서버 승인과 다른 사람의 사용에는 손대지 않는다. 관리자가 만든 거부는 풀 수 없다.
GRANT SELECT ON mint.denials TO mint_staff_owner;
GRANT INSERT (id, instance_id, org_id, scope_type, scope_id, server_id, reason, created_by)
    ON mint.denials TO mint_staff_owner;
GRANT UPDATE (lifted_at, lifted_by) ON mint.denials TO mint_staff_owner;

CREATE FUNCTION mint.staff_stop_using(p_org_id text, p_server_id text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    uid text := mint.staff_user();
    iid text := mint.staff_instance();
    d mint.denials;
    new_id uuid := gen_random_uuid();
BEGIN
    PERFORM mint.staff_check_target(p_org_id, p_server_id);
    SELECT * INTO d FROM mint.denials WHERE instance_id = iid AND scope_type = 'user'
      AND scope_id = uid AND server_id = p_server_id AND org_id = p_org_id AND tools IS NULL
      AND created_by = uid AND lifted_at IS NULL LIMIT 1;
    IF FOUND THEN
        RETURN d.id;
    END IF;
    INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id, server_id, reason,
                              created_by)
    VALUES (new_id, iid, p_org_id, 'user', uid, p_server_id, '본인이 사용을 그만둠', uid);
    PERFORM mint.staff_event('denial_created', 'denial', new_id::text, 1, uid,
        jsonb_build_object('denial_id', new_id, 'scope_type', 'user', 'scope_id', uid,
                           'server_id', p_server_id, 'tools', NULL::text, 'org_id', p_org_id,
                           'reason', '본인이 사용을 그만둠'));
    RETURN new_id;
END $$;

CREATE FUNCTION mint.staff_resume_using(p_org_id text, p_server_id text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    uid text := mint.staff_user();
    iid text := mint.staff_instance();
    d mint.denials;
    n integer := 0;
BEGIN
    PERFORM mint.staff_check_target(p_org_id, p_server_id);
    FOR d IN SELECT * FROM mint.denials WHERE instance_id = iid AND scope_type = 'user'
             AND scope_id = uid AND server_id = p_server_id AND org_id = p_org_id
             AND tools IS NULL AND created_by = uid AND lifted_at IS NULL FOR UPDATE LOOP
        UPDATE mint.denials SET lifted_at = clock_timestamp(), lifted_by = uid
        WHERE id = d.id RETURNING * INTO d;
        PERFORM mint.staff_event('denial_lifted', 'denial', d.id::text, d.state_version, uid,
            jsonb_build_object('denial_id', d.id, 'scope_type', 'user', 'scope_id', uid));
        n := n + 1;
    END LOOP;
    RETURN n;
END $$;

GRANT CREATE ON SCHEMA mint TO mint_staff_owner;
DO $$ BEGIN IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
    EXECUTE format('GRANT mint_staff_owner TO %I WITH SET TRUE',current_user); END IF; END $$;
ALTER FUNCTION mint.staff_stop_using(text, text) OWNER TO mint_staff_owner;
ALTER FUNCTION mint.staff_resume_using(text, text) OWNER TO mint_staff_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_staff_owner;
DO $$ BEGIN IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
    EXECUTE format('REVOKE SET OPTION FOR mint_staff_owner FROM %I',current_user); END IF; END $$;
REVOKE ALL ON FUNCTION mint.staff_stop_using(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.staff_resume_using(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.staff_stop_using(text, text) TO mint_staff;
GRANT EXECUTE ON FUNCTION mint.staff_resume_using(text, text) TO mint_staff;

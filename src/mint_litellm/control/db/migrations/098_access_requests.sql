-- 직원이 막힌 도구·서버의 권한을 요청하고 승인자가 기존 조치(차단 해제·승인·호출 허용)로 처리한다.
CREATE TABLE mint.access_requests (
    id uuid PRIMARY KEY,
    instance_id text NOT NULL,
    requested_by text NOT NULL,
    server_id text NOT NULL,
    tool text CHECK (tool IS NULL OR length(tool) BETWEEN 1 AND 256),
    reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z_]{2,63}$'),
    note text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'resolved', 'rejected', 'cancelled')),
    resolution text CHECK (resolution IN ('lift', 'grant', 'temp')),
    resolution_ref text,
    decided_by text,
    decision_note text CHECK (decision_note IS NULL OR length(decision_note) <= 500),
    created_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz,
    state_version bigint NOT NULL DEFAULT 1,
    CHECK ((status = 'open') = (decided_at IS NULL)),
    CHECK ((status = 'resolved') = (resolution IS NOT NULL))
);
CREATE UNIQUE INDEX access_requests_one_open ON mint.access_requests
    (instance_id, requested_by, server_id, coalesce(tool, '')) WHERE status = 'open';
CREATE INDEX access_requests_open_by_age ON mint.access_requests (instance_id, created_at)
    WHERE status = 'open';
CREATE TRIGGER access_requests_1_status BEFORE INSERT OR UPDATE ON mint.access_requests
    FOR EACH ROW EXECUTE FUNCTION mint.check_status('open',
      'open>resolved,open>rejected,open>cancelled');
CREATE TRIGGER access_requests_2_frozen BEFORE UPDATE ON mint.access_requests
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'id', 'instance_id', 'requested_by', 'server_id', 'tool', 'reason_code', 'note',
        'created_at');
CREATE TRIGGER access_requests_9_version BEFORE UPDATE ON mint.access_requests
    FOR EACH ROW EXECUTE FUNCTION mint.bump_version();
GRANT SELECT, INSERT, UPDATE ON mint.access_requests TO mint_control;
GRANT SELECT ON mint.access_requests TO mint_staff_owner;
GRANT INSERT (id, instance_id, requested_by, server_id, tool, reason_code, note)
    ON mint.access_requests TO mint_staff_owner;
GRANT UPDATE (status, decided_at) ON mint.access_requests TO mint_staff_owner;

-- 직원 쪽: 열기(같은 대상의 대기 요청이 있으면 그것을 돌려준다)와 본인 요청 취소.
CREATE FUNCTION mint.staff_open_access_request(
    p_id uuid, p_server text, p_tool text, p_reason text, p_note text
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    iid text := mint.staff_instance();
    uid text := mint.staff_user();
    existing uuid;
BEGIN
    IF uid IS NULL OR iid IS NULL THEN
        RAISE EXCEPTION 'staff session required' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM mint.servers WHERE instance_id = iid AND server_id = p_server) THEN
        RAISE EXCEPTION 'no such server' USING ERRCODE = 'no_data_found';
    END IF;
    SELECT id INTO existing FROM mint.access_requests
     WHERE instance_id = iid AND requested_by = uid AND server_id = p_server
       AND coalesce(tool, '') = coalesce(nullif(btrim(p_tool), ''), '') AND status = 'open';
    IF FOUND THEN
        RETURN existing;
    END IF;
    INSERT INTO mint.access_requests (id, instance_id, requested_by, server_id, tool, reason_code, note)
    VALUES (p_id, iid, uid, p_server, nullif(btrim(p_tool), ''), p_reason, coalesce(btrim(p_note), ''));
    PERFORM mint.staff_event('access_request_opened', 'access_request', p_id::text, 1, uid,
        jsonb_build_object('request_id', p_id, 'server_id', p_server,
                           'tool', nullif(btrim(p_tool), ''), 'reason_code', p_reason));
    RETURN p_id;
END $$;

CREATE FUNCTION mint.staff_cancel_access_request(p_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    iid text := mint.staff_instance();
    uid text := mint.staff_user();
    r mint.access_requests;
BEGIN
    UPDATE mint.access_requests SET status = 'cancelled', decided_at = clock_timestamp()
     WHERE instance_id = iid AND id = p_id AND requested_by = uid AND status = 'open'
    RETURNING * INTO r;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM mint.staff_event('access_request_cancelled', 'access_request', p_id::text,
        r.state_version, uid, jsonb_build_object('request_id', p_id, 'server_id', r.server_id));
    RETURN true;
END $$;

GRANT CREATE ON SCHEMA mint TO mint_staff_owner;
DO $$ BEGIN IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    EXECUTE format('GRANT mint_staff_owner TO %I WITH SET TRUE', current_user); END IF; END $$;
ALTER FUNCTION mint.staff_open_access_request(uuid, text, text, text, text) OWNER TO mint_staff_owner;
ALTER FUNCTION mint.staff_cancel_access_request(uuid) OWNER TO mint_staff_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_staff_owner;
DO $$ BEGIN IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    EXECUTE format('REVOKE SET OPTION FOR mint_staff_owner FROM %I', current_user); END IF; END $$;
REVOKE ALL ON FUNCTION mint.staff_open_access_request(uuid, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.staff_cancel_access_request(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.staff_open_access_request(uuid, text, text, text, text) TO mint_staff;
GRANT EXECUTE ON FUNCTION mint.staff_cancel_access_request(uuid) TO mint_staff;

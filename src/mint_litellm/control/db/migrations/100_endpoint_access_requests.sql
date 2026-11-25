-- 직원 PC(설치 키)에서 권한 요청을 열고·취소하고·본다. 직원 화면의 요청과 같은 표·같은 사건을 쓴다.
-- 오류 체계는 단말 신청 함수와 같다: MINT-KEY(키 없음·폐기·만료, 42501) MINT-INVALID(형식, 23514)
-- MINT-NOTFOUND(서버 없음, P0002).
GRANT SELECT ON mint.access_requests TO mint_endpoint_owner;
GRANT INSERT (id, instance_id, requested_by, server_id, tool, reason_code, note)
    ON mint.access_requests TO mint_endpoint_owner;
GRANT UPDATE (status, decided_at) ON mint.access_requests TO mint_endpoint_owner;
GRANT SELECT ON mint.servers TO mint_endpoint_owner;
GRANT SELECT ON mint.approvals TO mint_endpoint_owner;

CREATE FUNCTION mint.endpoint_key_user(p_key_token text, OUT iid text, OUT uid text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    k mint.endpoint_installs;
BEGIN
    SELECT * INTO k FROM mint.endpoint_installs WHERE key_token = p_key_token;
    IF p_key_token IS NULL OR NOT FOUND OR k.revoked_at IS NOT NULL
       OR (k.expires_at IS NOT NULL AND k.expires_at <= clock_timestamp()) THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    iid := k.instance_id; uid := k.user_id;
END $$;

CREATE FUNCTION mint.endpoint_open_access_request(
    p_key_token text, p_id uuid, p_server text, p_tool text, p_reason text, p_note text
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    who record;
    v_tool text := nullif(btrim(p_tool), '');
    existing uuid;
BEGIN
    SELECT * INTO who FROM mint.endpoint_key_user(p_key_token);
    IF p_id IS NULL OR p_server IS NULL OR p_reason IS NULL OR p_reason !~ '^[A-Z][A-Z_]{2,63}$'
       OR length(coalesce(p_note, '')) > 500 OR length(coalesce(v_tool, 'x')) > 256 THEN
        RAISE EXCEPTION 'MINT-INVALID: invalid access request' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM mint.servers WHERE instance_id = who.iid AND server_id = p_server)
    THEN
        RAISE EXCEPTION 'MINT-NOTFOUND: no such server' USING ERRCODE = 'no_data_found';
    END IF;
    SELECT id INTO existing FROM mint.access_requests
     WHERE instance_id = who.iid AND requested_by = who.uid AND server_id = p_server
       AND coalesce(access_requests.tool, '') = coalesce(v_tool, '') AND status = 'open';
    IF FOUND THEN
        RETURN existing;
    END IF;
    INSERT INTO mint.access_requests (id, instance_id, requested_by, server_id, tool, reason_code, note)
    VALUES (p_id, who.iid, who.uid, p_server, v_tool, p_reason, coalesce(btrim(p_note), ''));
    INSERT INTO mint.events(event_id, instance_id, kind, source_key, actor, payload)
      SELECT s.e, who.iid, 'access_request_opened', s.k, who.uid,
             jsonb_build_object('request_id', p_id, 'server_id', p_server, 'tool', v_tool,
                                'reason_code', p_reason, 'source', 'endpoint')
      FROM (SELECT gen_random_uuid() AS e,
                   'access_request:' || p_id || ':1:access_request_opened' AS k) s
      WHERE mint.claim_event_key(who.iid, s.k, s.e);
    RETURN p_id;
END $$;

CREATE FUNCTION mint.endpoint_cancel_access_request(p_key_token text, p_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    who record;
    r mint.access_requests;
BEGIN
    SELECT * INTO who FROM mint.endpoint_key_user(p_key_token);
    UPDATE mint.access_requests SET status = 'cancelled', decided_at = clock_timestamp()
     WHERE instance_id = who.iid AND id = p_id AND requested_by = who.uid AND status = 'open'
    RETURNING * INTO r;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    INSERT INTO mint.events(event_id, instance_id, kind, source_key, actor, payload)
      SELECT s.e, who.iid, 'access_request_cancelled', s.k, who.uid,
             jsonb_build_object('request_id', p_id, 'server_id', r.server_id, 'source', 'endpoint')
      FROM (SELECT gen_random_uuid() AS e,
                   'access_request:' || p_id || ':' || r.state_version
                   || ':access_request_cancelled' AS k) s
      WHERE mint.claim_event_key(who.iid, s.k, s.e);
    RETURN true;
END $$;

CREATE FUNCTION mint.endpoint_my_access_requests(p_key_token text)
RETURNS TABLE (id uuid, server_id text, tool text, reason_code text, status text,
               resolution text, decision_note text, created_at timestamptz,
               decided_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    who record;
BEGIN
    SELECT * INTO who FROM mint.endpoint_key_user(p_key_token);
    RETURN QUERY SELECT a.id, a.server_id, a.tool, a.reason_code, a.status, a.resolution,
                        a.decision_note, a.created_at, a.decided_at
      FROM mint.access_requests a
     WHERE a.instance_id = who.iid AND a.requested_by = who.uid
     ORDER BY a.created_at DESC LIMIT 20;
END $$;

-- 승인이 하나라도 살아 있는 서버(직원 화면 신청 이력의 「이용 종료됨」 판단과 같다).
CREATE FUNCTION mint.endpoint_live_servers(p_key_token text) RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    who record;
BEGIN
    SELECT * INTO who FROM mint.endpoint_key_user(p_key_token);
    RETURN QUERY SELECT DISTINCT a.server_id FROM mint.approvals a
     WHERE a.instance_id = who.iid AND a.status IN ('active', 'pending')
       AND a.valid_until > clock_timestamp();
END $$;

GRANT CREATE ON SCHEMA mint TO mint_endpoint_owner;
DO $$ BEGIN IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    EXECUTE format('GRANT mint_endpoint_owner TO %I WITH SET TRUE', current_user); END IF; END $$;
ALTER FUNCTION mint.endpoint_key_user(text) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_open_access_request(text, uuid, text, text, text, text)
    OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_cancel_access_request(text, uuid) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_my_access_requests(text) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_live_servers(text) OWNER TO mint_endpoint_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_endpoint_owner;
DO $$ BEGIN IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    EXECUTE format('REVOKE SET OPTION FOR mint_endpoint_owner FROM %I', current_user); END IF; END $$;
REVOKE ALL ON FUNCTION mint.endpoint_key_user(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_open_access_request(text, uuid, text, text, text, text)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_cancel_access_request(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_my_access_requests(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_live_servers(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_key_user(text) TO mint_endpoint_owner;
GRANT EXECUTE ON FUNCTION mint.endpoint_open_access_request(text, uuid, text, text, text, text),
    mint.endpoint_cancel_access_request(text, uuid), mint.endpoint_my_access_requests(text),
    mint.endpoint_live_servers(text) TO mint_plugin;

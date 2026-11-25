-- PC 권한 요청에 사유 코드가 없으면, 그 서버·도구에 걸린 활성 차단이 있을 때 DENIED(차단 해제),
-- 없으면 APPROVAL_ABSENT(이 사람에게 허용)로 정한다. 승인자 화면의 차단 조회와 같은 범위다.
GRANT SELECT ON mint.denials TO mint_endpoint_owner;

CREATE OR REPLACE FUNCTION mint.endpoint_open_access_request(
    p_key_token text, p_id uuid, p_server text, p_tool text, p_reason text, p_note text
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    who record;
    v_tool text := nullif(btrim(p_tool), '');
    v_team text;
    v_reason text := p_reason;
    existing uuid;
BEGIN
    SELECT * INTO who FROM mint.endpoint_key_user(p_key_token);
    IF v_reason IS NULL THEN
        SELECT team_id INTO v_team FROM mint.endpoint_installs WHERE key_token = p_key_token;
        v_reason := CASE WHEN EXISTS (
            SELECT 1 FROM mint.denials d
             WHERE d.instance_id = who.iid AND d.lifted_at IS NULL
               AND (d.server_id IS NULL OR d.server_id = p_server)
               AND (d.tools IS NULL OR v_tool IS NULL OR v_tool = ANY (d.tools))
               AND ((d.scope_type = 'user' AND d.scope_id = who.uid)
                    OR (d.scope_type = 'team' AND d.scope_id = v_team)
                    OR d.scope_type IN ('org', 'server')))
          THEN 'DENIED' ELSE 'APPROVAL_ABSENT' END;
    END IF;
    IF p_id IS NULL OR p_server IS NULL OR v_reason !~ '^[A-Z][A-Z_]{2,63}$'
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
    VALUES (p_id, who.iid, who.uid, p_server, v_tool, v_reason, coalesce(btrim(p_note), ''));
    INSERT INTO mint.events(event_id, instance_id, kind, source_key, actor, payload)
      SELECT s.e, who.iid, 'access_request_opened', s.k, who.uid,
             jsonb_build_object('request_id', p_id, 'server_id', p_server, 'tool', v_tool,
                                'reason_code', v_reason, 'source', 'endpoint')
      FROM (SELECT gen_random_uuid() AS e,
                   'access_request:' || p_id || ':1:access_request_opened' AS k) s
      WHERE mint.claim_event_key(who.iid, s.k, s.e);
    RETURN p_id;
END $$;

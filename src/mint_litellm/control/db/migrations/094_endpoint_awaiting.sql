-- 웹 화면으로 낸 신청은 PC가 모른다. 보고 응답에 「이 사람의 신청이 진행 중이거나 방금 승인됐다」를
-- 실어 PC가 짧은 주기로 보고해 승인을 곧바로 받게 한다(그 밖의 내용은 싣지 않는다).
CREATE FUNCTION mint.endpoint_user_awaiting(p_instance text, p_key_token text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM mint.endpoint_installs k JOIN mint.intakes i
          ON i.instance_id = k.instance_id AND i.requested_by = k.user_id
        WHERE k.instance_id = p_instance AND k.key_token = p_key_token AND k.revoked_at IS NULL
          AND (i.status IN ('received', 'checking', 'passed', 'indeterminate')
               OR (i.decision IN ('approved', 'exception')
                   AND i.decided_at > clock_timestamp() - interval '15 minutes')))
$$;
REVOKE ALL ON FUNCTION mint.endpoint_user_awaiting(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_user_awaiting(text, text) TO mint_plugin;

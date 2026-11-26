-- 접수 단계(서버 pending)에서 신청을 철회·반려해도 서버 등록이 「접수」에 남지 않고 반려로 닫는다.
DROP TRIGGER servers_1_status ON mint.servers;
CREATE TRIGGER servers_1_status BEFORE INSERT OR UPDATE ON mint.servers
    FOR EACH ROW EXECUTE FUNCTION mint.check_status(
        'pending,awaiting_approval',
        'pending>validating,pending>rejected,validating>awaiting_approval,validating>rejected,'
        'awaiting_approval>approved,awaiting_approval>validating,awaiting_approval>rejected,'
        'approved>suspended,suspended>approved,'
        'approved>terminating,suspended>terminating,terminating>terminated,'
        'rejected>validating');

CREATE OR REPLACE FUNCTION mint.withdraw_intake_row(iid text,p_id uuid,uid text,p_version bigint,
    p_reason text,p_actor text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,mint,pg_temp AS $$
DECLARE r mint.intakes; s mint.servers;
BEGIN
    IF uid IS NULL OR p_actor IS NULL OR length(btrim(coalesce(p_reason,''))) NOT BETWEEN 1 AND 500
    THEN RAISE EXCEPTION 'withdrawal reason and identity required' USING ERRCODE='check_violation'; END IF;
    SELECT * INTO r FROM mint.intakes WHERE instance_id=iid AND id=p_id FOR UPDATE;
    IF NOT FOUND OR r.requested_by IS DISTINCT FROM uid OR r.source NOT IN ('staff','operator','endpoint')
    THEN RAISE EXCEPTION 'only the requester may withdraw this application' USING ERRCODE='insufficient_privilege'; END IF;
    IF r.decision='withdrawn' THEN RETURN jsonb_build_object('changed',false,'intake',to_jsonb(r)); END IF;
    IF p_version IS NULL OR r.state_version<>p_version OR r.status NOT IN ('received','checking','passed','indeterminate','failed')
    THEN RAISE EXCEPTION 'application state changed or not withdrawable' USING ERRCODE='check_violation'; END IF;
    IF EXISTS(SELECT 1 FROM mint.jobs WHERE instance_id=iid AND kind='intake_run'
        AND split_part(target_ref,'/',1)=p_id::text AND status='running')
    THEN RAISE EXCEPTION 'validation is running; retry after completion' USING ERRCODE='check_violation'; END IF;
    SELECT * INTO s FROM mint.servers WHERE instance_id=iid AND server_id=r.server_id FOR UPDATE;
    IF NOT FOUND OR s.status NOT IN ('pending','validating','awaiting_approval','rejected')
       OR s.contract_status='managed'
    THEN RAISE EXCEPTION 'an approved or managed server cannot be withdrawn' USING ERRCODE='check_violation'; END IF;
    UPDATE mint.intakes SET status='decided',decision='withdrawn',decided_by=p_actor,
        decision_reason=btrim(p_reason),decided_at=clock_timestamp() WHERE id=p_id RETURNING * INTO r;
    UPDATE mint.tool_contracts SET status='superseded' WHERE instance_id=iid AND server_id=r.server_id
        AND status='candidate' AND source='intake';
    UPDATE mint.deployment_contracts SET status='superseded' WHERE instance_id=iid AND server_id=r.server_id
        AND status='candidate';
    -- Unapproved registration remains in place, and no usage permission is issued.
    IF s.status IN ('pending','validating','awaiting_approval') THEN
        UPDATE mint.servers SET status='rejected' WHERE instance_id=iid AND server_id=r.server_id;
    END IF;
    RETURN jsonb_build_object('changed',true,'intake',to_jsonb(r));
END $$;

-- 모든 신청이 닫혔는데 서버가 「접수」에 남은 행은 반려로 정리한다.
UPDATE mint.servers s SET status = 'rejected'
 WHERE s.status = 'pending'
   AND EXISTS (SELECT 1 FROM mint.intakes i WHERE i.instance_id = s.instance_id
                 AND i.server_id = s.server_id AND i.decision IN ('rejected', 'withdrawn'))
   AND NOT EXISTS (SELECT 1 FROM mint.intakes i WHERE i.instance_id = s.instance_id
                     AND i.server_id = s.server_id AND i.status <> 'decided');

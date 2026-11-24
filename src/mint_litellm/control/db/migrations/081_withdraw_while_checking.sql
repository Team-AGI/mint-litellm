-- 「검사 중」(재시도 중 포함)인 신청도 신청자가 화면에서 철회할 수 있다. 검사가 지금 실행 중일
-- 때만 막고, 남은 검사 작업은 신청이 결정되면 아무것도 하지 않고 끝난다.
DROP TRIGGER intakes_1_status ON mint.intakes;
CREATE TRIGGER intakes_1_status BEFORE INSERT OR UPDATE ON mint.intakes
    FOR EACH ROW EXECUTE FUNCTION mint.check_status('received',
      'received>checking,received>decided,checking>passed,checking>failed,checking>indeterminate,'
      'checking>decided,passed>decided,failed>decided,indeterminate>decided,passed>checking,'
      'indeterminate>checking,failed>checking');
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
    IF p_version IS NULL OR r.state_version<>p_version OR r.status NOT IN ('received','checking','passed','indeterminate')
    THEN RAISE EXCEPTION 'application state changed or not withdrawable' USING ERRCODE='check_violation'; END IF;
    IF EXISTS(SELECT 1 FROM mint.jobs WHERE instance_id=iid AND kind='intake_run'
        AND split_part(target_ref,'/',1)=p_id::text AND status='running')
    THEN RAISE EXCEPTION 'validation is running; retry after completion' USING ERRCODE='check_violation'; END IF;
    SELECT * INTO s FROM mint.servers WHERE instance_id=iid AND server_id=r.server_id FOR UPDATE;
    IF NOT FOUND OR s.status NOT IN ('pending','awaiting_approval','rejected') OR s.contract_status='managed'
    THEN RAISE EXCEPTION 'an approved or managed server cannot be withdrawn' USING ERRCODE='check_violation'; END IF;
    UPDATE mint.intakes SET status='decided',decision='withdrawn',decided_by=p_actor,
        decision_reason=btrim(p_reason),decided_at=clock_timestamp() WHERE id=p_id RETURNING * INTO r;
    UPDATE mint.tool_contracts SET status='superseded' WHERE instance_id=iid AND server_id=r.server_id
        AND status='candidate' AND source='intake';
    UPDATE mint.deployment_contracts SET status='superseded' WHERE instance_id=iid AND server_id=r.server_id
        AND status='candidate';
    -- Unapproved registration remains in place, and no usage permission is issued.
    IF s.status='awaiting_approval' THEN
        UPDATE mint.servers SET status='rejected' WHERE instance_id=iid AND server_id=r.server_id;
    END IF;
    RETURN jsonb_build_object('changed',true,'intake',to_jsonb(r));
END $$;

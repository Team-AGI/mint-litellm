-- 검사 작업이 실행 중이어도 신청자가 철회할 수 있다(QA-BUG-301). 실행 중인 검사는 결정을 보고
-- 판정 없이 멈추고, 그 사이 만든 후보 계약은 거둔다(서비스 conclude).
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

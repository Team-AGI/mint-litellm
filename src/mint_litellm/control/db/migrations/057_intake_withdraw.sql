-- Withdrawal is a terminal decision, preserving immutable check/event history.
ALTER TABLE mint.intakes DROP CONSTRAINT intakes_decision_check;
ALTER TABLE mint.intakes ADD CONSTRAINT intakes_decision_check
    CHECK (decision IN ('approved','rejected','exception','withdrawn'));
DO $$ DECLARE c record; BEGIN
    FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='mint.intakes'::regclass
      AND contype='c' AND pg_get_constraintdef(oid) LIKE '%purpose IS NOT NULL%'
    LOOP EXECUTE format('ALTER TABLE mint.intakes DROP CONSTRAINT %I',c.conname); END LOOP;
END $$;
ALTER TABLE mint.intakes ADD CONSTRAINT intakes_complete_before_check
    CHECK (status='received' OR (status='decided' AND decision IN ('rejected','withdrawn')) OR (
      purpose IS NOT NULL AND data_grade IS NOT NULL AND allowed_resources IS NOT NULL
      AND provider IS NOT NULL AND owner_user_id IS NOT NULL AND readiness IS NOT NULL
      AND data_return_terms IS NOT NULL AND requested_by IS NOT NULL));
DROP TRIGGER intakes_1_status ON mint.intakes;
CREATE TRIGGER intakes_1_status BEFORE INSERT OR UPDATE ON mint.intakes
    FOR EACH ROW EXECUTE FUNCTION mint.check_status('received',
      'received>checking,received>decided,checking>passed,checking>failed,checking>indeterminate,'
      'passed>decided,failed>decided,indeterminate>decided,passed>checking,indeterminate>checking');
-- Preserve early rejection of forbidden submissions; never approve before review.
CREATE FUNCTION mint.guard_intake_early_close() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,mint AS $$ BEGIN
    IF OLD.status='received' AND NEW.status='decided'
       AND NEW.decision IS DISTINCT FROM 'withdrawn' AND NEW.decision IS DISTINCT FROM 'rejected'
    THEN RAISE EXCEPTION 'unreviewed application can only be rejected or withdrawn' USING ERRCODE='check_violation'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER intakes_0_early_close BEFORE UPDATE ON mint.intakes
    FOR EACH ROW EXECUTE FUNCTION mint.guard_intake_early_close();

GRANT SELECT ON mint.intakes,mint.servers,mint.jobs,mint.approvals,
    mint.tool_contracts,mint.deployment_contracts TO mint_staff_owner;
GRANT UPDATE(status,decision,decided_by,decision_reason,decided_at) ON mint.intakes TO mint_staff_owner;
GRANT UPDATE(status) ON mint.servers,mint.tool_contracts,mint.deployment_contracts TO mint_staff_owner;
GRANT EXECUTE ON FUNCTION mint.contract_input_keys(text) TO mint_staff_owner;

CREATE FUNCTION mint.withdraw_intake_row(iid text,p_id uuid,uid text,p_version bigint,
    p_reason text,p_actor text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,mint,pg_temp AS $$
DECLARE r mint.intakes; s mint.servers;
BEGIN
    IF uid IS NULL OR p_actor IS NULL OR length(btrim(coalesce(p_reason,''))) NOT BETWEEN 1 AND 500
    THEN RAISE EXCEPTION 'withdrawal reason and identity required' USING ERRCODE='check_violation'; END IF;
    SELECT * INTO r FROM mint.intakes WHERE instance_id=iid AND id=p_id FOR UPDATE;
    IF NOT FOUND OR r.requested_by IS DISTINCT FROM uid OR r.source NOT IN ('staff','operator')
    THEN RAISE EXCEPTION 'only the requester may withdraw this application' USING ERRCODE='insufficient_privilege'; END IF;
    IF r.decision='withdrawn' THEN RETURN jsonb_build_object('changed',false,'intake',to_jsonb(r)); END IF;
    IF p_version IS NULL OR r.state_version<>p_version OR r.status NOT IN ('received','passed','indeterminate')
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

CREATE FUNCTION mint.staff_withdraw_intake(p_id uuid,p_version bigint,p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mint,pg_temp AS $$
DECLARE s mint.console_sessions := mint.staff_active_session(); result jsonb; r jsonb;
BEGIN
    IF s.last_verified_at<=clock_timestamp()-make_interval(secs=>coalesce(
        nullif(current_setting('mint.staff_verify_window_seconds',true),'')::int,600))
    THEN RAISE EXCEPTION 'staff session needs verification' USING ERRCODE='insufficient_privilege'; END IF;
    IF NOT EXISTS(SELECT 1 FROM mint.intakes WHERE instance_id=mint.staff_instance()
        AND id=p_id AND requested_by=mint.staff_user() AND source='staff')
    THEN RAISE EXCEPTION 'application not owned by this employee' USING ERRCODE='insufficient_privilege'; END IF;
    result:=mint.withdraw_intake_row(mint.staff_instance(),p_id,mint.staff_user(),p_version,p_reason,mint.staff_user());
    r:=result->'intake';
    IF (result->>'changed')::boolean THEN
        PERFORM mint.staff_event('intake_decided','intake',p_id::text,(r->>'state_version')::bigint,mint.staff_user(),
          jsonb_build_object('intake_id',p_id,'server_id',r->>'server_id','decision','withdrawn',
            'reason',r->>'decision_reason','decided_by',mint.staff_user(),'automatic',false));
    END IF;
    RETURN result;
END $$;
GRANT CREATE ON SCHEMA mint TO mint_staff_owner;
DO $$ BEGIN IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
    EXECUTE format('GRANT mint_staff_owner TO %I WITH SET TRUE',current_user); END IF; END $$;
ALTER FUNCTION mint.withdraw_intake_row(text,uuid,text,bigint,text,text) OWNER TO mint_staff_owner;
ALTER FUNCTION mint.staff_withdraw_intake(uuid,bigint,text) OWNER TO mint_staff_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_staff_owner;
DO $$ BEGIN IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
    EXECUTE format('REVOKE SET OPTION FOR mint_staff_owner FROM %I',current_user); END IF; END $$;
REVOKE ALL ON FUNCTION mint.withdraw_intake_row(text,uuid,text,bigint,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.staff_withdraw_intake(uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.withdraw_intake_row(text,uuid,text,bigint,text,text) TO mint_control;
GRANT EXECUTE ON FUNCTION mint.staff_withdraw_intake(uuid,bigint,text) TO mint_staff;

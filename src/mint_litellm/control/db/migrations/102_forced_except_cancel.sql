-- Root 검사 생략 승인과 진행 중 실행 취소도 강제 조치 기록에 남긴다.
ALTER TABLE mint.forced_actions DROP CONSTRAINT forced_actions_action_check;
ALTER TABLE mint.forced_actions ADD CONSTRAINT forced_actions_action_check CHECK (action IN (
    'halt', 'halt_lift', 'intake_reject', 'server_suspend', 'server_resume',
    'server_terminate', 'person_lockout', 'person_unlock', 'sessions_end', 'root_set',
    'root_unset', 'intake_except', 'run_cancel'));

-- 검사 전·검사 중 신청은 일반 결정으로 닫지 않는다(철회·접수 반려만). Root 강제 반려·검사 생략
-- 승인은 서비스가 Root를 확인한 뒤 같은 트랜잭션에서 mint.root_force를 켜고 결정한다.
CREATE OR REPLACE FUNCTION mint.guard_intake_early_close() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,mint AS $$ BEGIN
    IF current_setting('mint.root_force', true) = 'on' THEN RETURN NEW; END IF;
    IF OLD.status='received' AND NEW.status='decided'
       AND NEW.decision IS DISTINCT FROM 'withdrawn' AND NEW.decision IS DISTINCT FROM 'rejected'
    THEN RAISE EXCEPTION 'unreviewed application can only be rejected or withdrawn' USING ERRCODE='check_violation'; END IF;
    IF OLD.status='checking' AND NEW.status='decided' AND NEW.decision IS DISTINCT FROM 'withdrawn'
    THEN RAISE EXCEPTION 'an application under checking can only be withdrawn' USING ERRCODE='check_violation'; END IF;
    RETURN NEW;
END $$;

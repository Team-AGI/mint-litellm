import pytest
import psycopg
import uuid
from datetime import UTC, datetime, timedelta
from ctl_fixtures import INSTANCE, as_login
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import intake_withdrawals as svc, staff
from . import test_intakes as base
from .test_staff_intake_flow import submit

world=base.world

def withdraw(world,identifier,**options):
    version=options.pop('version',world.intake(identifier)['state_version'])
    reason=options.pop('reason','잘못된 신청 철회')
    return world.call(lambda ctx:svc.withdraw(ctx,identifier,version,reason),**options)

def test_pending_withdrawal_stops_queued_probe_and_allows_new_request(world):
    identifier=world.create()
    row=withdraw(world,identifier)
    assert row['decision']=='withdrawn'
    before=len(world.stub.requests)
    world.drain()
    assert len(world.stub.requests)==before
    assert world.checks(identifier)==[]
    assert world.create()!=identifier

def test_passed_withdrawal_preserves_checks_and_is_idempotent(world):
    identifier=world.create()
    world.drain()
    version=world.intake(identifier)['state_version']
    assert len(world.checks(identifier))==8
    withdraw(world,identifier,version=version)
    withdraw(world,identifier,version=version)
    assert len(world.checks(identifier))==8
    assert len([e for e in world.events('intake_decided') if e['payload'].get('decision')=='withdrawn'])==1
    assert world.server()['status']=='rejected'
    assert world.create()!=identifier

def test_other_user_and_stale_version_cannot_withdraw(world):
    identifier=world.create()
    with pytest.raises(ControlError):withdraw(world,identifier,user='other-user')
    with pytest.raises(ControlError):withdraw(world,identifier,version=999)
    assert world.intake(identifier)['status']=='received'

def test_empty_reason_and_checking_state_cannot_withdraw(world):
    identifier=world.create()
    with pytest.raises(ControlError):withdraw(world,identifier,reason=' ')
    world.conn.execute("UPDATE mint.intakes SET status='checking' WHERE id=%s",(identifier,))
    with pytest.raises(ControlError):withdraw(world,identifier)

def test_leased_validation_job_blocks_withdrawal_even_before_checking(world):
    identifier=world.create()
    world.conn.execute("UPDATE mint.jobs SET status='running',lease_owner='test',"
                       "lease_until=now()+interval '1 minute' WHERE kind='intake_run'"
                       " AND target_ref=%s",(identifier,))
    with pytest.raises(ControlError):withdraw(world,identifier)
    assert world.intake(identifier)['status']=='received'

def test_incomplete_input_cannot_enter_checking_but_requester_can_withdraw(world):
    identifier=world.create()
    world.conn.execute('UPDATE mint.intakes SET purpose=NULL WHERE id=%s',(identifier,))
    with pytest.raises(psycopg.errors.CheckViolation):
        world.conn.execute("UPDATE mint.intakes SET status='checking' WHERE id=%s",(identifier,))
    assert withdraw(world,identifier)['decision']=='withdrawn'

def test_employee_withdraws_a_validated_request_through_session_function(world):
    identifier=submit(world)
    world.drain()
    with as_login(world.url,'mint_staff') as sc, as_login(world.url,'mint_control') as control:
        sctx=staff.StaffContext(sc,control,INSTANCE,'employee')
        session=uuid.uuid4().hex*2
        now=datetime.now(UTC)
        staff.start_session(sctx,session,'ab'*32,now+timedelta(minutes=30),now+timedelta(hours=1))
        assert not sc.execute("SELECT has_function_privilege(current_user,"
            "'mint.withdraw_intake_row(text,uuid,text,bigint,text,text)','EXECUTE')").fetchone()[0]
        sc.commit()
        version=world.intake(identifier)['state_version']
        assert svc.staff_withdraw(sctx,session,identifier,version,'업무 취소')['decision']=='withdrawn'
    assert len(world.checks(identifier))==8
    assert submit(world)!=identifier

@pytest.mark.parametrize('decision',['approve','reject'])
def test_terminal_approval_or_rejection_cannot_be_withdrawn(world,decision):
    identifier=world.create()
    world.drain()
    world.decide(identifier,decision,reason='심사 결과')
    with pytest.raises(ControlError):withdraw(world,identifier)
    assert world.intake(identifier)['decision'] in ('approved','rejected')

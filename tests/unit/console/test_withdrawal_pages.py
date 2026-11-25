import pytest

from . import test_intake_contract_screens as screens
from . import test_staff_intakes as staff_tests

sworld = staff_tests.sworld


@pytest.fixture(autouse=True)
def _distinct_approver(monkeypatch):
    """직무 분리는 설정을 켰을 때만 건다."""
    monkeypatch.setenv("MINT_REQUIRE_DISTINCT_APPROVER", "1")



def test_employee_withdrawal_owner_csrf_confirmation_and_resubmission(sworld):
    client = staff_tests.staff_tests.logged_in(sworld)
    values = staff_tests.form(client)
    assert client.post("/staff/intakes", data=values).status_code == 303
    identifier = values["request_id"]
    path = "/staff/intakes/" + identifier
    page = client.get(path)
    assert "신청 철회" in page.text
    version = sworld.query("SELECT state_version FROM mint.intakes WHERE id=%s", identifier)[0][0]
    data = {
        "csrf": staff_tests.staff_tests.csrf(client),
        "state_version": version,
        "reason": "업무 변경",
        "confirm": "yes",
    }
    assert (
        client.post(
            path + "/withdraw", data={k: v for k, v in data.items() if k != "csrf"}
        ).status_code
        == 403
    )
    assert client.post(path + "/withdraw", data={**data, "confirm": ""}).status_code == 400
    other = staff_tests.staff_tests.logged_in(sworld, staff_tests.staff_tests.OTHER_KEY)
    assert (
        other.post(
            path + "/withdraw", data={**data, "csrf": staff_tests.staff_tests.csrf(other)}
        ).status_code
        == 404
    )
    assert client.post(path + "/withdraw", data=data).status_code == 303
    assert "철회됨" in client.get(path).text
    assert sworld.query("SELECT count(*) FROM mint.events WHERE kind='intake_decided'")[0][0] == 1
    assert client.post("/staff/intakes", data=staff_tests.form(client)).status_code == 303


def test_staff_withdrawal_removes_the_second_approval_from_the_reviewer_console(sworld):
    applicant = staff_tests.staff_tests.logged_in(sworld)
    values = staff_tests.form(applicant)
    identifier = values["request_id"]
    submission = applicant.post("/staff/intakes", data=values)
    assert submission.status_code == 303, submission.text
    staff_path = "/staff/intakes/" + identifier
    review_path = "/intakes/" + identifier
    queue_path = "/approvals?tab=second"

    reviewer = sworld.session_client("admin")
    assert review_path in reviewer.get("/intakes?source=staff").text
    # Model an inconclusive inspection locally so the dummy provider is never contacted.
    sworld.query("UPDATE mint.intakes SET status='checking' WHERE id=%s", identifier)
    sworld.query("UPDATE mint.intakes SET status='indeterminate' WHERE id=%s", identifier)
    first_decision = screens.hold_it(sworld, identifier, role="approver")
    assert first_decision.status_code == 303, first_decision.text
    confirm_path = f"/exceptions/{screens.hold_id(sworld)}/confirm"
    assert confirm_path in reviewer.get(queue_path).text
    assert "두 번째 승인 대기" in reviewer.get(review_path).text
    assert f'action="{staff_path}/withdraw"' in applicant.get(staff_path).text

    withdrawal = applicant.post(staff_path + "/withdraw", data={
        "csrf": staff_tests.staff_tests.csrf(applicant),
        "state_version": screens.version(sworld, identifier),
        "reason": "업무 범위 변경",
        "confirm": "yes",
    })
    assert withdrawal.status_code == 303, withdrawal.text
    applicant_page = applicant.get(withdrawal.headers["location"]).text
    assert "철회됨" in applicant_page and "업무 범위 변경" in applicant_page
    assert f'action="{staff_path}/withdraw"' not in applicant_page

    reviewer_page = reviewer.get(review_path).text
    assert "철회됨" in reviewer_page and "업무 범위 변경" in reviewer_page
    assert "두 번째 승인 대기" not in reviewer_page
    assert f'action="{review_path}/decision"' not in reviewer_page
    queue = reviewer.get(queue_path).text
    assert confirm_path not in queue
    assert "두 번째 승인을 기다리는 요청이 없습니다" in queue

    # A reviewer may still have the pre-withdrawal form open in a different tab.
    stale = reviewer.post(confirm_path, data={"csrf": sworld.csrf(reviewer)})
    assert stale.status_code == 409
    assert confirm_path not in stale.text
    assert sworld.query("SELECT status,decision FROM mint.intakes WHERE id=%s", identifier) == [
        ("decided", "withdrawn")]
    assert sworld.query("SELECT count(*) FROM mint.approvals") == [(0,)]


def test_admin_requester_can_withdraw_own_application_but_not_other_users(world):
    identifier = screens.add_intake(world, requested_by="human-1")
    admin = world.session_client("admin")
    path = "/intakes/" + identifier
    assert "신청 철회" in admin.get(path).text
    data = {
        "csrf": world.csrf(admin),
        "state_version": screens.version(world, identifier),
        "reason": "직원 신청으로 다시 진행",
        "confirm": "yes",
    }
    response = admin.post(path + "/withdraw", data=data)
    assert response.status_code == 303, response.text
    assert "철회됨" in admin.get(path).text
    other_id = screens.add_intake(world, requested_by="human-9")
    assert 'name="confirm" value="yes"' not in admin.get("/intakes/" + other_id).text
    assert (
        admin.post(
            "/intakes/" + other_id + "/withdraw",
            data={**data, "state_version": screens.version(world, other_id)},
        ).status_code
        == 403
    )


def test_a_failed_application_can_be_cancelled_and_sent_again(sworld):
    client = staff_tests.staff_tests.logged_in(sworld)
    values = staff_tests.form(client)
    assert client.post("/staff/intakes", data=values).status_code == 303
    identifier = values["request_id"]
    for status in ("checking", "failed"):
        sworld.query("UPDATE mint.intakes SET status=%s WHERE id=%s", status, identifier)
    path = "/staff/intakes/" + identifier
    assert "신청 철회" in client.get(path).text
    version = sworld.query("SELECT state_version FROM mint.intakes WHERE id=%s", identifier)[0][0]
    data = {"csrf": staff_tests.staff_tests.csrf(client), "state_version": version,
            "reason": "신청자 취소", "confirm": "yes"}
    assert client.post(path + "/withdraw", data=data).status_code == 303
    assert client.post("/staff/intakes", data=staff_tests.form(client)).status_code == 303

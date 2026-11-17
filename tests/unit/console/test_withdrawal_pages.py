from . import test_intake_contract_screens as screens
from . import test_staff_intakes as staff_tests

sworld = staff_tests.sworld


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

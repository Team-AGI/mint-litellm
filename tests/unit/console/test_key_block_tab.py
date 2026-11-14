"""승인 센터 「차단 제안」 탭: 목록·상세, 승인·거절·해제 요청과 역할."""

import json
import uuid

from console_fixtures import CONTROL_KEY, key_info
from console_pages_support import INSTANCE, form_post

TOKEN = "f" * 64


def seed(world, status="proposed", mint_blocked=False, **extra):
    proposal = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.key_block_proposals (id, instance_id, status, signal, key_token,"
        " key_alias, user_id, evidence, expires_at, mint_blocked, marker_updated_at)"
        " VALUES (%s, %s, %s, 'secret_exposure', %s, 'k-risky', 'someone-else', %s,"
        " now() + interval '1 day', %s, 'm1')",
        proposal, INSTANCE, status, TOKEN,
        json.dumps({"labels": ["private_key"], "calls": 2, "event_ids": ["e1", "e2"]}),
        mint_blocked,
    )
    litellm_key(world, blocked=extra.get("blocked"), updated_at="m1")
    return proposal


def litellm_key(world, **fields):
    body = key_info("someone-else", key_alias="k-risky", **fields)
    body["key"] = TOKEN
    world.stub.routes[("/key/info", CONTROL_KEY, TOKEN)] = (200, body)


def version(world, proposal):
    return world.query("SELECT state_version FROM mint.key_block_proposals WHERE id = %s",
                       proposal)[0][0]


def test_the_tab_lists_proposals_and_the_drawer_shows_impact_without_values(world, admin):
    proposal = seed(world)
    html = admin.get("/approvals?tab=blocks").text
    assert "k-risky" in html and "비밀·자격 노출" in html and "승인 대기" in html
    assert "private_key" not in html
    detail = admin.get(f"/approvals?tab=blocks&focus={proposal}").text
    assert "키 차단 승인" in detail and "탐지: 개인 키" in detail
    assert "사건</dt><dd>2건" in detail


def test_approving_records_the_approval_and_queues_the_block(world, admin):
    proposal = seed(world)
    world.with_control_key()
    response = form_post(world, admin, f"/key-blocks/{proposal}/approve", scope="key",
                         state_version=version(world, proposal), reason="확인")
    assert response.status_code == 303 and "key_block_approved" in response.headers["location"]
    assert world.query("SELECT status, decided_by FROM mint.key_block_proposals")[0] == (
        "approved", "admin")
    assert world.query("SELECT count(*) FROM mint.jobs WHERE kind = 'key_block_apply'")[0][0] == 1
    again = form_post(world, admin, f"/key-blocks/{proposal}/approve", scope="key",
                      state_version=version(world, proposal))
    assert again.status_code == 303
    assert world.query("SELECT count(*) FROM mint.jobs WHERE kind = 'key_block_apply'")[0][0] == 1


def test_a_viewer_cannot_decide_and_an_approver_cannot_unblock(world):
    proposal = seed(world)
    world.with_control_key()
    viewer = world.session_client("viewer")
    assert "차단 승인" not in viewer.get(f"/approvals?tab=blocks&focus={proposal}").text
    refused = form_post(world, viewer, f"/key-blocks/{proposal}/approve", scope="key",
                        state_version=version(world, proposal))
    assert refused.status_code in (400, 403)
    assert world.query("SELECT status FROM mint.key_block_proposals")[0][0] == "proposed"
    blocked = seed(world, "applied", True, blocked=True)
    approver = world.session_client("approver")
    refused = form_post(world, approver, f"/key-blocks/{blocked}/unblock", reason="x",
                        state_version=version(world, blocked))
    assert refused.status_code in (400, 403)


def test_unblock_warns_then_queues_after_acknowledgement(world, admin):
    proposal = seed(world, "applied", True, blocked=True)
    litellm_key(world, blocked=True, updated_at="other")
    world.with_control_key()
    path = f"/key-blocks/{proposal}/unblock"
    warned = form_post(world, admin, path, reason="확인", state_version=version(world, proposal))
    assert warned.status_code == 409 and "바뀐 것으로 보입니다" in warned.text
    done = form_post(world, admin, path, reason="확인", acknowledge="1",
                     state_version=version(world, proposal))
    assert done.status_code == 303
    assert world.query("SELECT status FROM mint.key_block_proposals")[0][0] == "unblocking"


def test_reject_closes_the_proposal(world, admin):
    proposal = seed(world)
    done = form_post(world, admin, f"/key-blocks/{proposal}/reject", reason="오탐",
                     state_version=version(world, proposal))
    assert done.status_code == 303
    assert world.query("SELECT status FROM mint.key_block_proposals")[0][0] == "rejected"

"""화면 시험이 함께 쓰는 상수와 보조 함수."""

import uuid

INSTANCE = "inst1"
PAGES = [
    "/", "/servers", "/servers/srv-ok", "/servers?filter=changed", "/servers/srv-ok?tab=contract",
    "/approvals", "/approvals?tab=calls", "/access", "/access?tab=dormant",
    "/endpoints", "/endpoints?tab=local-mcp", "/intakes/new", "/alerts", "/ledger", "/policy",
    "/admin",
]
# 화면에 그대로 나오면 안 되는 영어 열거값(상세의 「코드」 칸과 원장의 사건 키는 예외)
ENUMS = ["awaiting_approval", "enforce", "approver", "terminated", "suspended", "pending"]


def server_status(world) -> str:
    return world.query("SELECT status FROM mint.servers WHERE server_id = 'srv-ok'")[0][0]


def add_approval(world, server_id: str = "srv-ok") -> str:
    approval_id = str(uuid.uuid4())
    relation = world.query(
        "SELECT id FROM mint.usage_relations WHERE server_id = %s", server_id)[0][0]
    world.query(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id, tools,"
        " scope_type, scope_id, valid_from, valid_until, basis, granted_by, requested_by, status)"
        " VALUES (%s, %s, 'acme', %s, 'standard', %s, ARRAY['echo', 'ping'], 'user', 'human-5',"
        " now(), now() + interval '30 days', '{}', 'admin', 'human-5', 'active')",
        approval_id, INSTANCE, relation, server_id)
    return approval_id


def form_post(world, client, path, **fields):
    return client.post(path, data={"csrf": world.csrf(client), **fields})

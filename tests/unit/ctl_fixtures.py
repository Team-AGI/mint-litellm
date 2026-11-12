"""제어 평면 시험이 공유하는 고정 장치."""

import os
import uuid
from collections.abc import Iterator

import pytest
from litellm_stub import CONTROL_KEY, StubLiteLLM

import mint_litellm.control.db.migrate as migrate
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.litellm_admin import LiteLLMAdmin

DATABASE_URL = os.environ.get("MINT_TEST_DATABASE_URL")
INSTANCE = "inst1"


def make_ctx(conn, name: str = "root", role: str = "admin", user_id: str | None = "root-user"):
    return Context(conn, INSTANCE, Operator(name, role, user_id))


@pytest.fixture
def stub() -> Iterator[StubLiteLLM]:
    server = StubLiteLLM()
    yield server
    server.close()


@pytest.fixture
def litellm(stub: StubLiteLLM) -> LiteLLMAdmin:
    return LiteLLMAdmin(stub.url, CONTROL_KEY)


@pytest.fixture
def fresh_db() -> Iterator[str]:
    """마이그레이션 실행기로 초기화한 일회용 데이터베이스."""
    if not DATABASE_URL:
        pytest.skip("MINT_TEST_DATABASE_URL is not set")
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    name = f"mint_ctl_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    params = conninfo_to_dict(DATABASE_URL)
    params["dbname"] = name
    url = make_conninfo(**params)
    try:
        with psycopg.connect(url) as conn:
            migrate.apply_migrations(conn)
        yield url
    finally:
        with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


LOGIN_PASSWORDS = {
    "mint_plugin": "pw-plugin",
    "mint_control": "pw-control",
    "mint_worker": "pw-worker",
    "mint_staff": "pw-staff",
}


def as_login(url: str, key: str):
    """``mint_<프로세스>_app`` 로그인 역할로 접속한다(``login_roles`` 장치가 먼저 필요하다)."""
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    from mint_litellm.control.db.roles import LOGIN_ROLES

    params = conninfo_to_dict(url)
    params.update(user=LOGIN_ROLES[key], password=LOGIN_PASSWORDS[key])
    return psycopg.connect(make_conninfo(**params))


@pytest.fixture
def login_roles(fresh_db: str) -> Iterator[list[str]]:
    """네 프로세스의 로그인 역할을 만들고 시험이 끝나면 지운다(역할은 클러스터 전체에 속한다)."""
    import psycopg

    from mint_litellm.control.db.roles import LOGIN_ROLES, ensure_login_roles

    with psycopg.connect(fresh_db) as conn:
        configured = ensure_login_roles(conn, LOGIN_PASSWORDS)
    yield configured
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        for login in LOGIN_ROLES.values():
            conn.execute(f'DROP OWNED BY "{login}"')
            conn.execute(f'DROP ROLE IF EXISTS "{login}"')


def seed_approval_evidence(conn, intake_id) -> None:
    """신청 승인에 필요한 사람 확인 증빙을 모두 유효하게 넣는다(승인 시험의 준비 단계)."""
    from mint_litellm.control.services.evidence import KINDS

    names = [k.key for k in KINDS.values() if k.gate == "approve"]
    conn.execute(
        "INSERT INTO mint.policy_evidence (id, instance_id, kind, subject_kind, subject_id,"
        " summary, attached_by, valid_until) SELECT gen_random_uuid(), %s, k, 'intake', %s,"
        " '시험', 'root', now() + interval '30 days' FROM unnest(%s::text[]) AS k",
        (INSTANCE, str(intake_id), names),
    )


def seed_version_evidence(conn, server_id, instance=INSTANCE) -> None:
    """배포 계약이 바뀌는 재승인에 필요한 판본 확인 증빙을 유효하게 넣는다."""
    conn.execute(
        "INSERT INTO mint.policy_evidence (id, instance_id, kind, subject_kind, subject_id,"
        " summary, attached_by, valid_until) VALUES (gen_random_uuid(), %s, 'version_review',"
        " 'server', %s, '시험', 'root', now() + interval '30 days')",
        (instance, server_id),
    )

import console_fixtures
import ctl_fixtures
import pytest

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
stub = console_fixtures.stub
world = console_fixtures.world


@pytest.fixture
def admin(world):
    return world.session_client("admin")

"""verify run 명령: 시험 전용 키가 아니면 호출을 보내기 전에 거부한다."""

import pytest

from .test_cli import Cli, bootstrap

pytest.importorskip("psycopg")


@pytest.fixture
def mint(fresh_db, stub, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Cli(fresh_db, stub.url, capsys, tmp_path)


def test_a_key_without_the_verify_name_is_refused(mint, tmp_path):
    token = bootstrap(mint)
    key_file = tmp_path / "key.txt"
    key_file.write_text("sk-not-a-verify-key\n", encoding="utf-8")
    code, out, err = mint.run("verify", "run", "--server", "srv", "--key-file", str(key_file),
                              token=token)
    assert code == 1 and "mint-verify-" in err and not out

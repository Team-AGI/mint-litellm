"""PC 명령의 도움말·인자 오류·키트 없음 안내."""

import json

import pytest

from mint_litellm.endpoint.kit import mint_kit


def test_global_options_before_a_user_command_still_reach_that_command(monkeypatch):
    seen = {}
    monkeypatch.setattr(mint_kit, "cli_main", lambda argv: seen.setdefault("argv", argv) and 0)
    mint_kit.main(["--kit", "/x", "requests"])
    assert seen["argv"] == ["--kit", "/x", "requests"]
    assert mint_kit.first_word(["--home", "/h", "--json", "status"]) == "status"
    assert mint_kit.first_word(["--", "add"]) is None


def test_top_help_lists_staff_and_admin_commands(capsys):
    assert mint_kit.main(["--help"]) == 0
    text = capsys.readouterr().out
    for word in ("add <주소>", "requests", "app new", "relink", "install", "check"):
        assert word in text


def test_argument_errors_are_korean_and_point_to_help(capsys):
    with pytest.raises(SystemExit) as stop:
        mint_kit.main(["app", "new"])
    assert stop.value.code == 2
    err = capsys.readouterr().err
    assert "필요한 값이 빠졌습니다: name" in err and "도움말: mint app new --help" in err


def test_a_missing_kit_is_explained_not_a_traceback(tmp_path, capsys):
    assert (
        mint_kit.main(["status", "--kit", str(tmp_path), "--user-level", "--home", str(tmp_path)])
        == 2
    )
    assert "설치 명령" in capsys.readouterr().err
    assert mint_kit.main(["status", "--json", "--kit", str(tmp_path), "--home", str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "kit_missing"

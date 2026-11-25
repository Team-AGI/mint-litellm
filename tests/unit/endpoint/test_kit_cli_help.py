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


def test_top_help_is_grouped_and_lists_new_and_old_commands(capsys):
    assert mint_kit.main(["--help"]) == 0
    text = capsys.readouterr().out
    for group in ("자주 쓰는 일", "앱 자격", "설치·유지", "예시"):
        assert group in text
    for word in ("server add <주소>", "request list", "app new|list|remove", "link <설치 주소>",
                 "doctor", "config list", "install", "옛 명령"):  # fmt: skip
        assert word in text
    assert text.count("\n  mint ") == 3  # 예시 3개


def test_every_command_help_has_description_usage_options_and_examples(capsys):
    for words in (["server"], ["server", "add"], ["server", "list"], ["request", "access"],
                  ["request", "show"], ["app", "run"], ["config", "list"], ["link"]):  # fmt: skip
        with pytest.raises(SystemExit) as stop:
            mint_kit.cli_main([*words, "--help"])
        assert stop.value.code == 0
        text = capsys.readouterr().out
        assert text.index("사용법:") < text.index("옵션:") < text.index("예시:"), words
        assert "show this help" not in text and "options:" not in text


def test_every_add_option_has_a_korean_description(capsys):
    with pytest.raises(SystemExit):
        mint_kit.cli_main(["server", "add", "--help"])
    text = capsys.readouterr().out
    for flag in ("--grade", "--ro", "--rw", "--request-id", "--yes", "--json"):
        line = next(line for line in text.splitlines() if line.strip().startswith(flag))
        assert any("가" <= ch <= "힣" for ch in line), flag


def test_argument_errors_are_two_korean_lines_with_an_example(capsys):
    with pytest.raises(SystemExit) as stop:
        mint_kit.main(["server", "show"])
    assert stop.value.code == 2
    assert capsys.readouterr().err.splitlines() == [
        "오류: 서버 이름이 필요합니다.", "예: mint server show github_mcp"]
    with pytest.raises(SystemExit):
        mint_kit.main(["app", "new"])
    assert capsys.readouterr().err.splitlines() == [
        "오류: 이름이 필요합니다.", "예: mint app new my-bot"]


def test_unknown_options_and_commands_point_to_the_help(capsys):
    assert mint_kit.main(["server", "add", "--bogus"]) == 2
    assert capsys.readouterr().err.splitlines() == [
        "오류: `--bogus`는 없는 옵션입니다.", "다음: mint server add --help"]
    with pytest.raises(SystemExit) as stop:
        mint_kit.main(["server", "frobnicate"])
    assert stop.value.code == 2
    assert capsys.readouterr().err.splitlines() == [
        "오류: `frobnicate`는 없는 명령입니다.", "다음: mint server --help"]
    with pytest.raises(SystemExit):
        mint_kit.main(["frobnicate"])
    assert "다음: mint --help" in capsys.readouterr().err


def test_usage_errors_are_json_on_stderr_in_json_mode(capsys):
    with pytest.raises(SystemExit):
        mint_kit.main(["server", "show", "--json"])
    seen = capsys.readouterr()
    assert seen.out == ""
    assert json.loads(seen.err)["error"] == {
        "code": "usage", "message": "서버 이름이 필요합니다.",
        "next": "mint server show github_mcp"}  # fmt: skip


def test_a_missing_kit_is_explained_not_a_traceback(tmp_path, capsys):
    where = ["--kit", str(tmp_path), "--home", str(tmp_path)]
    assert mint_kit.main(["status", *where, "--user-level"]) == mint_kit.EXIT_LINK
    assert capsys.readouterr().err.splitlines() == [
        "오류: MINT가 이 PC에 설치돼 있지 않습니다.",
        "다음: 직원 화면 「내 PC」에서 설치 명령을 만들어 붙여 넣으십시오."]
    assert mint_kit.main(["status", "--json", *where]) == mint_kit.EXIT_LINK
    seen = capsys.readouterr()
    assert seen.out == "" and json.loads(seen.err)["error"]["code"] == "not_installed"
    for words in (["server", "list"], ["doctor"], ["config", "list"], ["requests"]):
        assert mint_kit.main([*words, "--kit", str(tmp_path)]) == mint_kit.EXIT_LINK
        assert "MINT가 이 PC에 설치돼 있지 않습니다" in capsys.readouterr().err

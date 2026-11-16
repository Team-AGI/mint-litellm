"""명령줄 오류는 한국어로, 파이썬 추적 정보 없이 나온다."""

import pytest

from mint_litellm import cli


def test_argument_errors_are_in_korean(capsys):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["settings", "mode", "bogus"], environ={})
    err = capsys.readouterr().err
    assert stopped.value.code == 2
    assert "사용법:" in err and "오류:" in err and "쓸 수 없는 값 'bogus'" in err
    assert "error:" not in err and "invalid choice" not in err


def test_a_missing_import_file_is_reported_without_a_traceback(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_command", lambda args, environ: open(tmp_path / "없음.json"))
    assert cli.main(["config", "import", str(tmp_path / "없음.json")], environ={}) == 1
    err = capsys.readouterr().err
    assert "파일이 없습니다" in err and "Traceback" not in err

"""실행 계약 변경의 축별 분류와 경보 요약."""

from mint_litellm.control import exec_drift
from mint_litellm.types.exec_contract import ExecContract

BASE = ExecContract(
    executable="/usr/bin/node", argv=("/opt/srv/index.js", "--mode=fast"), cwd="/opt/srv",
    executable_sha256="ab" * 32, env={"API": "https://api.example.com/v1"},
).document()


def verdicts(new: dict, old: dict = BASE) -> dict:
    return {a: r["verdict"] for a, r in exec_drift.classify(old, new).items()}


def test_identical_contracts_are_unchanged_on_every_axis():
    assert set(verdicts(dict(BASE)).values()) == {"unchanged"}


def test_a_new_path_argument_widens_file_access_only():
    new = {**BASE, "argv": (*BASE["argv"], "/etc/passwd")}
    assert verdicts(new) == {"file": "widened", "exec": "unchanged", "network": "unchanged"}


def test_a_dropped_working_directory_widens_file_access():
    assert verdicts({**BASE, "cwd": None})["file"] == "widened"


def test_a_changed_executable_hash_widens_execution():
    new = {**BASE, "executable_sha256": "cd" * 32}
    assert verdicts(new) == {"file": "unchanged", "exec": "widened", "network": "unchanged"}


def test_a_new_option_or_secret_reference_widens_execution():
    assert verdicts({**BASE, "argv": (*BASE["argv"], "--unsafe")})["exec"] == "widened"
    assert verdicts({**BASE, "secret_refs": {"TOKEN": "ref-1"}})["exec"] == "widened"


def test_a_new_remote_address_widens_network_only():
    new = {**BASE, "env": {**BASE["env"], "HOOK": "http://other.example.net:8080/x"}}
    assert verdicts(new) == {"file": "unchanged", "exec": "unchanged", "network": "widened"}


def test_a_changed_address_is_widening_and_lists_the_new_one():
    new = {**BASE, "env": {"API": "https://evil.example.org/v1"}}
    r = exec_drift.classify(BASE, new)
    assert r["network"]["verdict"] == "widened"
    assert r["network"]["added"] == ["https://evil.example.org/v1"]
    assert r["network"]["removed"] == ["https://api.example.com/v1"]


def test_removing_items_only_narrows():
    new = {**BASE, "argv": ("/opt/srv/index.js",), "env": {}}
    assert verdicts(new) == {"file": "unchanged", "exec": "narrowed", "network": "narrowed"}
    assert exec_drift.widened_axes(exec_drift.classify(BASE, new)) == []


def test_combined_widening_lists_all_axes_in_the_alert_text():
    new = {
        **BASE, "cwd": None, "argv": (*BASE["argv"], "--x"),
        "env": {"API": "https://api.example.com/v1", "B": "ftp://z.example.com"},
    }
    r = exec_drift.classify(BASE, new)
    assert exec_drift.widened_axes(r) == ["file", "exec", "network"]
    text = exec_drift.summary(r)
    assert "파일 접근 확대: 작업 디렉터리 제한 없음" in text
    assert "실행 확대: 인자 --x" in text
    assert "네트워크 확대: ftp://z.example.com" in text


def test_summary_marks_narrowing_and_no_change():
    assert exec_drift.summary(exec_drift.classify(BASE, dict(BASE))) == "권한 변화 없음"
    narrowed = {**BASE, "argv": ("/opt/srv/index.js",)}
    assert exec_drift.summary(exec_drift.classify(BASE, narrowed)) == "실행 축소"


def _declared(*entries):
    return ExecContract(
        executable="/usr/bin/node", executable_sha256="ab" * 32,
        file_access=[{"path": p, "mode": m} for p, m in entries],
    ).document()


def test_a_new_declared_path_widens_file_access_only():
    old = _declared(("/data", "ro"))
    new = _declared(("/data", "ro"), ("/home/u/.ssh", "ro"))
    assert verdicts(new, old) == {"file": "widened", "exec": "unchanged", "network": "unchanged"}
    assert "/home/u/.ssh" in exec_drift.summary(exec_drift.classify(old, new))


def test_a_declared_path_going_from_read_to_read_write_widens_and_back_narrows():
    ro, rw = _declared(("/data", "ro")), _declared(("/data", "rw"))
    assert verdicts(rw, ro)["file"] == "widened"
    assert verdicts(ro, rw)["file"] == "narrowed"
    assert verdicts(ro, ro)["file"] == "unchanged"


def test_dropping_a_declared_path_narrows_and_declaring_none_to_some_widens():
    assert verdicts(_declared(), _declared(("/data", "ro")))["file"] == "narrowed"
    assert verdicts(_declared(("/data", "ro")), _declared())["file"] == "widened"


def test_network_none_to_any_widens_the_network_axis_and_back_narrows_it():
    closed = {**BASE, "network": "none"}
    opened = {**BASE, "network": "any"}
    assert exec_drift.classify(closed, opened)["network"]["verdict"] == "widened"
    assert exec_drift.classify(opened, closed)["network"]["verdict"] == "narrowed"
    # 선언이 없는 이전 계약은 any와 같다.
    assert exec_drift.classify(BASE, opened)["network"]["verdict"] == "unchanged"
    assert exec_drift.classify(BASE, closed)["network"]["verdict"] == "narrowed"

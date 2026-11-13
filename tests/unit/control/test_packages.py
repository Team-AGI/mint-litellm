"""실행 계약에서 패키지 뽑기: 생태계별 고정·미고정, 제공처, 패키지 변화."""

import pytest

from mint_litellm.control import exec_drift, packages

SHA = "a" * 64
DIGEST = "sha256:" + "b" * 64


def doc(executable, *argv):
    return {"executable": executable, "argv": list(argv), "executable_sha256": SHA}


def pkgs(executable, *argv):
    return [p for p in packages.extract(doc(executable, *argv)) if p.ecosystem != "executable"]


@pytest.mark.parametrize(
    ("argv", "name", "version", "pinned"),
    [
        (("-y", "@scope/pkg@1.2.3", "--flag"), "@scope/pkg", "1.2.3", True),
        (("-y", "pkg@2.0.0-beta.1"), "pkg", "2.0.0-beta.1", True),
        (("-y", "pkg"), "pkg", None, False),
        (("pkg@latest",), "pkg", "latest", False),
        (("pkg@^1.2.0",), "pkg", "^1.2.0", False),
        (("--package=real@3.1.4", "cmd"), "real", "3.1.4", True),
    ],
)
def test_npx_specs(argv, name, version, pinned):
    [p] = pkgs("/usr/bin/npx", *argv)
    assert (p.ecosystem, p.name, p.version, p.pinned) == ("npm", name, version, pinned)
    assert p.registry == "registry.npmjs.org"


def test_npm_exec_pnpm_dlx_and_bunx_and_a_private_registry():
    assert pkgs("/usr/bin/npm", "exec", "--", "x@1.0.0")[0].name == "x"
    assert pkgs("/usr/bin/pnpm", "dlx", "x@1.0.0")[0].pinned
    assert pkgs(r"C:\tools\bunx.exe", "x@1.0.0")[0].name == "x"
    [p] = pkgs("/usr/bin/npx", "--registry", "https://npm.example.org/", "x@1.0.0")
    assert p.registry == "npm.example.org"


def test_a_source_spec_is_pinned_only_by_a_commit():
    assert not pkgs("/usr/bin/npx", "github:user/repo")[0].pinned
    p = pkgs("/usr/bin/npx", "github:user/repo#abcdef1234")[0]
    assert p.pinned and p.registry == "github"


@pytest.mark.parametrize(
    ("exe", "argv", "name", "version", "pinned"),
    [
        ("/u/uvx", ("mcp-server-fetch",), "mcp-server-fetch", None, False),
        ("/u/uvx", ("mcp-server-fetch@1.2.3",), "mcp-server-fetch", "1.2.3", True),
        ("/u/uvx", ("pkg@latest",), "pkg", "latest", False),
        ("/u/uvx", ("--from", "foo==1.0.0", "foocmd"), "foo", "1.0.0", True),
        ("/u/uvx", ("--with", "extra", "foo>=1.0"), "foo", ">=1.0", False),
        ("/u/pipx", ("run", "--spec", "foo[x]==2.0", "foocmd"), "foo", "2.0", True),
        ("/u/pipx", ("run", "foo==1.*"), "foo", "1.*", False),
        ("/u/uv", ("tool", "run", "foo==3.0"), "foo", "3.0", True),
    ],
)
def test_pypi_specs(exe, argv, name, version, pinned):
    [p] = pkgs(exe, *argv)
    assert (p.ecosystem, p.name, p.version, p.pinned) == ("pypi", name, version, pinned)
    assert p.registry == "pypi.org"


def test_python_module_runs_have_no_known_version():
    [p] = pkgs("/usr/bin/python3", "-m", "mcp_thing")
    assert (p.name, p.version, p.pinned, p.registry) == ("mcp_thing", None, False, "local")


@pytest.mark.parametrize(
    ("argv", "name", "version", "pinned", "registry"),
    [
        (("run", "-i", "--rm", "-e", "A=b", "ghcr.io/o/img:1.2", "arg"),
         "ghcr.io/o/img", "1.2", True, "ghcr.io"),
        (("run", "--rm", "img@" + DIGEST), "img", DIGEST, True, "docker.io"),
        (("run", "img"), "img", None, False, "docker.io"),
        (("run", "o/img:latest"), "o/img", "latest", False, "docker.io"),
        (("run", "-v", "/a:/b", "localhost:5000/x:2"), "localhost:5000/x", "2", True,
         "localhost:5000"),
    ],
)
def test_container_images(argv, name, version, pinned, registry):
    [p] = pkgs("/usr/bin/docker", *argv)
    assert (p.ecosystem, p.name, p.version, p.pinned, p.registry) == (
        "container", name, version, pinned, registry)


def test_the_executable_hash_is_always_recorded_and_unknown_forms_add_nothing():
    found = packages.extract(doc("/opt/server", "--stdio"))
    assert [(p.ecosystem, p.version) for p in found] == [("executable", SHA)]
    assert packages.unpinned(found) == []
    assert packages.unpinned(packages.extract(doc("/usr/bin/npx", "x")))[0].name == "x"


def test_changes_name_a_version_move_a_new_package_and_an_executable_swap():
    old = doc("/usr/bin/npx", "x@1.0.0")
    assert packages.changes(old, old) == []
    assert packages.changes(old, doc("/usr/bin/npx", "x@1.1.0")) == ["패키지 x 1.0.0 → 1.1.0"]
    assert packages.changes(old, doc("/usr/bin/npx", "y@1.0.0")) == [
        "새 패키지 y 1.0.0(registry.npmjs.org)", "패키지 제외 x"]
    swapped = dict(old, executable_sha256="c" * 64)
    assert packages.changes(old, swapped) == ["실행 파일 내용 변경"]


def test_the_exec_drift_summary_names_the_package_change():
    old, new = doc("/usr/bin/npx", "x@1.0.0"), doc("/usr/bin/npx", "x@1.1.0")
    result = exec_drift.classify(old, new)
    text = exec_drift.summary(result, packages.changes(old, new))
    assert "패키지 x 1.0.0 → 1.1.0" in text and "실행 확대" in text

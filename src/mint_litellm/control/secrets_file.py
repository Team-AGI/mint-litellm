"""저장소 밖 비밀 파일. 호출별 승인의 인자 지문 키를 한 번만 생성해 둔다."""

import os
import secrets
import stat
from collections.abc import Mapping
from pathlib import Path

from mint_litellm.control.errors import ControlError

KEY_NAME = "MINT_FINGERPRINT_KEY"
VERSION_NAME = "MINT_FINGERPRINT_KEY_VERSION"
DEFAULT_PATH = "~/.config/mint/secrets.env"


def new_key() -> str:
    """무작위 32바이트의 base64url 문자열."""
    return secrets.token_urlsafe(32)


def _loose(mode: int) -> bool:
    return os.name != "nt" and bool(mode & 0o022)


def _read_private(path: Path) -> str:
    """비밀 파일을 읽는다.

    마지막 디렉터리와 파일의 심볼릭 링크는 따르지 않고, 열린 디렉터리 기술자의 권한이 다른 사용자가
    쓸 수 있으면 거부하며, 그 디렉터리 기술자 기준으로 연 파일 기술자의 권한이 0600이 아니면
    거부한다. 읽기와 디코딩 오류는 ``ControlError``로 바꾼다.
    """
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_fd = None
    try:
        if os.name == "nt":
            descriptor = os.open(path, os.O_RDONLY)
        else:
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | nofollow)
            if _loose(os.fstat(directory_fd).st_mode):
                raise ControlError(
                    f"비밀 파일의 디렉터리 {path.parent}를 다른 사용자가 쓸 수 있습니다. "
                    "권한을 0700으로 고치십시오(자동으로 고치지 않습니다)."
                )
            descriptor = os.open(path.name, os.O_RDONLY | nofollow, dir_fd=directory_fd)
    except OSError as error:
        raise ControlError(
            f"비밀 파일 {path}을(를) 열 수 없습니다(심볼릭 링크는 허용하지 않습니다): {error}"
        ) from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            if os.name != "nt" and stat.S_IMODE(os.fstat(handle.fileno()).st_mode) != 0o600:
                raise ControlError(
                    f"비밀 파일 {path}의 권한이 0600이 아닙니다. 키가 노출되었을 수 있으니 권한을 "
                    "0600으로 고치고 키 노출 여부를 확인하십시오(자동으로 고치지 않습니다)."
                )
            return handle.read()
    except (OSError, UnicodeDecodeError) as error:
        raise ControlError(f"비밀 파일 {path}을(를) 읽을 수 없습니다: {error}") from None


def reserve_private(path: Path) -> None:
    """없는 파일을 0600으로 비워 둔 채 만든다. 이미 있으면 덮어쓰지 않고 거부한다."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except FileExistsError:
        raise ControlError(
            f"{path}이(가) 이미 있어 덮어쓰지 않습니다. 다른 경로를 쓰십시오."
        ) from None
    except OSError as error:
        raise ControlError(f"{path}을(를) 만들 수 없습니다: {error}") from None


def fill_private(path: Path, text: str) -> None:
    """``reserve_private``로 만든 파일에 한 줄을 쓴다."""
    try:
        path.write_text(text + "\n", encoding="utf-8", newline="\n")
    except OSError as error:
        raise ControlError(f"{path}을(를) 쓸 수 없습니다: {error}") from None


def _parse(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        name, sep, value = line.partition("=")
        if sep and not line.lstrip().startswith("#"):
            found[name.strip()] = value.strip()
    return found


def _check_existing(path: Path) -> bool:
    """이미 있는 파일을 검사한다. 키가 있으면 True, 권한이 0600이 아니거나 키가 없으면 실패한다."""
    if not _parse(_read_private(path)).get(KEY_NAME):
        raise ControlError(
            f"비밀 파일 {path}에 {KEY_NAME}가 없습니다. 파일을 덮어쓰지 않으므로 키를 직접 "
            "추가하거나 파일을 지운 뒤 다시 실행하십시오."
        )
    return True


def _prepare_directory(directory: Path) -> None:
    """디렉터리가 없으면 0700으로 만들고, 있으면(동시에 만들어진 경우 포함) 쓰기 권한만 확인한다."""
    if directory.is_symlink():
        raise ControlError(f"비밀 파일의 디렉터리 {directory}가 심볼릭 링크입니다.")
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    if _loose(directory.stat().st_mode):
        raise ControlError(
            f"비밀 파일의 디렉터리 {directory}를 다른 사용자가 쓸 수 있습니다. "
            "권한을 0700으로 고치십시오(자동으로 고치지 않습니다)."
        )


def ensure_fingerprint_key(path: Path) -> bool:
    """파일이 없을 때만 무작위 32바이트(base64url) 키를 만들어 0600 파일로 게시하고 True를 돌려준다.

    내용을 임시 파일에 다 쓴 뒤 하드 링크로 게시하므로 동시에 실행된 쪽 가운데 한 곳만 만들고,
    나머지는 완성된 파일을 읽기만 한다. 이미 있는 파일은 덮어쓰지 않는다. 파일을 마운트한
    디렉터리의 소유자에게 소유권을 넘겨 컨테이너 밖의 사용자가 읽을 수 있게 한다.
    """
    path = path.expanduser()
    if os.path.lexists(path):
        _check_existing(path)
        return False
    _prepare_directory(path.parent)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(
                f"{KEY_NAME}={new_key()}\n{VERSION_NAME}=1\n"
            )
            output.flush()
            os.fsync(output.fileno())
        try:
            owner = path.parent.stat()
            os.chown(temp, owner.st_uid, owner.st_gid)
        except (AttributeError, OSError):
            pass  # 소유자를 넘길 수 없는 환경(권한 부족, Windows)에서는 그대로 둔다.
        try:
            os.link(temp, path)
        except FileExistsError:
            _check_existing(path)
            return False
    finally:
        temp.unlink(missing_ok=True)
    return True


def load_fingerprint_key(environ: Mapping[str, str], path: Path | None = None) -> tuple[str, int]:
    """환경 변수, 없으면 비밀 파일에서 지문 키 문자열과 키 판본을 읽는다."""
    key, version, _ = load_fingerprint_key_with_source(environ, path)
    return key, version


def load_fingerprint_key_with_source(
    environ: Mapping[str, str], path: Path | None = None
) -> tuple[str, int, str]:
    """키, 키 판본과 읽은 곳(``environment`` 또는 비밀 파일 경로)."""
    key = environ.get(KEY_NAME)
    version = environ.get(VERSION_NAME)
    source = "environment"
    if not key:
        file = (path or Path(environ.get("MINT_SECRETS_FILE") or DEFAULT_PATH)).expanduser()
        if os.path.lexists(file):
            values = _parse(_read_private(file))
            key, version = values.get(KEY_NAME), version or values.get(VERSION_NAME)
            source = file.as_posix()
    if not key:
        raise ControlError(
            f"인자 지문 키({KEY_NAME})를 찾을 수 없습니다. init으로 키를 만들거나 "
            "--args-fp에 계산된 지문을 직접 넣으십시오."
        )
    try:
        return key, int(version or 1), source
    except ValueError:
        raise ControlError(f"{VERSION_NAME}가 정수가 아닙니다.") from None

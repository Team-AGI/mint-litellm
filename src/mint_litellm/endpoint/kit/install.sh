#!/usr/bin/env bash
# MINT 단말 설치 묶음: 이 파일 하나를 실행하면 설치된다. 관리자 권한은 한 번만 쓴다.
# 사용: ./install.sh [install|uninstall|status] [--user-level] [--dry-run]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$(command -v python3 || true)"
[[ -n $PYTHON ]] || { echo "Python 3.9 이상이 필요합니다." >&2; exit 2; }
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 9))' ||
  { echo "Python 3.9 이상이 필요합니다." >&2; exit 2; }

user_level=0
for arg in "$@"; do [[ $arg == --user-level || $arg == --dry-run ]] && user_level=1; done
if [[ ${EUID} -eq 0 || $user_level -eq 1 ]]; then
  exec "$PYTHON" -I -B "$HERE/mint_kit.py" "$@"
fi
# 비밀번호 없이 관리자 권한이 되면 그대로 쓰고, 사람이 터미널에 있으면 sudo가 직접 묻게 한다.
# 둘 다 아니면 관리자 권한 없이 사용자 수준으로 설치한다(MINT에는 「관리되지 않음」으로 보고된다).
if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
  exec sudo -n "$PYTHON" -I -B "$HERE/mint_kit.py" "$@"
elif command -v sudo >/dev/null && [[ -t 0 ]]; then
  exec sudo -p "관리자 권한 확인 - %u 비밀번호: " "$PYTHON" -I -B "$HERE/mint_kit.py" "$@"
fi
echo "관리자 권한을 얻을 수 없어 사용자 수준으로 설치합니다." >&2
exec "$PYTHON" -I -B "$HERE/mint_kit.py" "$@" --user-level

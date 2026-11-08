#!/usr/bin/env bash
# 장비에서 실행: 합격 시험 pytest 한 번(1~13 전부). 사용: run.sh <증거 이름> [pytest 추가 인자...]
set -uo pipefail
NAME=${1:?증거 이름}; shift
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
export ACC_HOME=${ACC_HOME:-$HOME/mint-s2}
source "$HERE/env.sh"
cd "$REPO"
export ACC_DS183=${ACC_DS183:-1}
export ACC_STEADY_SECONDS=${ACC_STEADY_SECONDS:-1800}
python -m pytest tests/acceptance/stage2 --stage2-live --stage2-site "$ACC_SITE" \
  --stage2-evidence "tests/acceptance/stage2/evidence/$NAME" --stage2-required \
  -p no:cacheprovider -rA -q --junitxml="$ACC_HOME/$NAME.junit.xml" "$@" > "$ACC_HOME/$NAME.log" 2>&1
echo "exit=$?" >> "$ACC_HOME/$NAME.log"

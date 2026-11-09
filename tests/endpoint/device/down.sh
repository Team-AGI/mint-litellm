#!/usr/bin/env bash
# 엔드포인트 탐색 스택을 내리고 볼륨·상태·.env를 지운다. 이 스택의 프로젝트 이름만 건드린다.
set -euo pipefail
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-mintep}
case "$COMPOSE_PROJECT_NAME" in
  mint|mints2|mints3|mint-manual|mint-g10) echo "다른 스택의 프로젝트 이름입니다" >&2; exit 2 ;;
esac
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
export EP_STATE=${EP_HOME:-$HOME/mint-ep} EP_PUBLIC_URL=${EP_PUBLIC_URL:-http://localhost}
cd "$REPO/deploy"
docker compose --env-file .env -f compose.yaml -f "$HERE/ep.yaml" --profile tools down -v --remove-orphans
docker image rm "mint-litellm:$COMPOSE_PROJECT_NAME" >/dev/null 2>&1 || true
rm -rf "$EP_STATE" .env config/litellm.mint.yaml
echo down-done

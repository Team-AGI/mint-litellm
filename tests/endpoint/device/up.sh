#!/usr/bin/env bash
# 솔루션 기기에서 실행하는 엔드포인트 탐색 전용 스택: postgres, opa, litellm 하나. 작업 실행기·콘솔은 띄우지 않는다.
# 프로젝트 이름·포트·볼륨·키는 다른 스택과 분리한다. 메인이 「시작해도 됨」을 알리기 전에는 실행하지 않는다.
# 사용: EP_PUBLIC_URL=http://<기기 주소>:4500 bash up.sh   (이 저장소 복제본의 tests/endpoint/device/)
set -euo pipefail
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-mintep}
case "$COMPOSE_PROJECT_NAME" in
  mint|mints2|mints3|mint-manual|mint-g10) echo "다른 스택의 프로젝트 이름입니다: $COMPOSE_PROJECT_NAME" >&2; exit 2 ;;
esac
PORT=${EP_PORT:-4500}
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
export EP_STATE=${EP_HOME:-$HOME/mint-ep}
: "${EP_PUBLIC_URL:?EP_PUBLIC_URL를 정하십시오(예: http://기기주소:$PORT)}"
export EP_PUBLIC_URL
mkdir -p "$EP_STATE/endpoint" "$EP_STATE/secrets"
chmod 700 "$EP_STATE" "$EP_STATE/secrets"
# 기기 메모리 여유가 작다. 가용 메모리가 1.2GB 아래이면 멈춘다(EP_FORCE=1이면 건너뜀).
avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
if [ "${EP_FORCE:-0}" != 1 ] && [ "$avail" -lt 1200 ]; then
  echo "가용 메모리 ${avail}MB: 다른 시험 스택 상태를 확인하십시오." >&2; exit 3
fi
if ss -ltn "sport = :$PORT" | grep -q LISTEN; then echo "포트 $PORT 사용 중" >&2; exit 4; fi
rand() { head -c 24 /dev/urandom | base64 | tr -d '/+=\n' | head -c "${1:-32}"; }

cd "$REPO/deploy"
if [ ! -f .env ]; then
  cp .env.example .env
  for pair in POSTGRES_PASSWORD=$(rand 24) MINT_PLUGIN_DB_PASSWORD=$(rand 24) MINT_CONTROL_DB_PASSWORD=$(rand 24) \
              MINT_WORKER_DB_PASSWORD=$(rand 24) MINT_STAFF_DB_PASSWORD=$(rand 24) MINT_EXPORT_HMAC_KEY=$(rand 40) \
              LITELLM_MASTER_KEY=sk-ep-$(rand 32) MINT_INSTANCE_ID=endpoint MINT_LITELLM_PORT=$PORT \
              MINT_CONSOLE_PORT=$((PORT + 30)) MINT_SELFCHECK_GRACE_SECONDS=30 MINT_SECRETS_DIR=$EP_STATE/secrets; do
    k=${pair%%=*}; v=${pair#*=}
    sed -i "/^$k=/d" .env; printf '%s=%s\n' "$k" "$v" >> .env
  done
  chmod 600 .env
fi
mkdir -p config
[ -f config/litellm.config.yaml ] || cp litellm.config.example.yaml config/litellm.config.yaml
C=(docker compose --env-file .env -f compose.yaml -f "$HERE/ep.yaml")
env_value() { grep -E "^$1=" .env | head -n1 | cut -d= -f2-; }

"${C[@]}" build litellm
"${C[@]}" up -d --wait postgres
"${C[@]}" run --rm --no-deps -T --user 0 --entrypoint chown control -R 65532:65532 /var/lib/mint/export /bundles
"${C[@]}" run --rm --no-deps -T --user 0 --entrypoint chown litellm -R 65532:65532 /var/lib/mint/buffer
"${C[@]}" run --rm --no-deps -T --user 0 --entrypoint sh control -c 'chgrp -R 65532 /app/config && chmod -R g+rX /app/config'
env "MINT_DATABASE_URL=postgresql://postgres:$(env_value POSTGRES_PASSWORD)@postgres:5432/mint" \
    "MINT_PLUGIN_DB_PASSWORD=$(env_value MINT_PLUGIN_DB_PASSWORD)" "MINT_CONTROL_DB_PASSWORD=$(env_value MINT_CONTROL_DB_PASSWORD)" \
    "MINT_WORKER_DB_PASSWORD=$(env_value MINT_WORKER_DB_PASSWORD)" "MINT_STAFF_DB_PASSWORD=$(env_value MINT_STAFF_DB_PASSWORD)" \
  "${C[@]}" run --rm --no-deps -e MINT_DATABASE_URL -e MINT_PLUGIN_DB_PASSWORD -e MINT_CONTROL_DB_PASSWORD \
    -e MINT_WORKER_DB_PASSWORD -e MINT_STAFF_DB_PASSWORD control \
    init --out /app/config/litellm.mint.yaml --fix-config /app/config/litellm.config.yaml >/dev/null
"${C[@]}" run --rm --no-deps -T --entrypoint python control -c "
from pathlib import Path
from mint_litellm.plugin.policy.bundle import prepare_bundle, publish_bundle
target = Path('/bundles/mint.tar.gz')
if not target.exists():
    publish_bundle(target, prepare_bundle(Path('/opt/mint'), 'initial').archive)
"
# 승인 계약 파일이 있어야 결정 경로가 붙는다(없으면 기동을 거부한다). make_registry.py로 만들어 둔다.
[ -f "$EP_STATE/endpoint/registry.json" ] || { echo "$EP_STATE/endpoint/registry.json이 없습니다(make_registry.py)." >&2; exit 5; }
"${C[@]}" up -d opa litellm
for _ in $(seq 1 90); do curl -fs "http://localhost:$PORT/health/readiness" >/dev/null && echo up-done && exit 0; sleep 5; done
echo "준비 안 됨" >&2; exit 6

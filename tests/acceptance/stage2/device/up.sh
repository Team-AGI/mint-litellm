#!/usr/bin/env bash
# 솔루션 기기에서 실행하는 합격 시험 스택 기동(처음부터). 공개 MCP 스택(tests/oss/stack.sh up)이 먼저 떠 있어야 한다.
# 비밀은 이 스크립트가 만들어 deploy/.env와 ~/mint-s2/acc.env(0600)에만 둔다.
set -euo pipefail
export DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker-acc}
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-mints2}
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
STATE=${ACC_HOME:-$HOME/mint-s2}
cd "$REPO/deploy"
OVERLAY="$HERE/acc.yaml"
C=(docker compose --env-file .env -f compose.yaml -f "$OVERLAY")
wait_ready() { for _ in $(seq 1 90); do curl -fs "http://127.0.0.1:$1/health/readiness" >/dev/null && return 0; sleep 5; done; echo "준비 안 됨: $1" >&2; return 1; }
rand() { head -c 24 /dev/urandom | base64 | tr -d '/+=\n' | head -c "${1:-32}"; }

docker network inspect mint-g10_mcp >/dev/null
mkdir -p "$STATE"
# 계수 역프록시의 시험용 CA와 인증서(수용검증은 https만 받는다). LiteLLM 컨테이너는 이 CA만 신뢰한다.
export ACC_CERT_DIR="$STATE/certs"
bash "$HERE/certs.sh" "$ACC_CERT_DIR"
if [ ! -f .env ]; then
  cp .env.example .env
  for pair in POSTGRES_PASSWORD=$(rand 24) MINT_PLUGIN_DB_PASSWORD=$(rand 24) MINT_CONTROL_DB_PASSWORD=$(rand 24) \
              LITELLM_MASTER_KEY=sk-acc-$(rand 32) MINT_INSTANCE_ID=acceptance MINT_LITELLM_PORT=4300 \
              MINT_CONSOLE_PORT=4330 MINT_REPLICAS=2 MINT_LOG_LEVEL=DEBUG MINT_SELFCHECK_GRACE_SECONDS=30 MINT_SECRETS_DIR=$STATE/secrets; do
    k=${pair%%=*}; v=${pair#*=}
    sed -i "/^$k=/d" .env; printf '%s=%s\n' "$k" "$v" >> .env
  done
  chmod 600 .env
fi
mkdir -p config
cp "$HERE/litellm.config.yaml" config/litellm.config.yaml
cp "$HERE/litellm.plain.yaml" config/litellm.plain.yaml
# 내보내기 볼륨은 호스트 디렉터리에 바인드한다(어댑터가 파일을 직접 읽고 쓴다). 컨테이너 사용자가 쓰도록 777.
mkdir -p "$STATE/export" && chmod 777 "$STATE/export"
docker volume inspect "${COMPOSE_PROJECT_NAME}_export" >/dev/null 2>&1 ||   docker volume create --driver local --opt type=none --opt o=bind --opt "device=$STATE/export" "${COMPOSE_PROJECT_NAME}_export" >/dev/null
./mint.sh up
# mint.sh가 올린 LiteLLM의 최초 마이그레이션이 끝나기 전에 오버레이로 다시 만들면 마이그레이션이 끊긴다.
wait_ready "${MINT_LITELLM_PORT:-4300}" || wait_ready 4300
# mint.sh가 띄운 작업 실행기는 루트라 루트 소유 파일을 남긴다. 지우면 되돌림 탐지가 막으므로(쓰기 기록이 있는데
# 파일이 없음) 소유자만 바꾸고 오버레이(비루트) 작업 실행기로 다시 올린다.
"${C[@]}" --profile worker stop worker
IMG=mint-litellm:${COMPOSE_PROJECT_NAME}; docker image inspect "$IMG" >/dev/null 2>&1 || IMG=mint-litellm:local
docker run --rm -v "${COMPOSE_PROJECT_NAME}_export:/x" --entrypoint sh "$IMG" -c 'chown -R 1000:1000 /x' || true
"${C[@]}" up -d cnt fixture pgproxy
set -a; . ./.env; set +a
"${C[@]}" exec -T postgres psql -U postgres -d postgres -tc "SELECT 1 FROM pg_database WHERE datname='litellm_plain'" | grep -q 1 \
  || "${C[@]}" exec -T postgres psql -U postgres -d postgres -c "CREATE DATABASE litellm_plain"
# LiteLLM 복제본이 같은 DB에 동시에 마이그레이션하면 교착으로 마이그레이션 기록이 어긋나므로 하나씩 올린다.
"${C[@]}" up -d litellm
wait_ready 4300
"${C[@]}" up -d litellm2
wait_ready 4301
"${C[@]}" up -d litellm-plain
wait_ready 4310
echo up-done

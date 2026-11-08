# source로 읽는다. acc.json(비밀)·deploy/.env에서 시험 실행기 환경을 만든다. 값은 출력하지 않는다.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
STATE=${ACC_HOME:-$HOME/mint-s2}
getenv() { grep -E "^$1=" "$REPO/deploy/.env" | head -n1 | cut -d= -f2-; }
getjson() { python3 -c "import json,sys;print(json.load(open('$STATE/acc.json')).get('$1',''))"; }
export DOCKER_CONFIG=$HOME/.docker-acc COMPOSE_PROJECT_NAME=mints2
export PATH="$STATE/venv/bin:$PATH"
export ACC_CERT_DIR="$STATE/certs"
export ACC_COMPOSE="docker compose -p mints2 --env-file deploy/.env -f deploy/compose.yaml -f tests/acceptance/stage2/device/acc.yaml"
export ACC_DATABASE_URL="postgresql://postgres:$(getenv POSTGRES_PASSWORD)@127.0.0.1:4332/mint"
export MINT_DATABASE_URL="postgresql://mint_control_app:$(getenv MINT_CONTROL_DB_PASSWORD)@127.0.0.1:4332/mint"
export ACC_PLUGIN_DATABASE_URL="postgresql://mint_plugin_app:$(getenv MINT_PLUGIN_DB_PASSWORD)@127.0.0.1:4332/mint"
export ACC_STAFF_DATABASE_URL="postgresql://mint_staff_app:$(getenv MINT_STAFF_DB_PASSWORD)@127.0.0.1:4332/mint"
export MINT_EXPORT_DIR="$STATE/export"
export MINT_EXPORT_HMAC_KEY="$(getenv MINT_EXPORT_HMAC_KEY)" MINT_INSTANCE_ID=acceptance
export MINT_LITELLM_URL=http://127.0.0.1:4300 ACC_LITELLM_ADMIN_URL=http://127.0.0.1:4300
export MINT_LITELLM_KEY="$(getjson ACC_CONTROL_KEY)" ACC_CONTROL_KEY="$(getjson ACC_CONTROL_KEY)"
export ACC_CALLER_KEY="$(getjson ACC_CALLER_KEY)" ACC_SUBMIT_KEY="$(getjson ACC_SUBMIT_KEY)"
export ACC_LITELLM_ADMIN_KEY="$(getenv LITELLM_MASTER_KEY)"
export ACC_ADMIN_TOKEN="$(getjson ACC_ADMIN_TOKEN)" ACC_APPROVER_TOKEN="$(getjson ACC_APPROVER_TOKEN)" ACC_ADMIN2_TOKEN="$(getjson ACC_ADMIN2_TOKEN)"
export ACC_PG_SERVICE=postgres ACC_PG_SUPERUSER=postgres ACC_FIXTURE_URL=http://127.0.0.1:4340 ACC_SERVER_ID=synthetic
export ACC_EXPORT_HOST_DIR="$STATE/export" ACC_EXPORT_CONTAINER_DIR=/var/lib/mint/export ACC_STATE_DIR="$STATE/state"
export ACC_READY_URLS=http://127.0.0.1:4300,http://127.0.0.1:4301 ACC_RESTORE_SERVICES="litellm litellm2 worker console"
export ACC_PLUGIN_SERVICES="litellm litellm2 worker" ACC_BUFFER_SERVICE=litellm ACC_BUFFER_CONTAINER_DIR=/var/lib/mint/buffer
export MINT_POLICY_ROOT="$REPO" ACC_SITE="$REPO/tests/acceptance/stage2/.runtime/site.json"
mkdir -p "$ACC_STATE_DIR"
[ -f "$STATE/local.env" ] && . "$STATE/local.env"

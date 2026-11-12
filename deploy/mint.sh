#!/usr/bin/env bash
# MINT 배포 보조 스크립트: up | status | backup | upgrade | cli
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE=(docker compose --env-file .env -f compose.yaml)
BUNDLE_FILE=/bundles/mint.tar.gz

fail() { echo "$*" >&2; exit 1; }

# 설정되지 않은 키는 빈 값이다(이전 .env에는 없는 키가 있다).
env_value() {
    grep -E "^$1=" .env | head -n1 | cut -d= -f2- || true
}

# .env 끝에 개행이 없으면 덧붙인 값이 마지막 줄에 붙어 버리므로 개행을 먼저 보장한다.
append_env() {
    if [ -s .env ] && [ -n "$(tail -c 1 .env)" ]; then
        printf '\n' >> .env
    fi
    printf '%s=%s\n' "$1" "$2" >> .env
}

# 인자 지문 키는 저장소 밖 비밀 파일에 둔다. 디렉터리(0700)만 준비하고, 파일과 키는 init이 만든다.
ensure_secrets() {
    local dir
    dir="$(env_value MINT_SECRETS_DIR)"
    if [ -z "$dir" ]; then
        dir="$HOME/.config/mint"
        sed -i '/^MINT_SECRETS_DIR=/d' .env
        append_env MINT_SECRETS_DIR "$dir"
    fi
    mkdir -p "$dir"
    chmod 700 "$dir"
}

# 직원 화면의 단말 설치 묶음이 사용자 키를 발급할 때 쓰는 LiteLLM 키(/key/generate, /key/delete만 연 키).
# 비밀 폴더에 없을 때만 마스터 키로 한 번 만들어 두고, 있으면 그대로 콘솔에 넘긴다.
# 만들지 못해도 기동은 계속하며(묶음 내려받기만 막힌다) 다음 up·upgrade가 다시 시도한다.
KIT_ISSUER_SCRIPT=$(cat <<'PY'
import json, os, secrets, sys, time, urllib.error, urllib.request
base = "http://litellm:4000"
headers = {"Authorization": "Bearer " + os.environ["LITELLM_MASTER_KEY"],
           "Content-Type": "application/json"}


def post(path, body):
    request = urllib.request.Request(base + path, json.dumps(body).encode(), headers, method="POST")
    with urllib.request.urlopen(request, timeout=10) as reply:
        return json.loads(reply.read() or b"{}")


deadline = time.time() + 120
while True:
    try:
        try:
            post("/user/new", {"user_id": "mint-kit-issuer", "user_role": "proxy_admin",
                               "auto_create_key": False})
        except urllib.error.HTTPError:
            pass  # 이미 있는 사용자
        print(post("/key/generate", {
            "user_id": "mint-kit-issuer",
            "key_alias": "mint-kit-issuer-" + secrets.token_hex(4),
            "allowed_routes": ["/key/generate", "/key/delete"],
        })["key"])
        break
    except urllib.error.HTTPError:
        sys.exit(1)
    except OSError:
        if time.time() > deadline:
            sys.exit(1)
        time.sleep(3)
PY
)

ensure_kit_issuer_key() {
    local file key
    file="$(env_value MINT_SECRETS_DIR)/kit_issuer.key"
    if [ ! -s "$file" ]; then
        key="$(env "LITELLM_MASTER_KEY=$(env_value LITELLM_MASTER_KEY)"             "${COMPOSE[@]}" run --rm --no-deps -T -e LITELLM_MASTER_KEY             --entrypoint python control -c "$KIT_ISSUER_SCRIPT" | tail -n 1)" || key=""
        if [[ "$key" =~ ^sk-[A-Za-z0-9_-]+$ ]]; then
            (umask 077; printf '%s
' "$key" > "$file")
        else
            echo "단말 설치 묶음 키를 만들지 못했습니다. 다음 up·upgrade에서 다시 시도합니다." >&2
            return 0
        fi
    fi
    MINT_KIT_ISSUER_KEY="$(head -n 1 "$file")"
    export MINT_KIT_ISSUER_KEY
}

# 비밀값은 .env에 없거나 비어 있을 때만 새로 만든다(base64url, 무작위 32바이트). 이미 있는 값은 바꾸지 않는다.
random_secret() {
    head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'
}

ensure_generated() {
    local name
    for name in MINT_EXPORT_HMAC_KEY MINT_WORKER_DB_PASSWORD MINT_STAFF_DB_PASSWORD; do
        if [ -z "$(env_value "$name")" ]; then
            sed -i "/^${name}=/d" .env
            append_env "$name" "$(random_secret)"
        fi
    done
    chmod 600 .env
}

require_env() {
    [ -f .env ] || fail ".env가 없습니다. .env.example을 복사해 값을 채우십시오."
    ensure_secrets
    ensure_generated
}

# 관리자 권한(마이그레이션·역할 생성)이 필요한 명령은 슈퍼유저 접속으로 실행한다.
admin_cli() {
    # 비밀번호는 명령 인자가 아니라 환경으로 넘긴다(-e VAR는 호출한 쪽 환경에서 값을 상속한다).
    env \
        "MINT_DATABASE_URL=postgresql://postgres:$(env_value POSTGRES_PASSWORD)@postgres:5432/mint" \
        "MINT_PLUGIN_DB_PASSWORD=$(env_value MINT_PLUGIN_DB_PASSWORD)" \
        "MINT_CONTROL_DB_PASSWORD=$(env_value MINT_CONTROL_DB_PASSWORD)" \
        "MINT_WORKER_DB_PASSWORD=$(env_value MINT_WORKER_DB_PASSWORD)" \
        "MINT_STAFF_DB_PASSWORD=$(env_value MINT_STAFF_DB_PASSWORD)" \
        "${COMPOSE[@]}" run --rm --no-deps \
        -e MINT_DATABASE_URL -e MINT_PLUGIN_DB_PASSWORD -e MINT_CONTROL_DB_PASSWORD \
        -e MINT_WORKER_DB_PASSWORD -e MINT_STAFF_DB_PASSWORD \
        control "$@"
}

cli() {
    "${COMPOSE[@]}" run --rm control "$@"
}

# 정책 엔진은 번들 파일이 있어야 기동한다. 파일이 없으면 저장소의 기본 정책으로 첫 번들을 게시하고,
# 판본 등록과 활성화는 policy activate가 수행한다.
ensure_bundle() {
    "${COMPOSE[@]}" run --rm --no-deps -T --entrypoint python control -c "
from pathlib import Path
from mint_litellm.plugin.policy.bundle import prepare_bundle, publish_bundle
target = Path('${BUNDLE_FILE}')
if not target.exists():
    publish_bundle(target, prepare_bundle(Path('/opt/mint'), 'initial').archive)
"
}

# 서비스는 비루트 사용자(65532)로 돈다. 이전 판본이 루트로 만든 볼륨은 소유자를 맞춰야 쓸 수 있다.
fix_volume_owners() {
    "${COMPOSE[@]}" run --rm --no-deps -T --user 0 --entrypoint chown control \
        -R 65532:65532 /var/lib/mint/export /bundles
    "${COMPOSE[@]}" run --rm --no-deps -T --user 0 --entrypoint chown litellm \
        -R 65532:65532 /var/lib/mint/buffer
    # 설정 폴더는 운영자 파일이라 소유자는 두고 그룹에만 읽기를 연다.
    "${COMPOSE[@]}" run --rm --no-deps -T --user 0 --entrypoint sh control \
        -c 'chgrp -R 65532 /app/config && chmod -R g+rX /app/config'
}

cmd_up() {
    require_env
    mkdir -p config
    [ -f config/litellm.config.yaml ] || cp litellm.config.example.yaml config/litellm.config.yaml
    "${COMPOSE[@]}" build litellm
    "${COMPOSE[@]}" up -d --wait postgres
    fix_volume_owners
    admin_cli init --out /app/config/litellm.mint.yaml \
        --fix-config /app/config/litellm.config.yaml >/dev/null
    ensure_bundle
    "${COMPOSE[@]}" up -d opa litellm
    ensure_kit_issuer_key
    "${COMPOSE[@]}" --profile worker up -d worker
    "${COMPOSE[@]}" --profile console up -d console
    echo "기동했습니다. 상태: ./mint.sh status"
}

cmd_status() {
    require_env
    "${COMPOSE[@]}" ps
    cli status
}

# 백업은 데이터베이스 두 개, 정책 번들, LiteLLM 설정을 한 폴더에 모은다. 하나라도 비면 폴더를 지운다.
cmd_backup() {
    require_env
    local dir
    dir="backups/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$dir"
    for database in mint litellm; do
        "${COMPOSE[@]}" exec -T postgres pg_dump -U postgres -d "$database" > "$dir/$database.sql"
    done
    "${COMPOSE[@]}" run --rm --no-deps -T --entrypoint cat control "$BUNDLE_FILE" > "$dir/mint.tar.gz"
    cp config/litellm.config.yaml "$dir/litellm.config.yaml"
    for file in mint.sql litellm.sql mint.tar.gz litellm.config.yaml; do
        [ -s "$dir/$file" ] || { rm -rf "$dir"; fail "백업의 $file이 비어 있어 폴더를 지웠습니다."; }
    done
    echo "백업: $dir (mint.sql, litellm.sql, mint.tar.gz, litellm.config.yaml; 비밀값은 포함하지 않습니다)"
}

cmd_upgrade() {
    require_env
    "${COMPOSE[@]}" build litellm
    "${COMPOSE[@]}" up -d --wait postgres
    # 이전 판본이 루트로 쓰는 중에 소유자를 바꾸면 그 사이에 만든 파일이 루트로 남는다.
    "${COMPOSE[@]}" --profile worker --profile console stop litellm worker console
    fix_volume_owners
    admin_cli init --out /app/config/litellm.mint.yaml \
        --fix-config /app/config/litellm.config.yaml >/dev/null
    "${COMPOSE[@]}" up -d litellm
    ensure_kit_issuer_key
    "${COMPOSE[@]}" --profile worker up -d worker
    "${COMPOSE[@]}" --profile console up -d console
    echo "업그레이드했습니다."
}

case "${1:-}" in
    up) cmd_up ;;
    status) cmd_status ;;
    backup) cmd_backup ;;
    upgrade) cmd_upgrade ;;
    cli) shift; require_env; cli "$@" ;;
    *) fail "사용법: ./mint.sh up | status | backup | upgrade | cli <명령...>" ;;
esac

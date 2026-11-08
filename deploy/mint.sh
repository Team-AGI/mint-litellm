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
    admin_cli init --out /app/config/litellm.mint.yaml >/dev/null
    ensure_bundle
    "${COMPOSE[@]}" up -d opa litellm
    "${COMPOSE[@]}" --profile worker up -d worker
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
    "${COMPOSE[@]}" --profile worker stop litellm worker
    fix_volume_owners
    admin_cli init --out /app/config/litellm.mint.yaml >/dev/null
    "${COMPOSE[@]}" up -d litellm
    "${COMPOSE[@]}" --profile worker up -d worker
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

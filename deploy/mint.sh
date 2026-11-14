#!/usr/bin/env bash
# MINT 배포 보조 스크립트: up | status | bootstrap | backup | upgrade | cli
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

# LiteLLM 키 두 개를 마스터 키로 한 번씩 만들어 비밀 폴더에 둔다. 파일이 있으면 그대로 쓴다.
# - kit: 직원 화면의 단말 설치 묶음이 사용자 키를 발급할 때 쓰는 키(/key/generate, /key/delete만 연 키).
# - control: 제어 평면 키(MINT_LITELLM_KEY). 승인·동기화·수용검증에 필요한 경로만 연다.
# 만들지 못해도 기동은 계속하며(해당 기능만 막힌다) 다음 up·upgrade가 다시 시도한다.
KEY_ISSUER_SCRIPT=$(cat <<'PY'
import json, os, secrets, sys, time, urllib.error, urllib.request
base = "http://litellm:4000"
headers = {"Authorization": "Bearer " + os.environ["LITELLM_MASTER_KEY"],
           "Content-Type": "application/json"}
if os.environ["KEY_KIND"] in ("control", "control-refresh"):
    from mint_litellm.control.litellm_control import STAGE2_ALLOWED_ROUTES
    from mint_litellm.types.cli_commands import CONTROL_PLANE_ALLOWED_ROUTES
    user, prefix = "mint-control", "mint-control-"
    routes = [*CONTROL_PLANE_ALLOWED_ROUTES, *STAGE2_ALLOWED_ROUTES]
else:
    user, prefix = "mint-kit-issuer", "mint-kit-issuer-"
    routes = ["/key/generate", "/key/delete"]


def post(path, body):
    request = urllib.request.Request(base + path, json.dumps(body).encode(), headers, method="POST")
    with urllib.request.urlopen(request, timeout=10) as reply:
        return json.loads(reply.read() or b"{}")


if os.environ["KEY_KIND"] == "control-refresh":
    # 이미 있는 제어 키의 허용 경로를 이 판본의 목록으로 맞춘다(새 기능의 경로가 빠지지 않게).
    try:
        post("/key/update", {"key": os.environ["EXISTING_KEY"], "allowed_routes": routes})
    except (urllib.error.HTTPError, OSError):
        sys.exit(1)
    sys.exit(0)

deadline = time.time() + 120
while True:
    try:
        try:
            post("/user/new", {"user_id": user, "user_role": "proxy_admin",
                               "auto_create_key": False})
        except urllib.error.HTTPError:
            pass  # 이미 있는 사용자
        print(post("/key/generate", {
            "user_id": user,
            "key_alias": prefix + secrets.token_hex(4),
            "allowed_routes": routes,
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

# 비밀 폴더 파일이 없을 때만 키를 만들어 쓴다. 성공하면 0, 만들지 못하면 1.
issue_key() {
    local kind="$1" file="$2" key
    [ -s "$file" ] && return 0
    key="$(env "LITELLM_MASTER_KEY=$(env_value LITELLM_MASTER_KEY)" \
        "${COMPOSE[@]}" run --rm --no-deps -T -e LITELLM_MASTER_KEY -e "KEY_KIND=$kind" \
        --entrypoint python control -c "$KEY_ISSUER_SCRIPT" | tail -n 1)" || key=""
    [[ "$key" =~ ^sk-[A-Za-z0-9_-]+$ ]] || return 1
    (umask 077; printf '%s\n' "$key" > "$file")
}

ensure_kit_issuer_key() {
    local file
    file="$(env_value MINT_SECRETS_DIR)/kit_issuer.key"
    if ! issue_key kit "$file"; then
        echo "단말 설치 묶음 키를 만들지 못했습니다. 다음 up·upgrade에서 다시 시도합니다." >&2
        return 0
    fi
    MINT_KIT_ISSUER_KEY="$(head -n 1 "$file")"
    export MINT_KIT_ISSUER_KEY
}

# 제어 평면 키는 .env의 MINT_LITELLM_KEY가 우선이고, 없으면 비밀 폴더의 control.key를 쓴다.
# 새로 만들었으면 init을 다시 실행해 도구 목록 면제 키로 저장한다.
load_control_key() {
    local file
    file="$(env_value MINT_SECRETS_DIR)/control.key"
    if [ -z "$(env_value MINT_LITELLM_KEY)" ] && [ -s "$file" ]; then
        MINT_LITELLM_KEY="$(head -n 1 "$file")"
        export MINT_LITELLM_KEY
    fi
}

ensure_control_key() {
    local file="$(env_value MINT_SECRETS_DIR)/control.key"
    [ -z "$(env_value MINT_LITELLM_KEY)" ] || return 0
    if [ ! -s "$file" ]; then
        if ! issue_key control "$file"; then
            echo "제어 평면 키를 만들지 못했습니다. 다음 up·upgrade에서 다시 시도합니다." >&2
            return 0
        fi
        load_control_key
        admin_cli init --out /app/config/litellm.mint.yaml \
            --fix-config /app/config/litellm.config.yaml >/dev/null
    fi
    load_control_key
    refresh_control_routes "$file"
}

# mint.sh가 만든 제어 키(비밀 폴더 파일)의 허용 경로를 판본마다 다시 맞춘다. 실패해도 기동은 계속한다.
refresh_control_routes() {
    local file="$1"
    [ -s "$file" ] || return 0
    env "LITELLM_MASTER_KEY=$(env_value LITELLM_MASTER_KEY)" "EXISTING_KEY=$(head -n 1 "$file")" \
        "${COMPOSE[@]}" run --rm --no-deps -T -e LITELLM_MASTER_KEY -e EXISTING_KEY \
        -e KEY_KIND=control-refresh --entrypoint python control -c "$KEY_ISSUER_SCRIPT" \
        >/dev/null 2>&1 \
        || echo "제어 평면 키의 허용 경로를 갱신하지 못했습니다. 다음 up·upgrade에서 다시 시도합니다." >&2
}

# 첫 관리자 토큰과 이후 명령이 쓰는 토큰은 비밀 폴더의 operator.token에 둔다(환경 변수가 있으면 그것이 우선).
load_operator_token() {
    local file
    file="$(env_value MINT_SECRETS_DIR)/operator.token"
    if [ -z "${MINT_OPERATOR_TOKEN:-}" ] && [ -z "$(env_value MINT_OPERATOR_TOKEN)" ] && [ -s "$file" ]; then
        MINT_OPERATOR_TOKEN="$(head -n 1 "$file")"
        export MINT_OPERATOR_TOKEN
    fi
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
    load_control_key
    load_operator_token
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
        -e MINT_WORKER_DB_PASSWORD -e MINT_STAFF_DB_PASSWORD ${MINT_LITELLM_KEY:+-e MINT_LITELLM_KEY} \
        control "$@"
}

cli() {
    "${COMPOSE[@]}" run --rm ${MINT_LITELLM_KEY:+-e MINT_LITELLM_KEY} control "$@"
}

# --save-token <경로>는 컨테이너 안이 아니라 이 호스트의 경로에 저장해야 한다. 컨테이너는 --rm이라
# 안에 쓴 파일이 사라지므로, 토큰을 JSON으로 받아 여기서 0600 파일로 쓴다.
cli_save_token() {
    local path="" arg skip=0 args=() reply token pattern
    for arg in "$@"; do
        if [ "$skip" -eq 1 ]; then path="$arg"; skip=0
        elif [ "$arg" = "--save-token" ]; then skip=1
        elif [[ "$arg" == --save-token=* ]]; then path="${arg#--save-token=}"
        else args+=("$arg"); fi
    done
    [ "$skip" -eq 0 ] && [ -n "$path" ] || fail "--save-token에는 저장할 경로가 필요합니다."
    [ ! -e "$path" ] || fail "$path이(가) 이미 있어 덮어쓰지 않습니다."
    [ -d "$(dirname "$path")" ] || fail "$(dirname "$path") 폴더가 없습니다."
    reply="$("${COMPOSE[@]}" run --rm -T ${MINT_LITELLM_KEY:+-e MINT_LITELLM_KEY} control --json         "${args[@]}")" || { echo "$reply" >&2; fail "명령이 실패했습니다."; }
    pattern='"token": *"([A-Za-z0-9_-]+)"'
    [[ "$reply" =~ $pattern ]] || fail "토큰을 받지 못했습니다."
    token="${BASH_REMATCH[1]}"
    (umask 077; printf '%s
' "$token" > "$path") || fail "토큰을 $path에 쓰지 못했습니다."
    echo "토큰을 $path에 저장했습니다. 이 파일을 --token-file로 주면 인증됩니다."
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
    ensure_control_key
    "${COMPOSE[@]}" --profile worker up -d worker
    "${COMPOSE[@]}" --profile console up -d console
    echo "기동했습니다."
    next_step
}

# 다음에 할 일 한 줄. 첫 관리자가 없으면 만드는 명령을, 있으면 상태 확인을 안내한다.
next_step() {
    if [ -z "${MINT_OPERATOR_TOKEN:-}" ] && [ -z "$(env_value MINT_OPERATOR_TOKEN)" ]; then
        echo "다음: ./mint.sh bootstrap <이름> <LiteLLM 사용자 식별자>  (첫 관리자를 만들고 기본 정책을 적용합니다)"
    else
        echo "상태: ./mint.sh status"
    fi
}

# 토큰이 없으면 상태 대신 할 일만 보인다(운영자가 아직 없을 때도 실행된다).
cmd_status() {
    require_env
    "${COMPOSE[@]}" ps
    if [ -z "${MINT_OPERATOR_TOKEN:-}" ] && [ -z "$(env_value MINT_OPERATOR_TOKEN)" ]; then
        cli doctor
    else
        cli status
    fi
}

# 첫 관리자를 만들어 토큰을 비밀 폴더에 두고(이후 mint.sh 명령이 자동으로 씁니다) 기본 정책을 적용한다.
cmd_bootstrap() {
    require_env
    [ "$#" -eq 2 ] || fail "사용법: ./mint.sh bootstrap <이름> <LiteLLM 사용자 식별자>"
    local file reply token pattern
    file="$(env_value MINT_SECRETS_DIR)/operator.token"
    [ ! -e "$file" ] || fail "$file이 이미 있습니다. 첫 관리자는 한 번만 만들 수 있습니다."
    reply="$("${COMPOSE[@]}" run --rm -T ${MINT_LITELLM_KEY:+-e MINT_LITELLM_KEY} control --json \
        operator bootstrap --name "$1" --user-id "$2")" || fail "첫 관리자를 만들지 못했습니다."
    pattern='"token": *"([A-Za-z0-9_-]+)"'
    [[ "$reply" =~ $pattern ]] || fail "토큰을 받지 못했습니다."
    token="${BASH_REMATCH[1]}"
    (umask 077; printf '%s\n' "$token" > "$file") || fail "토큰을 $file에 쓰지 못했습니다. 토큰: $token"
    load_operator_token
    cli policy activate initial || echo "기본 정책을 적용하지 못했습니다. ./mint.sh status로 확인하십시오." >&2
    echo "첫 관리자 $1을(를) 만들었습니다. 토큰은 $file에 있습니다. 상태: ./mint.sh status"
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
    BACKUP_DIR="$dir"
    echo "백업: $dir (mint.sql, litellm.sql, mint.tar.gz, litellm.config.yaml; 비밀값은 포함하지 않습니다)"
}

# 업그레이드 단계. "설명|함수" 순서가 곧 실행 순서이며 --dry-run은 이 표만 보인다.
# 이미지 빌드·데이터베이스 확인·백업까지는 이전 판본이 그대로 돈다. 서비스를 멈춘 뒤에는 마이그레이션
# (제어 평면)이 플러그인보다 먼저 끝나야 새 열을 판정이 읽는다.
UPGRADE_STEPS=(
    "새 이미지를 빌드합니다|upgrade_build"
    "데이터베이스를 띄워 확인합니다|upgrade_postgres"
    "백업을 만듭니다|upgrade_backup"
    "litellm·worker·console을 멈춥니다|upgrade_stop"
    "마이그레이션을 적용하고 LiteLLM 설정의 빠진 기본값을 채웁니다(제어 평면 먼저)|upgrade_migrate"
    "정책 카탈로그가 바뀌었으면 새 판본으로 활성화합니다|upgrade_policy"
    "LiteLLM(플러그인)을 새 이미지로 다시 띄웁니다|upgrade_litellm"
    "키를 확인하고 작업 실행기와 콘솔을 띄웁니다|upgrade_rest"
    "점검합니다(check, doctor)|upgrade_verify"
    "사람이 정할 일을 계산해 보입니다|upgrade_report"
)
UPGRADE_STEP=""
UPGRADE_STOPPED=""
BACKUP_DIR=""

upgrade_build() { "${COMPOSE[@]}" build litellm; }
upgrade_postgres() { "${COMPOSE[@]}" up -d --wait postgres; }
upgrade_backup() { cmd_backup; }
upgrade_stop() {
    # 이전 판본이 루트로 쓰는 중에 소유자를 바꾸면 그 사이에 만든 파일이 루트로 남는다.
    UPGRADE_STOPPED=1
    "${COMPOSE[@]}" --profile worker --profile console stop litellm worker console
}
upgrade_migrate() {
    fix_volume_owners
    admin_cli init --out /app/config/litellm.mint.yaml --fix-config /app/config/litellm.config.yaml >/dev/null
}
has_operator_token() {
    load_operator_token
    [ -n "${MINT_OPERATOR_TOKEN:-}" ] || [ -n "$(env_value MINT_OPERATOR_TOKEN)" ]
}
upgrade_policy() {
    ensure_bundle
    "${COMPOSE[@]}" up -d opa
    if has_operator_token; then
        cli upgrade policy
    else
        echo "운영자 토큰이 없어 정책 판본 확인을 건너뜁니다. ./mint.sh bootstrap으로 첫 관리자를 만드십시오."
    fi
}
upgrade_litellm() { "${COMPOSE[@]}" up -d litellm; }
upgrade_rest() {
    ensure_kit_issuer_key
    ensure_control_key
    "${COMPOSE[@]}" --profile worker up -d worker
    "${COMPOSE[@]}" --profile console up -d console
}
# 방금 띄운 서비스가 응답하기까지 몇 번 다시 시도한다.
upgrade_verify() {
    if ! has_operator_token; then
        cli doctor
        return 0
    fi
    local try
    for try in 1 2 3 4 5 6; do
        if cli check; then
            cli doctor
            return 0
        fi
        [ "$try" -lt 6 ] && sleep "${MINT_UPGRADE_WAIT:-5}"
    done
    return 1
}
upgrade_report() {
    if has_operator_token; then
        cli upgrade report || echo "남은 결정을 계산하지 못했습니다. ./mint.sh cli upgrade report로 다시 실행하십시오." >&2
    else
        echo "운영자 토큰이 없어 남은 결정을 계산하지 않습니다."
    fi
}

upgrade_exit() {
    local code=$?
    [ "$code" -ne 0 ] && [ -n "$UPGRADE_STEP" ] || return 0
    echo "업그레이드를 중단했습니다: $UPGRADE_STEP 단계가 실패했습니다." >&2
    if [ -z "$UPGRADE_STOPPED" ]; then
        echo "아직 서비스를 멈추지 않아 이전 판본이 그대로 실행 중입니다. 원인을 고친 뒤 ./mint.sh upgrade를 다시 실행하십시오." >&2
    else
        echo "서비스가 멈춘 상태일 수 있습니다. 원인을 고친 뒤 ./mint.sh upgrade를 다시 실행하십시오." >&2
        [ -z "$BACKUP_DIR" ] || echo "이 업그레이드 전의 백업: $BACKUP_DIR" >&2
    fi
}

cmd_upgrade() {
    local dry=0 entry number=0 total=${#UPGRADE_STEPS[@]}
    case "${1:-}" in
        "") ;;
        --dry-run) dry=1 ;;
        *) fail "사용법: ./mint.sh upgrade [--dry-run]" ;;
    esac
    if [ "$dry" -eq 1 ]; then
        [ -f .env ] || fail ".env가 없습니다. .env.example을 복사해 값을 채우십시오."
        echo "업그레이드 계획(아무것도 바꾸지 않았습니다):"
        for entry in "${UPGRADE_STEPS[@]}"; do
            number=$((number + 1))
            echo "  $number. ${entry%%|*}"
        done
        return 0
    fi
    require_env
    trap upgrade_exit EXIT
    for entry in "${UPGRADE_STEPS[@]}"; do
        number=$((number + 1))
        UPGRADE_STEP="[$number/$total] ${entry%%|*}"
        echo "$UPGRADE_STEP"
        "${entry##*|}"
    done
    UPGRADE_STEP=""
    echo "업그레이드했습니다.${BACKUP_DIR:+ 백업: $BACKUP_DIR}"
}

case "${1:-}" in
    up) cmd_up ;;
    status) cmd_status ;;
    backup) cmd_backup ;;
    bootstrap) shift; cmd_bootstrap "$@" ;;
    upgrade) shift; cmd_upgrade "$@" ;;
    cli) shift; require_env
        case " $* " in
            *" --save-token"*) cli_save_token "$@" ;;
            *) cli "$@" ;;
        esac ;;
    *) fail "사용법: ./mint.sh up | status | bootstrap <이름> <사용자> | backup | upgrade [--dry-run] | cli <명령...>" ;;
esac

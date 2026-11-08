#!/usr/bin/env bash
# 장비에서 처음부터: 스택 기동 → 사용자·키·운영자 → 계수 서비스 → site.json → 기준 스냅숏. 깨끗한 셸에서 실행한다.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
export ACC_HOME=${ACC_HOME:-$HOME/mint-s2}
PY=$ACC_HOME/venv/bin/python
cd "$REPO"
bash "$HERE/up.sh"
for _ in $(seq 1 60); do
  curl -fs http://127.0.0.1:4300/health/readiness >/dev/null && curl -fs http://127.0.0.1:4301/health/readiness >/dev/null && break
  sleep 5
done
"$PY" "$HERE/bootstrap.py"
export DOCKER_CONFIG=$HOME/.docker-acc COMPOSE_PROJECT_NAME=mints2 ACC_CERT_DIR=$ACC_HOME/certs
C=(docker compose --env-file deploy/.env -f deploy/compose.yaml -f tests/acceptance/stage2/device/acc.yaml)
"${C[@]}" --profile worker --profile console up -d worker console
"$PY" "$HERE/bootstrap.py" operators
docker rm -f mints2-counter >/dev/null 2>&1 || true
docker run -d --name mints2-counter --network mints2_default -p 4350:4350 -v "$HERE/counter_service.py:/c.py:ro" python:3.13-slim python /c.py http://cnt:8080/__log 4350 0.0.0.0 >/dev/null
source "$HERE/env.sh"
mkdir -p tests/acceptance/stage2/.runtime
"$PY" "$HERE/make_site.py" > tests/acceptance/stage2/.runtime/site.json
"$PY" "$HERE/bootstrap.py" servers
# 첫 정책 판본 활성화(설명 검사·위험 등급이 활성 번들의 데이터를 읽는다)
(cd deploy && MINT_OPERATOR_TOKEN=$ACC_ADMIN_TOKEN ./mint.sh cli policy activate initial --json < /dev/null > /dev/null)
# 제어 평면 키 토큰 저장(pin이 전 도구를 보려면 필요, DS-175)
(cd deploy && MINT_OPERATOR_TOKEN=$ACC_ADMIN_TOKEN ./mint.sh cli settings control-key --json < /dev/null > /dev/null)
# 수용검증의 URL 검사가 요구하는 제공자 허용 목록(계수 역프록시 호스트). 기준 스냅숏에 들어가도록 스냅숏 전에 등록한다.
MINT_OPERATOR_TOKEN=$ACC_ADMIN_TOKEN "$PY" -m mint_litellm.cli allowlist add --kind provider --value cnt   --valid-until "$(date -u -d '+300 days' +%Y-%m-%dT%H:%M:%SZ)" --note acceptance --json > /dev/null
sleep 20
"$PY" -m tests.acceptance.stage2.adapters snapshot apply
echo all-done

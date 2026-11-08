# 2단계 장비 합격 시험

범위는 합격 기준 1~13이다. 제품 코드는 바꾸지 않는다. 실행 대상은 솔루션 기기,
pj1, pj3이며 공개 MCP는 Playwright, Context7, Grafana이다.

**장애 주입 어댑터는 `adapters.py`에 있다.** 사례마다 이름 있는 함수 하나이며
`python -m tests.acceptance.stage2.adapters <이름> apply|undo`로 실행된다.
종료 코드 78은 「미구현으로 건너뜀」(제품 명령·작업 처리기 부재), 70은 어댑터 본문 미작성(실패)이다.
`emit-site`가 `faults`와 `case_setup` 조각을 만들어 준다(아래). 명령·처리기가 병합되지 않은
사례(동기·신청·계약·콘솔)는 78로 건너뛰고, 병합된 뒤에도 본문이 없으면 70으로 실패한다.

## 솔루션 기기의 깨끗한 복제본

아래 명령은 장비에서 실행할 절차이며 샌드박스에서는 실행하지 않는다.
저장소 URL, 병합 main SHA, 비밀 값은 장비의 환경변수로 제공한다.

```bash
git clone "$ACC_REPOSITORY_URL" mint-stage2-acceptance
cd mint-stage2-acceptance
git checkout --detach "$ACC_MAIN_SHA"
git status --porcelain
uv sync --locked --extra dev
mkdir -p tests/acceptance/stage2/.runtime
cp tests/acceptance/stage2/site.example.json tests/acceptance/stage2/.runtime/site.json
cp deploy/.env.example deploy/.env
```

`git status --porcelain`은 비어 있어야 한다. 시험 자산도 해당 SHA에 포함되어야 한다.
`.runtime`, `evidence`, `deploy/.env`는 커밋하지 않는다. 환경 파일은 0600으로 관리한다.
실제 값이 든 환경 파일이나 셸 출력은 보고에 붙이지 않는다.

1. 시험 전용 compose 프로젝트를 선택한다. `COMPOSE_PROJECT_NAME`을 명시하고,
   다른 프로젝트의 컨테이너·볼륨을 정지하거나 삭제하지 않는다.
2. `deploy/.env`에 배치 식별자, DB 역할별 비밀, LiteLLM 키, 지문 키,
   내보내기 HMAC 키·디렉터리를 설정한다. 모드 상한은 enforce,
   `MINT_OBSERVE_SECONDS=60`, `MINT_RECONCILE_SECONDS=300`,
   `MINT_CHECKPOINT_SECONDS=600`, `MINT_LOG_LEVEL=DEBUG`로 맞춘다.
   후속 main의 compose가 실제로 이 환경변수를 각 프로세스에 전달하는지도 확인한다.
3. `deploy/mint.sh up`으로 init → 정책 번들 → 이미지 빌드 → 스택을 올린다.
   worker 프로필은 `docker compose --profile worker up -d worker`로 올린다.
   console은 병합된 main의 프로필/실행 명령을 사용한다. 없는 console 명령을 대체하지 않는다.
4. `bash tests/oss/stack.sh up`으로 고정 판본 공개 서버 스택을 올린다.
   파일이 아직 없으면 공개 MCP 준비도 미완료다. 공개 스택의 순정 LiteLLM은
   MINT 합격 대상이 아니다. 시험 호출과 pj1/pj3는 솔루션 기기의 MINT 경로로 연결한다.
5. 공개 서버의 실제 업스트림 앞에 1단계 계수 역프록시를 둔다. 솔루션에서
   역프록시를 우회해 같은 서버에 연결하는 경로가 없어야 한다.
   `site.counters[server_id]`는 해당 서버의 `{"tools/call": 누적정수}` JSON 계수 면이다.
6. 합성 서버는 `fixture_server.py --bind <시험망 바인드 이름> --port 8940`으로 올린다.
   `/mcp`가 MCP 경로, `/counters`가 계수 면이다. `/control`에
   `{"mode":"description|schema|added|removed|limit|base"}`를 보내 변형한다.
   시험망에서만 노출한다. 이 서버는 공개 MCP 3종의 증거를 대체하지 않는다.
7. 호출자·신청자·승인자를 서로 구분한다. 운영자 bootstrap/add로 토큰을 발급하고,
   신청자와 다른 LiteLLM 사용자에 결속된 approver를 사용한다. 본인 확인에는
   같은 사람의 호출 키와 별도 콘솔 키가 필요하다.
8. 양쪽 복제본은 같은 DB·정책·필수 설정을 사용하고 내보내기를 읽기 전용으로 마운트한다.
   대조 스택은 같은 이미지·업스트림·인증·설정에서 MINT 가드레일만 뺀다.
   성능용 복제본 두 개의 접근 경로를 각각 `site.litellm`에 넣는다.

## 장비 설정과 픽스처 연결

`site.example.json`의 `.invalid` 주소와 식별자는 형식 예시다.
`secret_env`에는 **환경변수 이름만** 둔다. 값은 파일에 넣지 않는다.
제어 CLI를 호스트 Python으로 실행하면 `MINT_DATABASE_URL`(제어 역할),
`MINT_INSTANCE_ID`, `MINT_LITELLM_URL`, `MINT_LITELLM_KEY`도 해당 프로세스에 제공한다.
compose CLI를 사용하면 `site.cli`를 argv 배열로 교체하고 운영자 토큰이 컨테이너까지
전달되는지 확인한다. 제한 없는 키를 제품 프로세스에 추가하지 않는다.

첫 신청은 서버가 아직 활성화되지 않은 상태여야 한다. 공개 서버 제출은 LiteLLM의
비관리자 팀 범위 키로 수행한다. `allow_all_keys=false`이며 신청에 필요한 목적,
자료 등급, 제공자, 책임자, 종료 준비도, 반환 조건을 준비한다. 각 서버 식별자·호출 도구
이름은 실제 목록 값으로 채운다. 예시의 변경 도구 인자는 실제 스키마에 맞게 보완한다.
공급망 검사에 필요한 운영자 첨부 증거와 provider 허용 목록도 준비한다.

`case_setup`은 **각 사례 직전**의 깨끗한 시험 DB·LiteLLM·내보내기 상태를 복구하는
argv 배열이다. `{case}`를 사례 식별자로 치환한다. 마지막 사건 표 검사는 초기화하지 않는다.
다른 사례의 재승인·철회 이력이 다음 사례에 섞이면 기대값이 성립하지 않는다.
기존 장비 초기화/스냅숏 도구를 연결하고 장비 역할·외부 상태도 함께 복구해야 한다.

각 `faults.<이름>`은 `apply`, `undo`, 선택적 `timeout`을 갖는 argv 배열이다.
셸 문자열 조합을 사용하지 않는다. `apply` 전후 상태를 보관하고 `undo`는 중복 호출해도
원래 상태로 돌아가야 한다. 실패해도 역순으로 복구하며 복구 실패는 시험 실패다.
DB 복원은 시험 스택에 한정한다. 24시간 시험은 timeout을 최소 86460초로 지정한다.

어댑터가 쓰는 환경변수(값은 장비 환경에만 둔다): `COMPOSE_PROJECT_NAME`(또는 `ACC_COMPOSE` argv
문자열), `ACC_PG_SERVICE`·`ACC_PG_SUPERUSER`, `ACC_EXPORT_HOST_DIR`·`ACC_EXPORT_CONTAINER_DIR`,
`ACC_LITELLM_ADMIN_URL`·`MINT_LITELLM_KEY`, `ACC_FIXTURE_URL`, `ACC_SERVER_ID`,
`ACC_PLUGIN_DATABASE_URL`, `ACC_ADMIN_TOKEN`, `ACC_STATE_DIR`. 시험 시작 전에 한 번
`adapters snapshot`으로 기준 스냅숏을 만들고, 사례마다 `case_setup`이 그것으로 복원한다.

활성화(`rig.fixture`·`rig.activate`)는 CLI(`intake create|approve`)를 쓴다. 승인 범위는 `site.approval_scope`
(`{type: key|team, id, team?}`)이며 없으면 호출 키(`caller`)의 키 범위이다.

시나리오 어댑터(`scenarios.py`)가 추가로 읽는 값: `ACC_SITE`(또는 `MINT_ACC_SITE`, 없으면
`.runtime/site.json`)에서 서버·신청 입력·계수기·로그 명령을 읽는다. 환경변수는 `ACC_LITELLM_ADMIN_URL`
과 `ACC_LITELLM_ADMIN_KEY`(시험 주체 생성·삭제용 관리 키), `ACC_SUBMIT_KEY`(조직에 묶인 사용자의
비관리자 팀 범위 제출 키), `ACC_ADMIN_TOKEN`·`ACC_APPROVER_TOKEN`·`ACC_ADMIN2_TOKEN`(서로 다른 사용자의
운영자 토큰), `MINT_DATABASE_URL`(제어 역할)·`ACC_STAFF_DATABASE_URL`(직원 역할)·`ACC_PLUGIN_DATABASE_URL`,
`MINT_EXPORT_HMAC_KEY`(키 교체 시험의 원래 값), `ACC_PLUGIN_SERVICES`(키 교체 때 다시 만들 서비스, 기본
`litellm worker`), `ACC_BUFFER_SERVICE`·`ACC_BUFFER_CONTAINER_DIR`(버퍼 검색), `ACC_STEADY_SECONDS`
(24시간 시험 길이, 합격 기준은 86400), 이행 시험(항목 12)은 `stage1.py`가 1단계 SHA(6b4912c)로 별도 프로젝트 스택
`mints1`을 만들고 1단계 데이터를 넣은 뒤 `mint.sh upgrade`로 올려 재며(`ACC_KEEP_STAGE1=1`이면 끝난 뒤 남겨 둔다), `ACC_UI_AUDIT_CMD`(JSON argv: stdin의
`{base, paths, cookies}`로 스크린샷 13개·대비·키보드·문구 검수를 하고 결과 JSON을 출력하는 도구)와
`ACC_UI_REVIEWER`(검수자). 직원 확인은 직원 화면 경로(`/staff/login`, `/staff/confirmations/{id}/confirm`)로 한다. 합성 서버 `mode`에 `unauthorized`(MCP 요청에 401)가
추가되었다. 접근 로그를 세는 시험(`unpin_calls`·`test_route_calls`·`reject_calls`)은 `decision_logs`의
`docker logs`에 `--since`를 붙여 센다.

```bash
.venv/bin/python -m tests.acceptance.stage2.adapters emit-site --repo "$PWD"   > tests/acceptance/stage2/.runtime/site-faults.json   # faults, case_setup 조각을 site.json에 합친다
```

`--ssh <별칭>`을 주면 각 argv가 `ssh <별칭> <한 줄 명령>`이 된다. 관측 JSON은 어댑터가 도는
호스트에 쓰이므로, 시험 실행기와 다른 호스트일 때는 증거 디렉터리를 공유해야 한다.

누락된 연결 목록은 DB 없이 만들 수 있다.

```bash
.venv/bin/python -m tests.acceptance.stage2.inventory \
  --site tests/acceptance/stage2/.runtime/site.json \
  -o tests/acceptance/stage2/.runtime/missing-fixtures.json
```

프로젝트의 `tests` 디렉터리가 다른 설치 패키지와 충돌하면 아래 실행을 쓴다.

```bash
PYTHONPATH=tests/acceptance .venv/bin/python -m stage2.inventory \
  --site tests/acceptance/stage2/.runtime/site.json
```

첫 명령의 종료 코드 1은 연결 누락이며 제품 동작 실패와 다르다.
공개 판본 교체 3종의 argv는 예시에 제공했다. 나머지는 이전 장비 도구와 연결한다.
`inventory`가 성공해도 명령의 실제 동작이나 관측값의 진실성을 확인한 것은 아니다.

## 장애 주입 도구의 관측 JSON 계약

복잡한 경쟁·DB 복원·권한 제한·화면 시험은 `apply`가 준비 → 행동 → 원시 증거 수집을
끝내고 `{observation}` 경로에 JSON을 쓴다. `{run_id}`도 argv 한 인자로 전달할 수 있다.
시작·종료 시각과 실제 계수·상태·HTTP 응답·SQLSTATE를 측정하여 기록한다.
기대값을 복사한 결과나 `passed: true`만 있는 결과는 실측 증거가 아니다.

```json
{
  "run_id": "apply 인자로 받은 실행 식별자",
  "sha": "시험 중인 main SHA",
  "events": {"sync_held": 1},
  "raw_evidence": [{"path": "장비 로컬 증거 경로", "sha256": "원시 파일 SHA-256"}]
}
```

각 사례의 필수 관측 필드는 `expected_events.yaml`의 `observations`가 정본이다.
예를 들어 `sync_race_30`은 실제 30회 경쟁 후 누락된 소유 항목 수와 비소유 필드 경보 수를
기록한다. `restore_epoch_caught_up`은 DB epoch가 따라잡은 상태와 소비·확인·관측을
각각 수행했다는 관측값을 기록한다. API·DB 역할 시험은 두 표면을 모두 시도한다.
13개 화면 시험은 스크린샷 13개, 각 파일 경로·SHA-256, 검수자, 대비·키보드 결과가 필요하다.
현재 복제본에는 이 JSON을 생성하는 기존 장비 도구의 어댑터가 없으므로 연결 작업이 남아 있다.

## pj1 · pj3의 실제 Claude Code

자동 실행은 `client_probe.py`와 `remote_client.py`를 두 장비에 함께 복사하고
`site.clients.pj1`/`pj3`를 고정 원격 argv로 연결한다. 예시는 장비 이름의 SSH 별칭을 쓴다.
다른 원격 실행 환경이면 같은 stdin/stdout 계약을 전달하는 실행기로 바꾼다.
각 원격 프로세스에는 `ACC_CLAUDE_CONFIG`, `ACC_CLIENT_EVIDENCE`와 호출 키 환경을
제공한다. JSON 인자를 원격 셸 문자열에 보간하지 않는다.
항목 13은 앞선 증거를 확인한 뒤 초기 상태를 복구하고 세 서버의 다섯 상태를 직접 전환한다.
각 상태에서 두 실제 Claude Code를 호출하고 계수/원장과 대조하여 원문을 솔루션 기기로 수집한다.
수동으로 미리 만든 다른 실행의 클라이언트 파일을 합격 증거로 대신하지 않는다.

아래처럼 환경변수를 참조하는 MCP 설정을 각 장비 로컬에 둔다.
pj3에 기존 관리형 설정이 있으면 이 설정과 충돌하는지 먼저 확인한다.
관리가 강제하는 설정을 이 시험 스크립트가 변경하지 않는다.

```json
{"mcpServers":{"acceptance":{"type":"http","url":"${ACC_MCP_URL}",
"headers":{"Authorization":"Bearer ${ACC_CALLER_KEY}"}}}}
```

공개 서버마다 before → active → drift → reapproved → revoked 상태에서 각각 호출한다.
drift 단계에서는 해당 판본 쌍에서 실제로 변경된 도구를 선택한다. before에서 목록에 도구가
없다는 출력도 업스트림 0과 함께 보관한다. REST 호출을 실제 클라이언트 시험으로 대신하지 않는다.
Claude Code 도구 권한이 준비되어 있어야 하며 `--allowedTools`에는 설정에 맞는 전체 도구 이름을 넣는다.

```bash
python -X utf8 client_probe.py --device pj1 --sha "$ACC_MAIN_SHA" \
  --server context7 --phase active --config "$ACC_CLAUDE_CONFIG" \
  --tool "$ACC_TOOL" --arguments arguments.json --counter-url "$ACC_COUNTER_URL" \
  --output client-evidence/context7-active.json
```

pj3 PowerShell에서는 같은 인자를 사용하되 `--device pj3`로 지정하고,
변수 참조를 `$env:ACC_MAIN_SHA`, `$env:ACC_CLAUDE_CONFIG`, `$env:ACC_TOOL`,
`$env:ACC_COUNTER_URL`로 바꾼다. Python 표준 라이브러리만 필요하다.
각 호출은 최대 180초이며 원문과 해시를 저장한다. 같은 디렉터리에서 다섯 단계를 수행하면
`client-pj1.json`/`client-pj3.json`과 합쳐진 원문이 생성된다.
파일을 솔루션 기기로 수집하고 JSON의 transcript 경로를 실제 수집 위치로 맞춘다.
원문 바이트는 바꾸지 않고 해시를 재확인한다. 원문에 키가 없는지 확인한 뒤 공유한다.

## 실행과 증거

```bash
.venv/bin/python -m pytest tests/acceptance/stage2 --stage2-live \
  --stage2-site tests/acceptance/stage2/.runtime/site.json \
  --stage2-evidence tests/acceptance/stage2/evidence/final-run \
  --stage2-required -q
```

`--stage2-required`는 건너뜀도 실패로 처리한다. 준비 중에는 이 옵션을 빼서
명령·처리기 부재를 확인한다. 실제 장비 합격 때는 1~13을 **같은 pytest 실행**으로 돌린다.
항목 13은 같은 SHA·같은 batch의 앞선 사례 64개와 핵심 흐름 6종의 통과 증거를 요구한다.
중간 실행 결과를 섞거나 별도 실행의 예전 합격 결과로 누락을 채우지 않는다.

사례별 JSON에는 SHA, 실행 식별자, 건너뜀 사유, 기대·실제 사건 수, 원장 source_key,
업스트림 호출 차이, 호출 반환 시간, 해석이 담긴다. 주소·환경변수의 비밀 값은 가린다.
원시 fixture 관측 파일은 비공개 로컬 증거이며 공유 전 비밀·주소 검색을 따로 한다.

성능은 복제본 2개·동시 8개, 1/2/4/8 단계 예열 뒤 4라운드 교대로 각 800건을 보낸다.
시나리오는 작은 인자, JSON UTF-8 정확히 65536바이트 인자, 128KiB 문자열이다.
대형 문자열은 보수적 패턴 참에 따른 enforce 차단을 예상한다. 이 판정도 실제 비용이다.
MINT 3200건의 원장 `decision_ref`와 두 복제본 DEBUG 로그를 정확히 대조하고
예열·다른 호출·누락·중복 표본을 제외/검출한다. 분위수는 nearest-rank이며
p50/p95/p99 상한은 30/100/300ms다. RTT 차이는 보조값이다.
원장에 인자 본문이나 패턴 불리언을 새로 저장하지 않는다. 대형 문자열에 실제 적용된
정책 ID와 관리 서버 상태로 패턴/관리 스냅숏 경로를 확인한다.
측정 중 다른 부하와 무관한 스택의 상태를 기록하고 정지한 것이 있으면 복구한다.

## 샌드박스 검증

```powershell
.\.venv\Scripts\python.exe -X utf8 -m pytest --collect-only tests/acceptance
.\.venv\Scripts\python.exe -X utf8 -m pytest tests/acceptance/stage2/test_assets.py -q
.\.venv\Scripts\python.exe -X utf8 -m compileall -q tests/acceptance
.\.venv\Scripts\python.exe -X utf8 -m ruff check tests/acceptance
```

수집 때는 DB·장비·Docker를 호출하지 않는다. 이 검증은 장비 합격 증거가 아니다.
현재 관리 API 응답을 평면 JSON, 변경 요청을 `state_version` 필드로 해석했다.
후속 main의 실제 OpenAPI/CLI가 다르면 이 자산의 경로·필드 연결을 대조해야 한다.
배포 계약 변경은 별도 사건을 사용하며 봉인 자체의 사건 건수는 0이다.

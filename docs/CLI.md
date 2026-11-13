# CLI

`mint-litellm`은 운영자용 명령줄 도구이다. `init`과 `operator bootstrap`을 제외한 모든 명령은 운영자 토큰으로 인증하며, 변경의 행위자는 토큰에 결속된 운영자 이름이다. CLI는 LiteLLM에 쓰지 않는다. 계약 재승인은 계획과 동기화 작업을 등록한다.

## 역할

| 역할 | 권한 |
| --- | --- |
| `admin` | 모든 명령 |
| `approver` | 승인·거부·철회·호출별 승인과 조회 |
| `viewer` | 조회 |

`admin`과 `approver`는 LiteLLM 사람 사용자 식별자(`--user-id`)에 결속되어야 하고, 등록 시 사용자가 존재하는지 확인한다. 직무 분리는 이 식별자로 판정한다. `approve`는 신청·요청자와 같은 사용자의 운영자가 승인할 수 없고(`--second-approver`로 다른 운영자의 토큰을 함께 제시하면 두 사람 모두 기록하고 허용), 호출별 승인은 호출 주체와 같은 사용자의 운영자가 승인할 수 없다. 같은 사람이 토큰을 여러 개 가져도 사용자 식별자가 같으면 한 사람으로 본다. 첫 `admin`은 `operator bootstrap`으로 만든다. 이 명령은 `operators` 표가 비어 있을 때만 토큰 없이 실행되며 그 뒤에는 거부된다.

## 명령

| 명령 | 역할 | 설명 | LiteLLM 읽기 | 사건 |
| --- | --- | --- | --- | --- |
| `mint-litellm contract show` | 모든 역할 | 서버의 승인본·후보 계약을 조회한다. | - | - |
| `mint-litellm contract diff` | 모든 역할 | 승인 계약과 관측 원본·해시·변경 순번을 비교한다. | - | - |
| `mint-litellm contract reapprove` | `admin`, `approver` | 직무 분리·재검사 증거를 확인하고 후보 id·판본을 고정한 계획과 동기화 작업을 등록한다. | - | `reapproval_requested` |
| `mint-litellm init` | 토큰 불필요 | LiteLLM 설정 조각(권장 설정 포함)을 만들고 기본 조직을 준비한다. `--no-spend-logs`를 주면 `disable_spend_logs: true`를 포함한다. `--fix-config <파일>`은 운영자 LiteLLM 설정의 MINT 가드레일 `mode`에 빠진 모드와 빠진 필수 설정(`disable_env_credential_login: true`, 서버별 기본 `rpm`·`max_concurrent_requests`)을 한 줄 수정으로 더한다(바꾸기 전 `<파일>.bak-<시각>` 사본을 남기고, 다른 항목과 주석은 그대로이며 이미 있으면 아무것도 하지 않는다). 안전하게 고칠 수 없는 모양이면 고칠 줄을 알리고 오류로 끝난다. `./mint.sh up`·`upgrade`가 `config/litellm.config.yaml`에 이 옵션을 쓴다. | - | - |
| `mint-litellm check` | 모든 역할 | 필수 설정 위반이 있으면 종료 코드 0이 아닌 값으로 끝나고, 권장 설정은 경고하며, 관측 항목 4가지를 출력한다. | `/v1/mcp/server`, `/key/list`, `/team/list`, `/guardrails/list` | - |
| `mint-litellm doctor` | 토큰 불필요 | 지금 비어 있거나 기다리는 일(운영자·제어 평면 키·정책 판본 없음, 승인 대기, 결정 대기 신청, 열린 경보, 실패한 작업, 보류된 동기화)과 다음에 실행할 명령을 보인다. 읽기 전용이며 데이터베이스만 읽는다. | - | - |
| `mint-litellm upgrade policy` | `admin` | 저장소의 정책 카탈로그 해시가 적용 중인 판본과 다르면 `catalog-<해시 앞 12자>` 판본으로 활성화한다. `--check`는 바뀌었는지만 알린다. `./mint.sh upgrade`가 부른다. | - | `policy_activated` |
| `mint-litellm upgrade report` | 모든 역할 | 업그레이드 뒤 사람이 정해야 하는 일(범위가 비어 막힌 OAuth 서버, `allow_token_forward`가 없는 전달 서버 승인, 재확인이 필요한 승인, 증빙이 없는 버전 미고정 패키지, 보고가 없거나 이전 판본인 단말 설치 묶음)을 데이터베이스에서 계산해 해결할 화면·명령과 함께 보인다. 읽기 전용이다. | - | - |
| `mint-litellm status` | 모든 역할 | 모드, 정책 판본, 경보, 관측 항목과 같은 「할 일」 목록을 표시한다. | `/v1/mcp/server`, `/key/list`, `/team/list` | - |
| `mint-litellm operator add` | `admin` | 운영자를 등록하고 토큰을 발급한다. `--save-token <파일>`을 주면 토큰을 화면에 보이지 않고 0600 파일로만 받는다(파일이 이미 있으면 운영자를 만들기 전에 거부한다). `admin`·`approver`는 LiteLLM 사용자 식별자 (`--user-id`) 결속이 필수이다. | `/user/info` | `operator_added` |
| `mint-litellm operator bootstrap` | 토큰 불필요 | `operators` 표가 비어 있을 때만 토큰 없이 첫 `admin` 운영자를 만들고 토큰을 발급한다. `--name`과 `--user-id`가 필요하며, 사용자가 LiteLLM의 사람 사용자로 존재하는지 확인한다. 행위자는 `bootstrap`으로 기록하고, 운영자가 이미 있으면 거부한다. | `/user/info` | `operator_added` |
| `mint-litellm operator remove` | `admin` | 운영자를 삭제한다. 토큰이 끝나고 그 사용자의 콘솔 세션이 폐기된다. 마지막 관리자와 본인은 삭제할 수 없다. | 없음 | `operator_removed` |
| `mint-litellm operator set-role` | `admin` | 운영자의 역할을 바꾼다(`--role`). 그 사용자의 콘솔 세션이 폐기된다. 마지막 관리자는 낮출 수 없다. | 없음 | `operator_role_changed` |
| `mint-litellm server register` | `admin` | LiteLLM에 등록된 서버를 승인 대기 상태로 등록한다. | `/v1/mcp/server/{server_id}` | `server_registered` |
| `mint-litellm server register-local` | `admin` | 로컬 실행(stdio) 서버를 LiteLLM 없이 실행 계약(`--contract` JSON 파일)으로 승인 대기 상태로 등록한다. 서버가 접근할 경로는 계약 파일의 `file_access`나 `--read`·`--read-write`(반복 가능)로 선언한다. 네트워크는 `--network none|any`(또는 계약 파일의 `network`)로 선언하며, `none`이면 단말 격리가 막고 생략하면 제한이 없다. | - | `server_registered` |
| `mint-litellm server suspend` | `admin` | 서버를 중지한다. 중지된 서버의 호출은 차단된다. | - | `server_suspended` |
| `mint-litellm server terminate` | `admin` | 승인 또는 중지된 서버를 폐기 중으로 바꾼다(호출은 즉시 차단). 작업 실행기가 LiteLLM 관리 API로 그 서버에 저장된 사용자별 OAuth2·API 키 자격을 지우고, 목록을 다시 읽어 하나도 남지 않은 것을 확인하고, 서버 계정·문서 공유 권한 회수 확인 증빙(`access_revocation`)이 있으면 폐기됨으로 닫고(없으면 폐기 중에 머물고 경보 `evidence_missing`을 연다) `server_terminated`에 지운 개수를 남긴다. 남아 있으면 폐기 중에 머물며 재시도하고 경보 `server_credentials_remain`을 연다. 서버 자체 비밀·사용자별 환경 변수·동적 등록 클라이언트는 LiteLLM이 목록·삭제 경로를 주지 않아 읽어 확인하지 못한다. | - | `server_terminating`, `server_terminated` |
| `mint-litellm server resume` | `admin` | 중지한 서버를 다시 승인 상태로 되돌린다. | - | `server_resumed` |
| `mint-litellm relation add` | `admin` | 조직·팀·목적·서버를 묶는 이용 관계를 만든다. | - | `relation_created` |
| `mint-litellm relation terminate` | `admin` | 이용 관계를 종료 중으로 바꾸고 그 관계의 활성 승인을 철회한다. 그 관계에 속한 승인과 매칭되는 호출은 `RELATION_TERMINATED`로 차단되고, LiteLLM 권한 회수를 읽어 확인한 결과가 사건으로 남는다. | - | `relation_terminating`, `approval_revoked` |
| `mint-litellm approve` | `admin`, `approver` | 이용 관계에 속한 승인을 등록한다. 근거와 유효 기간이 필수이며, 대상 권한이 LiteLLM에 서버 식별자 형식으로 있는지 읽어 확인한다. | `/key/info`, `/team/info` | `approval_granted`, `server_approved` |
| `mint-litellm deny` | `admin`, `approver` | 주체 또는 서버에 대한 거부를 만든다. 거부는 모든 승인보다 우선한다. | - | `denial_created` |
| `mint-litellm denial lift` | `admin`, `approver` | 거부를 해제한다. | - | `denial_lifted` |
| `mint-litellm revoke` | `admin`, `approver` | 승인을 철회한다. `--deny`를 주면 같은 범위의 거부를 함께 만든다. | - | `approval_revoked`, `denial_created` |
| `mint-litellm call-approval request` | `admin`, `approver` | 특정 주체·서버·도구·인자에 대한 호출별 승인을 요청한다. | - | `call_approval_requested` |
| `mint-litellm call-approval approve` | `admin`, `approver` | 호출별 승인을 승인한다. 호출 주체와 같은 사용자의 운영자는 승인할 수 없다. `--for 10m`·`--for 30m`을 주면 그 시간 동안 같은 호출을 되풀이해 쓸 수 있고, 없으면 1회용이다. | - | `call_approval_approved` |
| `mint-litellm call-approval reject` | `admin`, `approver` | 호출별 승인 요청을 거절한다. | - | `call_approval_rejected` |
| `mint-litellm call-approval cancel` | `admin`, `approver` | 요청 중이거나 승인된 호출별 승인을 취소한다. | - | `call_approval_cancelled` |
| `mint-litellm consent add` | `admin` | 사용자 동의를 등록한다. 운영자 증명은 증거 참조와 증거 해시가 필수이다. | - | `consent_granted` |
| `mint-litellm consent revoke` | `admin` | 등록된 동의를 철회한다. | - | `consent_revoked` |
| `mint-litellm allowlist add` | `admin` | 허용 목록 항목을 등록한다. 종료일이 필수이다. | - | `allowlist_added` |
| `mint-litellm allowlist lift` | `admin` | 허용 목록 항목을 해제한다. | - | `allowlist_lifted` |
| `mint-litellm org add` | `admin` | 조직을 만든다. | - | `org_created` |
| `mint-litellm org close` | `admin` | 조직을 닫는다. 닫힌 조직에 속한 주체의 호출은 차단된다. | - | `org_closed` |
| `mint-litellm org bind` | `admin` | 팀 또는 사용자를 조직에 묶는다. 한 팀·한 사용자는 한 조직에만 묶인다. | - | `org_binding_created` |
| `mint-litellm org unbind` | `admin` | 팀 또는 사용자의 조직 바인딩을 제거한다. | - | `org_binding_removed` |
| `mint-litellm org suggest` | 모든 역할 | 점검 작업이 만든 열린 조직 연결 제안을 조회한다(최근 7일 호출이 많은 주체가 먼저). | - | - |
| `mint-litellm org suggest apply` | `admin` | 제안 하나(`<제안 식별자>`) 또는 한 규칙의 열린 제안 전체(`--rule team_metadata\|team_alias\|email_domain`)를 적용한다. 묶기는 `org bind`와 같은 경로이다. | - | `org_binding_created` |
| `mint-litellm org suggest ignore` | `admin` | 제안을 무시한다. 무시한 제안은 다시 열리지 않는다. | - | - |
| `mint-litellm org domain` | 모든 역할 | 이메일 도메인과 조직의 대응표를 조회한다. | - | - |
| `mint-litellm org domain set` | `admin` | 이메일 도메인을 조직에 대응시킨다(`--org`). | - | - |
| `mint-litellm org domain unset` | `admin` | 도메인의 조직 대응을 지운다. | - | - |
| `mint-litellm settings default-org` | `admin` | 바인딩이 없는 주체에 적용할 기본 조직을 지정하거나 해제한다. | - | `settings_changed` |
| `mint-litellm settings mode` | `admin` | 집행 모드를 enforce 또는 observe로 정한다. 환경 변수의 상한이 enforce이면 observe로 바꿀 수 없다. | - | `settings_changed` |
| `mint-litellm settings control-key` | `admin` | 환경 변수 `MINT_LITELLM_KEY`의 제어 평면 키를 도구 목록 면제 키로 저장한다(`--clear`는 해제). `init`도 키가 있으면 저장되지 않은 경우 같은 일을 한다. | - | `settings_changed` |
| `mint-litellm settings observable` | `admin` | 관측 모드로 전환할 수 있는 사유 계열과 정책을 정한다. | - | `settings_changed` |
| `mint-litellm policy activate` | `admin` | 정책 번들을 검증하고 정책 엔진에 적재한 뒤 활성 판본으로 전환한다. | - | `policy_activated` |
| `mint-litellm policy shadow` | `admin` | 정책 판본을 시험용 정책 엔진에 올려 활성 판본과 나란히 평가한다. 호출의 판정은 달라지지 않고 판정이 달라지는 호출만 센다. | - | `policy_shadow_set` |
| `mint-litellm policy shadow-cancel` | `admin` | 시험 중인 정책 판본을 내린다. | - | `policy_shadow_cleared` |
| `mint-litellm policy status` | 모든 역할 | 적용 중인 판본과 시험 중인 판본, 판정이 달라지는 호출 수를 조회한다. | - | - |
| `mint-litellm ledger list` | 모든 역할 | 원장 사건을 종류·기간·호출 식별자로 조회한다. | - | - |
| `mint-litellm sync status` | 모든 역할 | LiteLLM에 반영한 키·팀·서버 권한의 확인 상태, 외부 삭제 횟수, 보류 여부를 조회한다. | - | - |
| `mint-litellm sync resume` | `admin` | 반복 외부 삭제로 보류된 항목을 풀고 다시 부여한다. | - | `sync_applied` |
| `mint-litellm alert list` | 모든 역할 | 경보를 상태(`--status`)별로 조회한다. | - | - |
| `mint-litellm alert ack` | `admin` | 열린 경보(`alert_id`)를 확인 처리한다. 확인한 운영자 이름이 남는다. | - | `alert_acknowledged` |
| `mint-litellm alert resolve` | `admin` | 경보(`alert_id`)를 해결됨으로 닫는다. 같은 원인이 다시 생기면 새 경보가 열린다. | - | `alert_resolved` |
| `mint-litellm intake list` | 모든 역할 | 수용검증 신청을 상태(`--status`)별로 조회한다. | - | - |
| `mint-litellm intake show` | 모든 역할 | 신청 한 건과 검사 결과, 도구 계약 후보를 보인다. | - | - |
| `mint-litellm intake create` | `admin` | 서버의 수용검증 신청을 만든다(아래 「수용검증 신청」). | `/v1/mcp/server/{server_id}` | `intake_received` |
| `mint-litellm intake recheck` | `admin` | 검사를 다시 한다. | - | - |
| `mint-litellm intake assign` | `admin` | 신청자가 비어 있는 제출 신청에 사람 사용자를 신청자로 지정한다. | `/user/info` | `intake_requester_assigned` |
| `mint-litellm intake approve` | `admin`, `approver` | 모든 검사를 통과한 신청을 승인한다. | - | `intake_decided`, `contract_approved` |
| `mint-litellm intake reject` | `admin`, `approver` | 신청을 거절한다. | - | `intake_decided` |
| `mint-litellm intake except` | `admin`, `approver` | 판별 불가가 있는 신청을 예외 승인한다. | - | `intake_decided`, `contract_approved` |

## 식별자 줄여 쓰기와 토큰 안내

목록에 나온 식별자(경보·신청·호출별 승인·동기화 항목·승인·거부·동의·허용 목록)는 끝 8자리(또는 충분히 긴 앞부분)만 써도 이 배치 안에서 한 건으로 정해지면 찾아 준다(`alert ack 3f9c1a2b`). 둘 이상이면 더 길게 입력하라고 알리고, 없으면 그대로 없다고 알린다. 토큰 없이 인증이 필요한 명령을 실행하면 운영자가 한 명도 없을 때는 첫 관리자를 만드는 명령(`operator bootstrap ... --save-token`)을, 있을 때는 토큰을 받는 방법을 안내한다.

## 정책 활성화 실패와 복원

### 정책 시험 적용

새 판본을 바로 적용하기 전에 `policy shadow <판본>`으로 시험용 정책 엔진(`opa-shadow`, `docker compose --profile shadow up -d opa-shadow`)에 올린다. LiteLLM 컨테이너의 `MINT_SHADOW_OPA_URL`을 시험용 정책 엔진 주소(`http://opa-shadow:8181`)로 정하면 호출마다 활성 판본이 판정을 마친 뒤 같은 입력을 시험 판본에도 보낸다. 시험 결과는 호출의 판정에 쓰이지 않고, 오류는 평가 오류 수로만 센다. 판정 결과나 사유가 달라진 호출은 (서버, 도구, 현재 결과, 시험 결과, 사유)별로 세고 호출 식별자를 다섯 개까지만 남긴다. `policy status`와 콘솔 정책 화면의 「정책 시험 적용」에서 허용에서 차단, 차단에서 허용으로 바뀌는 호출 수를 본다. 마음에 들면 `policy activate <판본>`(콘솔의 「적용」)으로 평소 활성화 경로를 거쳐 적용하고, 아니면 `policy shadow-cancel`(콘솔의 「취소」)로 내린다.

`policy activate`가 시간 초과나 취소로 끝나면 이전 활성 번들을 복원하려고 시도하며, 결과를 `restore_outcome` 필드에 담는다(`--json`). 성공하면 값은 `null`이다. 복원도 확인하지 못했다면 그 사실이 필드에 남으므로 운영자가 현재 적재된 번들을 `status`로 다시 확인해야 한다.

## 서버와 승인의 활성화 순서

1. LiteLLM에 서버를 구성한다. 설정 서버는 `server_id`를 명시한다.
2. `server register <server_id>`로 서버를 등록한다. LiteLLM 관리 API로 존재를 확인하고 상태는 승인 대기가 된다.
3. `relation add`로 조직·팀·목적과 서버를 묶는 이용 관계를 만든다.
4. `approve --relation <관계> --basis <근거>`로 승인한다. 대상 키·팀의 `object_permission`이 서버 식별자 형식으로 부여되어 있는지 읽어 확인하며, 별칭이나 이름 형식의 항목이 있으면 실패하고 교정 방법을 안내한다. 첫 승인이 활성화되는 같은 트랜잭션에서 서버가 승인 상태로 바뀐다.

승인을 모두 철회해도 서버 상태는 바뀌지 않는다. 서버 전체를 막으려면 `server suspend`를 쓴다. 특정 주체를 더 넓은 승인까지 포함해 막으려면 `revoke --deny`를 쓴다.

## 관리자 콘솔 `mint-litellm console`

`mint-litellm console`은 상주 프로세스다. FastAPI와 서버 렌더링 화면(Jinja2, HTMX, ECharts)을 한 프로세스로 띄우며 빌드 단계와 외부 자산이 없다(응답 헤더 `Content-Security-Policy: default-src 'self'`). `MINT_DATABASE_URL`은 `mint_control_app` 로그인의 주소여야 하고, `MINT_LITELLM_URL`(로그인 확인용)과 `MINT_EXPORT_DIR`·`MINT_EXPORT_HMAC_KEY`가 없으면 기동을 거부한다. `--host`(기본 `localhost`, `*`는 이 호스트가 가진 모든 주소: IPv4만 있는 컨테이너에서도 열린다)·`--port`(기본 8080)·`--ssl-certfile`·`--ssl-keyfile`을 받는다. 쿠키는 항상 `Secure`이므로 브라우저는 HTTPS(또는 `localhost`)로 접속해야 한다.

- **로그인**: 사람이 자기 LiteLLM 키를 낸다. 콘솔은 그 키로 `GET /key/info`와 `GET /user/info`를 부르고(키가 차단·만료·미등록이거나 마스터 키이거나 사용자에 결속되지 않았거나 사람 사용자가 아니면 거부) 평문 키를 바로 버린다. 그 사용자에 결속된 유효한 운영자(`operators`) 행이 있어야 하고, 화면 권한은 그 행의 역할이다.
- **세션**: `__Host-mint_session` 쿠키(`HttpOnly`·`Secure`·`SameSite=Strict`), 유휴 30분·절대 8시간(`MINT_SESSION_IDLE_SECONDS`·`MINT_SESSION_ABSOLUTE_SECONDS`). 변경 요청은 CSRF 토큰(`X-CSRF-Token` 헤더 또는 폼 필드 `csrf`)과 같은 출처가 필요하다. 작업 실행기가 `MINT_SESSION_VERIFY_SECONDS`(기본 300)마다 제어 평면 키로 세션의 키·사용자·운영자 행을 다시 확인하고 맞지 않으면 폐기한다. LiteLLM에 닿지 못하면 2주기까지는 세션을 유지하고 그 뒤에는 확인하지 못한 세션을 폐기한다(그래서 작업 실행기에는 `MINT_LITELLM_URL`·`MINT_LITELLM_KEY`가 필요하다).
- **HTTP API** `/api/v1/<자원>`: 세션 쿠키 또는 `Authorization: Bearer <운영자 토큰>`. 변경 요청은 대상의 `state_version`을 보내야 하며 다르면 `409 MINT-ADMIN-CONFLICT`이다. 오류 본문은 `{code, message, reference}`이고 `X-Request-Id` 응답 헤더가 `reference`와 같다(사건이 있는 오류는 사건 키). 자원: `overview`, `servers`, `relations`, `approvals`, `denials`, `call-approvals`, `orgs`, `operators`, `allowlists`, `settings`, `policy/versions`, `ledger`(`/ledger/export?format=csv|json`).
- 승인(`POST /approvals`)·운영자 등록·서버 등록은 LiteLLM 읽기가 필요하다. 콘솔은 제어 평면 키(`MINT_LITELLM_KEY`)를 읽기 경로 전용 클라이언트로만 쓰며(쓰기는 작업 실행기만) 설치 기본은 키를 설정하는 것이다. 키가 없으면 이 동작은 거부되고 명령줄에서 한다. 오류 코드는 `MINT-ADMIN-<이유>`(`…-INVALID-INPUT`·`…-UNAVAILABLE` 포함)이다.

### 직원 화면

같은 콘솔 프로세스가 `/staff` 아래에 직원 화면을 연다. 직원 화면의 연결은 `MINT_STAFF_DATABASE_URL`(`mint_staff_app` 로그인의 주소)로 따로 만들며, 이 값이 없으면 직원 화면은 열리지 않는다. 직원 로그인은 관리자와 같은 본인 키 확인이지만 운영자 행이 필요 없고, 세션 쿠키 `__Host-mint_staff`는 관리자 세션과 따로다. 세션에는 로그인 때 본인 키 정보의 `team_id`에서 읽은 소속 팀이 함께 저장되며 작업 실행기의 재확인이 새 값으로 갱신한다. 화면 입력으로 팀을 받는 곳은 없다.

- **쓸 수 있는 서버·도구**: 소속 조직의 이용 관계가 있는 승인된 서버와, 본인·본인 팀·본인 조직·본인 키 범위의 유효한 승인이 허용하는 도구.
- **본인 확인 요청**: 정책이 본인 확인을 요구해 만든 요청을 확인·거절·취소한다. 확인은 호출한 키와 다른 키로 로그인한 세션에서만 된다(`require_separate_confirm_key`). 화면에 보이는 인자 값은 필드당 256자까지이며 요청이 끝나면 데이터베이스에서 지워진다.
- **동의 관리와 내 기록**: 목적별 동의 등록·철회(유효 기간 상한 `MINT_STAFF_CONSENT_MAX_DAYS`, 기본 90일)와 본인 범위의 기록.
- 직원 로그인 역할은 표를 직접 읽거나 쓰지 못하고 `mint.staff_*` 함수만 실행한다. 이 함수들은 슈퍼유저가 아닌 전용 역할(`mint_staff_owner`)이 소유하며 그 역할은 함수가 쓰는 표·열 권한만 가진다.

## 작업 실행기 `mint-litellm worker`

`mint-litellm worker`는 운영자 명령이 아니라 상주 프로세스다(토큰·사건 없음). 같은 이미지를 `mint_worker_app` 로그인(제어·작업·봉인 그룹)으로 접속해 띄우며, 복제본을 여럿 띄워도 안전하다. `MINT_DATABASE_URL`은 이 로그인의 주소여야 하고, 다른 로그인이면 기동을 거부한다. `MINT_EXPORT_DIR`·`MINT_EXPORT_HMAC_KEY`가 없거나 `MINT_WEBHOOK_URLS`가 있는데 `MINT_WEBHOOK_HMAC_KEY`가 없으면 기동을 거부한다.

- 주기가 된 일정(`schedules`)을 한 주기에 한 번 작업으로 등록하고, 임대가 만료된 `running` 작업을 `pending`으로 되돌리고(시도 한 번으로 센다), 대기 작업을 하나씩 임대해 실행한다. 실행 중에는 임대(`MINT_WORKER_LEASE_SECONDS`, 기본 60초)를 1/3마다 연장하고, 연장에 실패하면 그 작업의 외부 호출을 멈춘다.
- 실패한 작업은 `min(2^시도 횟수 × 5초, 10분)` 뒤에 다시 시도하고, 시도 8번째 실패에서 `failed`가 되며 경보 `job_failed`(같은 종류·대상은 한 건으로 묶고 횟수만 올린다)를 남긴다. 오류 메시지는 저장하지 않고 오류 코드만 남긴다.
- 작업 실행기가 처리하는 작업은 `org_suggest_scan`(`MINT_ORG_SUGGEST_SECONDS`마다 조직 연결 제안 갱신, 「조직 연결 제안」), `submission_poll`(`MINT_SUBMISSION_POLL_SECONDS`마다 LiteLLM 제출을 신청으로 만든다), `intake_run`(수용검증), `session_verify`(콘솔 세션 재확인), `package_vuln_scan`(`MINT_VULN_SCAN_SECONDS`마다 패키지 취약점 조회와 치명 취약점 48시간 기한 판정, 아래 「패키지·취약점 통제」), `evidence_expiry_scan`(1시간마다 증거 만료 7일 전 경보와 재검사 등록), `approval_expiry_scan`(1분마다 만료된 호출별 승인·본인 확인을 `expired`로 표시), `endpoint_result_scan`(1분마다 결과 보고 없이 5분이 지난 허용된 로컬 서버 호출에 `call_outcome_unknown`(사유 `no_report`)을 남긴다), `seal`(1분마다 미봉인 사건을 해시 연쇄로 봉인), `export_negative_state`(부정 상태 전이가 커밋될 때 등록), `export_checkpoint`(10분마다, 기동 직후 한 번)이다. 그 밖에 `contract_observe`, `sync_server`·`sync_target`·`sync_reconcile`, `relation_finalize`·`server_finalize`·`activation_finalize`, `alert_deliver`, `call_spike_scan`, `content_finding_scan`(1분마다 계약 관리가 아닌 서버의 내용 검사 기록을 모아 경보를 연다), `metric_rollup`(1분마다 지표 롤업), `restore_publish`가 있다. 처리기가 없는 종류는 등록할 수 없다.
- 60초마다 내보내기 파일과 DB를 대조해 되돌림을 판정한다. 처음 어긋나면 봉인·내보내기를 보류하고, 두 번 연속 어긋나거나 파일이 없거나 검증되지 않으면 외부 쓰기를 모두 멈춘다(`restore_blocked`로 대기, 시도 횟수 불변). 외부 쓰기 직전마다 같은 판정과 임대 유효성을 다시 확인한다.
- SIGTERM·SIGINT를 받으면 실행 중인 작업에 취소를 알린다. 작업이 그대로 끝나면 완료로 기록하고, 취소를 받아 멈추면 시도 횟수를 올리지 않고 임대를 놓은 뒤 종료한다.

## 권한 동기화 `sync`

작업 실행기가 키·팀 범위 승인을 LiteLLM의 `object_permission`(`mcp_servers`, `mcp_tool_permissions`)에 맞춘다. 쓸 때마다 MINT가 넣지 않은 항목은 그대로 둔 전체 목록과 전체 맵을 보내고, 쓴 뒤 다시 읽어 반영 여부를 확인한다. 팀 소속 키는 팀이 허용한 서버만 받을 수 있어 팀이 먼저 맞춰진다. `MINT_RECONCILE_SECONDS`마다 재조회해 MINT가 반영한 항목이 외부에서 지워졌으면 다시 부여한다. 같은 항목이 `MINT_SYNC_HOLD_WINDOW_SECONDS` 안에 다시 지워지면 그 항목은 보류되어 다시 부여하지 않고 경보 `sync_divergence`와 사건 `sync_held`를 남긴다. `sync status --held`로 찾아 `sync resume <id>`로 풀거나, 승인을 철회한다. 작업 실행기가 LiteLLM을 부르려면 `MINT_LITELLM_URL`과 `MINT_LITELLM_KEY`가 필요하다.

## 봉인·내보내기·복원 명령

운영자 토큰으로 실행한다. `MINT_EXPORT_DIR`·`MINT_EXPORT_HMAC_KEY`(키 교체 중에는 `MINT_EXPORT_HMAC_KEY_PREVIOUS`)가 필요하다.

| 명령 | 역할 | 설명 |
| --- | --- | --- |
| `mint-litellm seal verify [--from N --to M]` | 전부 | 봉인 연쇄를 처음부터 다시 계산하고 마지막 체크포인트 파일의 봉인 끝과 대조한다. 내보내기 키가 있으면 배치 끝 해시의 서명도 확인한다. 어긋나면 종료 코드 1. |
| `mint-litellm export status` | 전부 | 최근 내보내기와 최신 파일의 서명 키를 보여 주고 옛 키를 빼도 되는지 알려 준다. |
| `mint-litellm restore check` | admin | 파일의 부정 상태와 DB를 비교해 누락·봉인 앵커·마지막 성공 전송 이후 활동 서버를 보여 준다. |
| `mint-litellm restore attest --reason <사유>` | admin | 파일에 담긴 부정 상태 행 전체 스냅숏으로 복구 DB를 되돌리고(없는 행은 같은 식별자로 다시 넣고, 뒤처진 행은 파일 내용으로 되돌린다), DB 세대를 파일 세대 + 1로 올리고, 복원 요청과 `restore_attested`를 커밋한다. 부모 행이 없어 되돌릴 수 없는 항목이 있으면 목록과 함께 거부한다. 반복해도 같은 결과다. 명령은 파일을 쓰지 않는다. |
| `mint-litellm restore accept-stale --reason <사유> --second-approver <토큰>` | admin 2인 | 파일이 없거나 검증되지 않을 때 복원 요청과 `restore_stale_accepted`를 커밋한다. 명령은 파일을 쓰지 않는다. |

## 증빙 첨부와 이용 관계 종료 완료

사람이 확인하는 정책의 증빙을 대상에 붙인다. 증빙의 원문은 저장하지 않고 요약, 문서 위치, 문서 해시값, 유효 기한만 남긴다. 같은 대상·종류에서는 가장 최근에 붙인 증빙이 현재 증빙이다.

| 증빙 종류 | 대상 | 필수 자리 | 기본 유효 기간 |
| --- | --- | --- | --- |
| `trial_call` 시험 호출 결과 | 신청 | 신청 승인 | 90일 |
| `provider_terms` 제공자 자료 처리 조건 확인 | 신청 | 신청 승인 | 365일 |
| `least_privilege` 서버 계정 최소 권한 확인 | 신청 | 신청 승인 | 180일 |
| `prompt_review` 제공 지시문 검토 (해당 없음 가능) | 신청 | 신청 승인 | 90일 |
| `transfer_approval` 서버 간 전달 승인 (해당 없음 가능) | 신청 | 신청 승인 | 365일 |
| `version_review` 되돌릴 판본의 보안 문제 확인 | 서버 | 배포 계약이 바뀌는 재승인 | 30일 |
| `unpinned_acceptance` 버전 미고정 패키지 사용 승인 | 서버 | 버전이 고정되지 않은 패키지를 실행하는 로컬 서버의 승인 | 30일 |
| `vuln_exception` 취약점 조치 예외 | 서버 | 치명 취약점 조치 기한이 지난 서버의 호출 차단을 푸는 예외 | 30일 |
| `instance_exception` 인스턴스 간 불일치 예외 | 서버 | 다른 인스턴스와 계약·설정이 달라 막힌 서버의 호출 차단을 푸는 예외(admin만) | 30일 |
| `command_input_review` 명령·질의 입력 전달 방식 점검 결과 (문서 해시값 필수) | 신청 | 로컬 실행 서버이거나 도구 이름에 실행·질의 말이 든 서버의 신청 승인 | 180일 |
| `access_revocation` 서버 계정·문서 공유 권한 회수 확인 | 서버 | 서버 폐기 마무리(없으면 서버가 폐기 중에 머물고 경보를 연다. 붙이면 마무리가 다시 실행된다) | 없음 |
| `deletion_proof` 자료 삭제·반환 증빙 | 이용 관계 | 관계 종료 완료 | 없음 |
| `access_recheck` 변경된 자료의 접근 권한 재확인 (해당 없음 가능) | 서버 | 주기 확인 | 90일 |
| `source_review` 변경된 자료의 출처 확인 (해당 없음 가능) | 서버 | 주기 확인 | 90일 |
| `instruction_review` 바뀐 지시문 재심사 (해당 없음 가능) | 서버 | 주기 확인 | 90일 |

필수 자리(신청 승인·재승인·관계 종료 완료)는 증빙이 없거나 기한이 지났으면 거절한다. 신청 승인은 일반 승인(`intake approve`)에만 적용하고 거절과 예외 승인은 막지 않는다. 증빙 없이 예외 승인하면 누락된 증빙 종류가 `intake_decided` 사건과 승인 근거의 `missing_evidence`에 남고, 콘솔 신청 화면에 「증빙 누락」으로 표시된다. 증빙 확인 작업은 1시간마다 승인된 신청, 승인된 관리 서버, 종료 중인 이용 관계를 훑어 증빙이 없거나 만료됐거나 7일 안에 끝나면 경보 `evidence_missing`·`evidence_expiring`을 연다. 경보는 서버마다 한 건(이용 관계는 관계마다 한 건)이고 정책별 누락은 경보 본문의 `items`에 담긴다. 증빙을 붙이면 그 묶음 경보가 닫히고, 남은 누락이 있으면 다음 확인 작업이 최신 목록으로 다시 연다.

| 명령 | 역할 | 설명 |
| --- | --- | --- |
| `mint-litellm evidence attach <종류> <대상 식별자> --summary <요약> [--ref <문서 위치>] [--sha256 <해시값>] [--valid-until <기한>] [--not-applicable]` | admin·approver | 증빙을 붙이고 `evidence_attached`를 남긴다. 유효 기한은 종류별 기본 기간을 넘을 수 없다. `--not-applicable`은 해당 없음 가능 종류에만 쓰고 요약에 사유를 적는다. |
| `mint-litellm evidence show <intake\|server\|relation> <대상 식별자>` | 전부 | 대상에 붙일 수 있는 증빙 종류마다 현재 상태를 보인다. |
| `mint-litellm relation finish <이용 관계>` | admin | 종료 중인 이용 관계를 종료됨으로 닫고 `relation_terminated`를 남긴다. 자료 삭제·반환 증빙이 있어야 한다. |

복원 요청은 작업 `restore_publish`를 등록하고, 작업 실행기는 되돌림 차단 상태에서도 이 작업만은 실행한다. 순서는 기존 파일을 `restored/<요청>/`로 옮겨 보관, DB 기준 새 부정 상태·체크포인트·`latest.json` 게시, 다시 읽어 서명·내용 검증, `exports` 행 확정이다. 중간에 중단되면 차단이 유지되고 작업이 이어서 끝낸다.

봉인 해시·HMAC·내용 해시가 쓰는 정규 JSON은 `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`를 UTF-8로 인코딩한 것이며(코드의 `restore.files.canonical_json` 한 곳), 실수 값은 거부한다. 서명 입력은 `hmac` 필드를 뺀 본문 전체(`key_id` 포함), 배열은 저장 순서이며 시각은 UTC ISO 8601 초 단위 `Z`다. 허용 자료형은 문자열·정수·참거짓·null·배열·객체뿐이고 사건 본문에도 실수를 넣을 수 없다. 시험 벡터는 `tests/unit/control/test_export.py`에 있다.

HMAC 키를 교체하려면 새 키를 `MINT_EXPORT_HMAC_KEY`, 옛 키를 `MINT_EXPORT_HMAC_KEY_PREVIOUS`에 두고 다시 기동한다. 작업 실행기가 새 키로 체크포인트를 쓰고 최신 부정 상태 파일을 다시 서명하면 `export status`가 옛 키를 빼도 된다고 알려 준다.

## 수용검증 신청 `mint-litellm intake`

`intake` 명령은 신청 → 검사 → 승인을 다룬다. 검사는 작업 실행기가 한다(`intake_run`). 제어 평면 키(`MINT_LITELLM_KEY`)는 `allowed_routes`에 `/key/update`, `/team/update`, `/mcp-rest/test/connection`, `/mcp-rest/test/tools/list`를 더해야 한다.

- `mint-litellm intake list [--status <상태>]`, `mint-litellm intake show <신청>`: 신청, 검사 결과(검사마다 최근 시도), 도구 계약 후보를 본다.
- `mint-litellm intake create <server_id> --purpose … --data-grade … --allowed-resources <JSON> --provider … --owner … --credential-notice … --revocation-record … --audit-access-days … --data-return-terms …`: 신청을 만든다. 같은 서버에 LiteLLM 제출에서 온 `received` 신청이 있으면 그 신청의 필수 입력을 채운다. 제출 접수 때 제공자(서버 주소의 호스트)·허용 자원(도구 목록)·책임자(제출자)는 미리 채워지고 경보 `intake_pending`이 열리므로 이 세 항목은 생략할 수 있다(목적·자료 등급·종료 준비도·반환 조건은 사람이 정한다). 필수 입력이 모두 있고 신청자가 있어야 검사가 시작된다. 다만 제출 주소가 거부 대상 리터럴 IP(사설·루프백 등, 허용 목록 예외 제외)이면 입력을 기다리지 않고 제출을 조회할 때 `url_guard`(`IP_FORBIDDEN`)로 자동 거절한다.
- `mint-litellm intake assign <신청> --requester <사용자>`: 제출의 `submitted_by`가 비어 있을 때(서비스 계정 제출) 사람 사용자를 신청자로 지정한다. 지정한 운영자는 그 신청을 결정할 수 없다.
- `mint-litellm intake recheck <신청> [--registry-first] [--url <새 주소> [--transport <방식>]]`: 검사를 다시 한다. `--registry-first`는 연결 검사가 `CREDENTIALS_REQUIRED`로 판별 불가였던 제출 서버를 LiteLLM 레지스트리에 올리고(승인은 제출의 `allow_all_keys`를 그대로 두므로, 켜진 제출은 승인 직후 같은 작업에서 `allow_all_keys=false`로 고치고 다시 읽어 확인한다. 끄지 못하면 신청은 더 진행하지 않고 경보 `sync_divergence`가 열린다) 저장된 자격으로 연결·정의 검사를 다시 한다. 키·팀 권한은 주지 않는다. 승인된 신청(승인·예외로 결정되고 관리 중인 서버)도 받는다. 이 재검사는 신청 상태를 `decided`로 둔 채 검사를 승인된 배포 계약(배포 드리프트면 레지스트리의 현재 값으로 만든 배포 후보)으로 다시 실행하고, 서버에 재승인을 기다리는 드리프트가 있으면 후보 계약과 그 후보에 결속된 증거를 저장한다. 계약 관측이 새 드리프트를 처음 기록하면 같은 작업이 자동으로 등록되므로, 운영자는 `contract diff`로 후보를 확인한 뒤 `contract reapprove`로 재승인하면 된다LiteLLM이 서버 URL을 돌려주지 않아 배포 후보를 만들 수 없으면 `--url`로 새 주소를 준다(관측된 배포 URL 해시와 다르거나, 전송 방식이 관측값(관측이 없으면 승인된 값)과 다르면 거부한다. 재승인 계획이 진행 중이어도 거부한다. 입력한 운영자는 그 후보의 제시자로 기록된다. 콘솔 재검사에도 같은 입력칸이 있다). 서버 자격 흐름(`oauth2_flow`) 드리프트는 승인된 배포 값 그대로 배포 후보를 두고 발급자 허용 목록·흐름 검사를 다시 하며, 흐름이 여전히 틀리면 통과하지 못해 차단이 유지된다. 도구 삭제는 재검사를 등록하지 않는다.
- `mint-litellm intake approve <신청> [--valid-until <시각>] [--scope key|user|team --scope-id <식별자> --team <팀>]`: 모든 검사가 통과한 신청을 승인한다. 신청자와 같은 사용자는 승인할 수 없고, 연결·정의 증거는 24시간 안이어야 한다(아니면 `MINT-ADMIN-STALE-EVIDENCE`, 재검사). 승인은 도구 계약 후보와 배포 계약 후보를 승인하고 서버 행에 계약 값을 복사하고(`contract_status=managed`) 이용 관계와 `pending` 승인을 만들며 동기화 작업을 등록한다. 승인 범위의 기본은 책임자 사용자이고, 유효 기간의 기본은 90일(high·critical 도구가 있으면 30일)이다.
- `mint-litellm intake except <신청> --reason … --second-approver … [--valid-until …]`: 판별 불가가 있는 신청의 예외 승인. 사유와 두 번째 승인자가 필요하고 유효 기간의 기본은 30일, 상한은 90일이다.
- `mint-litellm intake reject <신청> --reason …`: 거절한다. 제출에서 온 신청은 LiteLLM 제출도 거절된다.

검사가 하나라도 실패하면 신청은 자동으로 거절된다. `MINT_INTAKE_ALLOWED_PORTS`(기본 `443,8443`)는 URL 검사가 허용하는 포트이다. 정책 번들 데이터(`description_markers`, `risk`)는 작업 실행기가 `MINT_OPA_URL`의 정책 엔진에서 활성 번들로 읽고(판본별 캐시, 엔진이 돌려준 판본·해시가 활성 판본과 다르거나 읽을 수 없으면) 해당 검사는 판별 불가이다. 제어 평면 키의 `allowed_routes`에는 서버 수정 경로가 `/v1/mcp/server` 접두로 이미 들어 있다.

## 서버를 LiteLLM에서 삭제하는 순서

승인된 서버가 LiteLLM 레지스트리에 없으면 플러그인 자가 점검 5번이 실패해 프록시가 기동하지 않는다. 그래서 서버를 지울 때는 먼저 MINT에서 `server suspend <server_id>`로 서버를 중지하고, 그다음 LiteLLM에서 삭제한다. 삭제하기 전에 그 서버를 가리키는 팀·키의 MCP 권한(`object_permission`)도 지운다. 남아 있으면 `check`가 없는 서버를 가리키는 권한으로 실패를 알린다. 중지된 서버는 호출이 계속 차단되고, 레지스트리에 없어도 기동을 막지 않는다. 플러그인은 이 서버에 대해 `server_identity_mismatch_observed` 사건(`fields`에 `registry_missing`)을 남기고, `check`는 같은 서버를 정보 행으로 알린다. 중지한 서버는 통제 상태로 남는다. 서버를 완전히 폐기하려면 `server terminate`를 쓴다(서버 폐기는 `docs/운영.md`).

## 환경 변수

| 변수 | 용도 | 기본값 |
| --- | --- | --- |
| `MINT_DATABASE_URL` | MINT 데이터베이스 접속 주소 | 필수 |
| `MINT_INSTANCE_ID` | 배치 식별자. 영문자·숫자·`.`·`_`·`-`, 128자 이하 | `default` |
| `MINT_OPERATOR_TOKEN` | 운영자 토큰. `--token-file <파일>`로 대신할 수 있다. | 인증이 필요한 명령에서 필수 |
| `MINT_LITELLM_URL` | LiteLLM 관리 API 주소 | `server register`·`operator add`·`approve`·`consent add`·`check`·`status`에서 필요 |
| `MINT_LITELLM_KEY` | 제어 평면 LiteLLM 키(`proxy_admin`, `allowed_routes` 11개로 제한). `./mint.sh up`이 비워 둔 `.env`의 값을 대신해 만들어 비밀 폴더에 둔다. `init`이 이 키의 토큰을 도구 목록 면제 키로 저장한다(키를 넣은 뒤 `init`을 다시 실행하거나 `settings control-key`를 실행). 저장되지 않으면 서버 승인 때 도구 고정이 멈추고 경보 `sync_divergence`(`control_key_not_set`)가 열린다. | 위와 같음 |
| `MINT_STAFF_DATABASE_URL` | 콘솔 직원 화면이 쓰는 `mint_staff_app` 로그인의 데이터베이스 주소 | 없으면 직원 화면을 열지 않음 |
| `MINT_STAFF_CONSENT_MAX_DAYS` | 직원 본인 동의의 유효 기간 상한(일, 1~365) | `90` |
| `MINT_RECERT_DAYS` | 승인 필요성 재확인 주기(일, 1~365). 마지막 재확인(없으면 승인 시작)부터 센다 | `90` |
| `MINT_RECERT_GRACE_DAYS` | 재확인 요청 뒤 보류까지의 유예(일, 1~365) | `14` |
| `MINT_VULN_FEED_URL` | 알려진 취약점 조회 주소(OSV 형식 API). 사내 미러를 쓰려면 http(s) 주소를 준다 | `https://api.osv.dev` |
| `MINT_VULN_SCAN_SECONDS` | 취약점 조회·조치 기한 판정 주기(초, 60 이상) | `900` |
| `MINT_INSTANCE_MISMATCH_GRACE_SECONDS` | 다른 인스턴스와 계약·설정이 다른 상태가 이 시간(초)을 넘게 이어지면 그 서버 호출을 막는다. 경보는 바로 열린다. 0이면 바로 막는다. | `900` |
| `MINT_VULN_FEED_TIMEOUT_SECONDS` | 조회 요청 한 번의 제한 시간(초) | `15` |
| `MINT_EVENT_RETENTION_DAYS` | 사건 원장 보관 일수(31 이상). 설정하면 달 전체가 이보다 오래되고 내보내기 파일을 다시 읽어 확인한 월 분할을 지운다. 없으면 아무것도 지우지 않는다. MINT는 기본값을 정하지 않는다 | 없음(끔) |
| `MINT_WEBHOOK_FORMATS` | 웹훅 주소마다 하나씩, 같은 순서로 적는 전송 형식(`json`·`slack`·`teams`). 수가 맞지 않거나 모르는 값이면 기동을 거부한다. | 모두 `json` |
| `MINT_LINK_TTL_SECONDS` | 알림 속 콘솔 바로가기 링크의 유효 시간(초, 최소 60). | `86400` |
| `MINT_ORG_META_KEY` | 팀 메타데이터에서 조직 식별자를 읽는 키. | `mint_org` |
| `MINT_ORG_SUGGEST_SECONDS` | 조직 연결 제안 점검 주기(초, 60 이상). | `3600` |
| `MINT_DORMANT_DAYS` | 이 일수 동안 호출에 한 번도 쓰이지 않은 활성 승인을 「미사용」으로 본다. | `30` |
| `MINT_CONSOLE_URL` | 경보 본문의 `console_url`에 넣을 콘솔 주소(선택). 없으면 `null`이다. | 없음 |
| `MINT_LITELLM_CONFIG` | `check`·`status`가 읽는 LiteLLM `config.yaml` 경로. `--config`로 대신할 수 있다. | 없음 |
| `MINT_MODE` | 모드 상한. `enforce`이면 `settings mode observe`가 거부된다. | `enforce` |
| `MINT_REPLICAS`, `MINT_LITELLM_WORKERS` | `check`가 공유 캐시 설정을 판단할 때 쓰는 복제본 수와 컨테이너당 LiteLLM 워커 수. 곱이 둘 이상이면 공유 Redis를 요구한다. | `1`, `1` |
| `MINT_SECRETS_FILE` | `init`이 인자 지문 키를 쓰는 비밀 파일. `--secrets-file`로 대신할 수 있다. | `~/.config/mint/secrets.env` |
| `MINT_PLUGIN_DB_PASSWORD`, `MINT_CONTROL_DB_PASSWORD` | `init`이 판정 프로세스용·제어 평면용 로그인 역할(`mint_plugin_app`, `mint_control_app`)을 만들 때 쓰는 비밀번호 | 없음(역할을 만들지 않음) |
| `MINT_WORKER_DB_PASSWORD`, `MINT_STAFF_DB_PASSWORD` | `init`이 작업 실행기용(`mint_worker_app`: 제어·작업·봉인 그룹)·콘솔 직원 화면 연결 풀용(`mint_staff_app`: 직원 그룹) 로그인 역할을 만들 때 쓰는 비밀번호 | 없음(역할을 만들지 않음) |
| `MINT_EXPORT_DIR`, `MINT_EXPORT_HMAC_KEY`, `MINT_WORKER_LEASE_SECONDS` 등 | `worker`가 읽는 2단계 설정(`MINT_EXPORT_HMAC_KEY`는 디코딩하면 32바이트 이상인 base64url). | `MINT_EXPORT_DIR`·`MINT_EXPORT_HMAC_KEY`는 필수, 임대 길이 60초 |
| `MINT_SHADOW_OPA_URL`, `MINT_OPA_SHADOW_BUNDLE_PATH` | `policy shadow`의 시험용 정책 엔진 주소와 그 엔진이 감시하는 번들 파일. 각 옵션(`--opa-url`, `--bundle-path`)으로 대신할 수 있다. LiteLLM 컨테이너에도 `MINT_SHADOW_OPA_URL`을 주어야 시험 판본을 평가한다. | 없음, `/bundles/shadow.tar.gz` |
| `MINT_SHADOW_SAMPLE_PERCENT`, `MINT_SHADOW_MAX_PER_SECOND` | LiteLLM 컨테이너가 시험 판본을 평가하는 호출의 비율(1~100)과 워커당 초당 평가 수 상한. 어느 쪽에 걸려도 호출은 그대로 처리되고 건너뛴 수로만 센다. | `100`, `50` |
| `MINT_OPA_URL`, `MINT_POLICY_ROOT`, `MINT_OPA_BUNDLE_PATH` | `policy activate`의 정책 엔진 주소, `policy/`를 담은 루트, 정책 엔진이 감시하는 번들 파일. 각 옵션(`--opa-url`, `--policy-root`, `--bundle-path`)으로 대신할 수 있다. | `/opt/mint`, `/bundles/mint.tar.gz` |

## 설정 조각

`init`은 LiteLLM 설정 조각을 `config/litellm.mint.yaml`에 쓰고, 호출별 승인의 인자 지문 키가 없으면 저장소 밖 비밀 파일(`--secrets-file`, 기본 `~/.config/mint/secrets.env`, 권한 0600)에 만든다. 출력의 `fingerprint_key_file`·`fingerprint_key_created`로 확인하며 키 값은 출력하지 않는다. `--out <경로>`로 위치를 바꾸고 `--out -`로 표준 출력에 낸다. 통제할 설정 서버는 `--mcp-server <이름>=<URL>`로 줄 수 있으며 `server_id`는 이름과 같게 명시된다.

## 승인 조건과 대상 확인

`approve`는 정책이 읽는 조건을 승인과 함께 저장한다. 승인은 생성한 뒤 조건을 바꿀 수 없으므로 조건이 달라지면 새 승인을 만든다. 조건은 지정한 것만 저장되고 사건에도 그대로 남는다.

| 옵션 | 조건 | 효과 |
| --- | --- | --- |
| `--high-risk-tools a,b` | `high_risk_tools` | 나열한 도구는 호출별 승인을 요구한다. 계약 관리 서버의 도구는 승인된 계약의 위험 등급이 `high`·`critical`이면 이 옵션 없이도 요구하므로, 이 옵션은 요구를 더하기만 한다. |
| `--business-hours-only` | `business_hours_only` | 업무 시간 밖의 호출을 차단한다. 업무 시간은 정책 번들의 값이다. |
| `--business-hours 시간대,요일,시작,끝` | `business_hours` | 이 승인의 업무 시간을 재정의한다(예: `Asia/Seoul,1-5,09:00,18:00`, 요일은 1=월 ~ 7=일). `--business-hours-only`와 함께 쓴다. |
| `--require-consent 목적` | `require_consent` | 그 목적의 동의가 있어야 호출을 허용한다. 서버의 수용 신청 자료 등급이 `confidential`·`restricted`이면 이 옵션 없이도 이용 목적을 동의 목적으로 요구한다. |
| `--allowed-host 호스트` (반복) | `allowed_hosts` | 인자의 URL이 향할 수 있는 호스트(하위 도메인 포함). 계약 관리 서버에만 적용한다. |
| `--allowed-path 경로` (반복) | `allowed_paths` | 인자의 절대 경로가 있어야 하는 폴더. 계약 관리 서버에만 적용한다. 허용 경로가 없으면 모든 절대 경로를 차단하며, 제한을 두지 않으려면 승인에 `allowed_paths_unrestricted`를 명시한다(콘솔의 「제한 없음」). |
| `--allowed-arg-key 이름` (반복) | `allowed_arg_keys` | 호출이 쓸 수 있는 인자 이름. 이 밖의 이름이 있으면 차단한다. 계약 관리 서버에만 적용한다. 지정하지 않으면 승인된 도구 계약의 입력 정의에 있는 이름만 허용한다. 계약의 입력 정의를 알 수 없고 이 옵션도 없으면 호출을 `MINT-CONTRACT-DRIFT-input-keys-unknown`으로 막는다. |
| `--allow-input-secret 종류` (반복) | `allow_input_secrets` | 인자에서 비밀을 찾으면 도구로 보내기 전에 `MINT-POLICY-DETECT-POL-E-05`로 막는다(개인 키, 클라우드 접근 키, 접근 토큰, JWT, Bearer 토큰, 주민등록번호, 카드 번호). 종류 이름(`private_key`, `cloud_access_key`, `access_token`, `jwt`, `bearer_token`, `resident_registration_number`, `card_number`, `custom_marker`)을 적으면 이 승인의 도구에 한해 그 종류를 허용한다. 사건에는 종류와 건수만 남긴다. 계약 관리 서버에만 적용한다. |
| `--allow-token-forward` | `allow_token_forward` | 호출자 토큰을 업스트림에 그대로 전달하는 서버(`true_passthrough`·`oauth_delegate`)의 도구 호출을 이 승인에서 허용한다. 없으면 `MINT-TOKEN-FORWARD-FORBIDDEN`으로 막는다(관측 모드로 풀리지 않음). |
| `--max-result-bytes 수` | `max_result_bytes` | 도구 결과 한 건의 크기 상한(바이트). 넘으면 결과 대신 `MINT-OUTPUT-BLOCKED`를 돌려주고 응답 사건의 `output_findings`에 `POL-E-16`을 남긴다. |
| `--max-result-items 수` | `max_result_items` | 도구 결과 한 건의 내용 블록 수 상한. 넘으면 위와 같이 막는다. |
| `--no-result-scan` | `scan_result` | 결과 본문의 지시문 표지 검사를 끈다. 계약 관리 서버는 이 옵션이 없으면 검사하며, 표지가 있으면 결과를 `MINT-OUTPUT-BLOCKED`로 막고 `output_findings`에 `POL-E-04`를 남긴다. 관측 모드에서는 막지 않고 응답 사건에만 남긴다. |
| `--response-scan block\|mask\|observe` | `response_scan` | 결과 본문의 비밀(개인 키, 클라우드 접근 키, GitHub 토큰, Bearer 토큰, JWT)과 개인정보(주민등록번호, 전화번호, 이메일, 카드 번호)를 찾았을 때의 처리. `mask`(기본)는 찾은 값만 `[MASKED:종류]`로 바꿔 주고, `block`은 결과 대신 `MINT-OUTPUT-BLOCKED`를 돌려주며, `observe`는 기록만 한다. 응답 사건의 `sensitive_findings`에 종류별 건수만 남기고 값은 남기지 않으며 `output_findings`에 `POL-E-05`를 남긴다. 관측 모드에서는 어느 값이든 기록만 한다. |

호출별 승인은 승인할 때 사용 기간을 고른다(콘솔 승인 폼의 1회·10분·30분, `call-approval approve --for 10m|30m`, HTTP API `window_minutes`). 기본인 1회는 첫 일치 호출에서 소비된다. 10분·30분 승인은 소비되지 않고 승인 시각부터 그 시간이 끝날 때까지 같은 주체·서버·도구·인자 지문·계약·대상의 호출에 되풀이해 쓰이며, 쓸 때마다 `call_approval_uses` 표에 호출 식별자별 한 행이 남고 호출의 판정 사건에도 승인 식별자가 남는다. 기간이 끝나면 더는 맞지 않고(작업이 `expired`로 표시), 취소하면 즉시 멈춘다. 콘솔 목록은 사용 기간·남은 시간·사용 횟수를 보인다. 이 기간 동안은 인자가 달라지면 새 승인이 필요하다.

계약 관리 서버의 호출별 승인(`call-approval request`)과 본인 확인은 요청할 때 승인된 도구 계약에 묶인다. 계약이 교체되거나 철회되면 아직 쓰지 않은 승인은 만료되고, 승인된 계약이 없는 도구에는 호출별 승인을 요청할 수 없다.

승인 범위(`--scope key|user|team`)의 대상은 LiteLLM에서 읽어 확인한다. 대상이 없거나, `object_permission.mcp_servers`에 서버 식별자가 아닌 항목(별칭·이름)이 있거나, 대상에 해당 서버의 권한(직접 부여 또는 서버가 속한 접근 그룹)이 없으면 승인은 만들어지지 않는다. 이용 관계에 팀이 있으면 `team` 범위는 그 팀, `key` 범위는 팀이 같은 키, `user` 범위는 그 팀에 속한 사용자여야 한다. 팀이 없는 관계에서는 `team` 범위가 그 조직에 묶인 팀이어야 하고, `key`·`user` 범위는 조직 유도 결과(팀 바인딩, 사용자 바인딩, 기본 조직 순)가 관계의 조직과 같아야 한다. `--scope org` 승인은 지원하지 않으므로 조직에 묶인 팀을 `team` 범위로 승인한다.

## 서버 등록의 계약 URL

`server register`는 서버의 URL 해시를 계약 값으로 저장한다. URL은 `--url`, LiteLLM 설정 파일(`--config` 또는 `MINT_LITELLM_CONFIG`의 `mcp_servers.<이름>.url`, `server_id`가 같은 항목), 관리 API 응답 순으로 정하며 출처는 사건의 `url_source`(`operator`, `config_file`, `registry`)에 남는다. 제어 평면 키는 제한된 키라서 관리 API가 URL을 응답하지 않는 것이 보통이다. 둘 이상의 출처가 보이면 모두 같아야 한다. URL이 없는 서버(stdio, OpenAPI 명세 기반)는 `MINT-UNSUPPORTED`(사유 `server_without_url`)로 거부한다. 로컬 실행(stdio) 서버는 `server register-local <server_id> --contract <파일>`로 등록한다. 계약 파일은 실행 경로(`executable`, 절대 경로), `argv`, 작업 디렉터리(`cwd`, 선택), `executable_sha256`, `script_sha256`(선택), 비밀이 아닌 `env`, 비밀 참조 ID(`secret_refs`)를 담은 JSON이고, 서버 행에는 URL 해시 없이 계약 해시와 판본이 저장된다. 이 서버는 LiteLLM 레지스트리·접근 권한 없이 MINT 표만으로 등록·승인되며 `check`와 플러그인 자가 점검의 레지스트리 대조에서 빠진다. 이미 등록된 서버에 다시 실행하면 계약 값을 갱신한다. `status`는 플러그인이 관측한 계약 불일치(`server_identity_mismatch_observed`)를 서버를 다시 등록하기 전까지 경보로 표시한다.

## 출력 형식

기본 출력은 사람이 읽는 텍스트이다. `--json`(명령 앞이나 뒤 어디에 두어도 된다)을 주면 표준 출력에 JSON 객체 한 개만 쓴다. 안내와 오류 메시지는 표준 오류로 나간다.

| 필드 | 의미 |
| --- | --- |
| `ok` | 명령이 성공했는지. `check`가 필수 설정 위반으로 실패해도 결과는 출력된다. |
| `command` | 명령 이름(`approve`, `org add` 등) |
| `id` | 변경의 중심이 된 객체의 식별자. 생성 명령은 만든 객체(승인·거부·이용 관계·동의·허용 목록·호출별 승인은 UUID, 조직·운영자·정책 판본은 이름), 상태 변경 명령은 대상 객체 |
| `state_version` | 변경 뒤 그 객체의 상태 버전 |
| `events` | 이 명령이 원장에 남긴 사건 목록(남긴 순서). 항목: `event_id`, `kind`, `source_key`, `entity`, `entity_id`, `state_version` |
| `token` | 토큰을 발급하는 명령(`operator add`, `operator bootstrap`)만. 다시 표시되지 않는다. |
| `notes` | `approve`가 알리는 주의 사항 목록 |

`id`와 `state_version`은 `events`의 첫 사건에서 온다. `approve`처럼 사건이 둘이면(`approval_granted`, `server_approved`) 첫 사건이 승인이다. `revoke --deny`는 `approval_revoked`, `denial_created` 순서이다.

명령별 추가 필드는 다음과 같다.

| 명령 | 추가 필드 |
| --- | --- |
| `init` | `migrations`(이번에 적용한 마이그레이션), `login_roles`(설정한 로그인 역할), `snippet_path`(설정 조각 파일) 또는 `snippet`(`--out -`일 때 본문) |
| `check` | `incomplete`(확인하지 못한 필수 행), `findings`(각 항목 `item`, `level`=`OK`·`INFO`·`WARN`·`FAIL`·`SKIP`, `message`), `observations`(관측 4항목) |
| `status` | `instance_id`, `mode`(`stored`, `ceiling`, `effective`), `default_org_id`, `policy_version`, `policy_shadow`(시험 판본이 있을 때만: `version`, `evaluated`, `allow_to_deny`, `deny_to_allow`, `other`, `errors`, `skipped`), `policy_bundle`(`state`: `match`·`mismatch`·`unverified`·`none`, `detail`), `servers`(상태별 개수), `enforcement`(워커별 최근 집행 점검 전환: `worker_id`, `passed`, `failed`, `last_transition_at`, `run_id`), `alerts`, `observations` |
| `sync status` | `grants`(각 항목 `id`, `target_type`, `target_id`, `item`, `server_id`, `tools`, `preexisting`, `observed`, `missing_count`, `held`, `held_at`, `last_applied_at`, `state_version`) |
| `ledger list` | `events`(각 항목 `event_id`, `inserted_at`, `kind`, `source_key`, `invocation_id`, `attempt_id`, `actor`, `subject`, `payload`, `final`) |

## 종료 코드

| 코드 | 의미 |
| --- | --- |
| 0 | 성공 |
| 1 | 명령을 수행할 수 없음: 입력 검증 실패, 상태 전이 위반, 직무 분리 위반, LiteLLM 읽기 실패, 데이터베이스 오류, `check`의 필수 설정 위반 |
| 2 | 명령줄 사용법 오류 |
| 3 | 실패는 없지만 필수 검증을 모두 수행하지 못함: `check`가 관리 API나 LiteLLM 설치본이 없어 필수 행을 확인하지 못했거나, `check`·`status`가 정책 엔진에서 활성 판본의 적재 내용을 읽지 못했다. |
| 4 | 인증 실패: 토큰이 없거나 틀렸거나 만료됨, 역할 부족 |

`check`는 필수 설정이 하나라도 어긋나면 1로 끝나고, 어긋남은 없지만 필수 행을 확인하지 못했으면 3으로 끝난다. 권장 설정 위반은 경고로 출력하고 종료 코드에 영향을 주지 않는다. 재승인 계획·`pin_reapproval` 차단 표지·사건·`sync_server` 작업은 같은 트랜잭션에서 기록한다. 명령 성공은 계획 등록을 뜻한다.

## 계약 재승인

`contract show <server_id>`와 `contract diff <server_id>`는 승인본·후보·관측본을 표시한다. `diff`의 관측값은 업스트림 시험 목록에서 얻은 원본이며 호출자에게 제공한 목록을 사용하지 않는다.

`contract reapprove <server_id> --intake <id> --tool-contract <candidate_id>`는 후보 도구 계약의 재승인 계획을 등록하고 `plan_id`·`job_id`를 돌려준다. 도구가 여러 개면 `--tool-contract`를 반복하고, 배포 값 변경에는 `--deployment-contract <candidate_id>`를 함께 지정한다. `--state-version`은 서버의 낙관적 잠금 버전이다. 신청자와 승인자는 서로 다른 사람이어야 하며, 후보 집합의 해시에 결속된 24시간 이내 통과 증거가 있어야 한다. 재검사는 수용검증 경로로 실행한다. 재승인자는 원래 신청자와도, 운영자가 `--url`로 제시한 배포 후보의 제시자와도 달라야 한다. 예외 승인(`intake except`)된 신청의 재승인은 `--second-approver`로 다른 admin 한 명이 더 필요하고(두 사람 모두 신청자·제시자와 달라야 한다), 원래 예외 승인의 유효 기한이 지났으면 새 예외 승인을 받아야 한다.

재승인 계획은 작업 실행기의 `sync_server`가 확정한다. LiteLLM에 새 계약을 다시 고정(pin)한 뒤 계획과 후보 id·판본·도구 집합을 다시 확인하고, 승인본·사건·고정 원장·계획 완료를 한 트랜잭션에서 확정한다. 불일치나 DB 실패이면 고정을 되돌리려 시도하고 기존 승인본과 먼저 커밋한 차단을 유지한다. 외부 고정과 DB 사이에는 분산 원자성이 없고 되돌리기도 실패할 수 있으므로, 실패했을 때는 차단이 안전 경계이다.

배포 후보를 등록하면 승인 전 서버 차단과 재승인 요청이 같은 트랜잭션에서 기록된다. 재검사 증거의 `inputs.contract_sha256`은 `SHA-256(JCS({tools: {도구명: 후보 sha256}, deployment: 배포 후보 sha256 또는 null}))`이다. 관측 작업은 수용검증 클라이언트의 업스트림 시험 목록(`test_tools_list`)을 쓰며, 이 연결이 없거나 관측이 실패하면 관측 시각을 갱신하지 않는다.

## 정책 번들 내용 대조

`check`와 `status`는 활성 정책 판본의 번들 해시를 정책 엔진(`MINT_OPA_URL`)이 실제로 적재한 규칙 원문과 정책 데이터에서 다시 계산해 등록된 값과 대조한다. 다르면 두 명령 모두 종료 코드 1로 끝나고(`ok`는 `false`, `status`는 경보도 표시한다), 정책 엔진에서 적재 내용을 읽지 못하면 필수 확인을 하지 못한 것이므로 두 명령 모두 종료 코드 3으로 끝난다. 활성 판본이 없으면 `check`는 경고만 하고 `status`는 성공으로 끝난다. 대조 시점 사이에 정책 엔진의 내용이 바뀌면 다음 대조까지 알 수 없다.

## 호출별 승인의 인자 지문

`call-approval request`는 인자 지문을 세 가지 방법 중 하나로 받는다.

- `--arguments '<JSON 객체>'` 또는 `--args-file <파일>`(읽을 수 없으면 오류로 끝난다): 호출 인자 원문으로 플러그인과 같은 함수(HMAC-SHA256, 키를 정렬하고 구분자 공백 없이 비ASCII 문자를 그대로 둔 JSON)로 지문을 계산한다. 키는 `MINT_FINGERPRINT_KEY`(없으면 비밀 파일이며, 권한이 0600이 아니거나 심볼릭 링크이면 거부한다)에서 읽고 키 판본은 `MINT_FINGERPRINT_KEY_VERSION`(`--fp-key-version`으로 바꿀 수 있다)을 쓴다.
- `--args-fp <지문>`: 차단 사건에 기록된 지문(소문자 16진 64자)을 그대로 넣는다.

`MINT_TARGET_PROFILES`에 프로필이 지정된 서버는 인자 원문(`--arguments`·`--args-file`)으로만 요청할 수 있다. 같은 규칙으로 대상과 행위를 뽑아 승인에 함께 기록하며, 이 값이 호출에서 뽑은 값과 같아야 승인이 쓰인다.

키가 없으면 인자 원문으로는 요청할 수 없고, 지문 키가 설정되어 있지 않으면 플러그인에서 호출별 승인은 항상 요구 상태로 남는다.

## 경보와 웹훅

경보는 종류와 대상으로 묶인다. `intake_pending`은 제출로 도입 신청이 만들어질 때, `call_approval_requested`는 승인이 없어 막힌 호출이 호출별 승인 요청을 자동으로 열 때 열린다(요청은 대기 상태이며 승인은 사람이 한다. 같은 주체·서버·도구·인자의 대기 요청이 있으면 새로 열지 않는다). 같은 묶음의 미해결 경보가 있으면 새로 만들지 않고 `count`와 `last_at`만 올린다. `job_failed`는 작업이 최대 시도 횟수를 넘겨 실패할 때, 같은 종류·대상의 작업이 이후 성공하면 해결된다. `approval_expiring`은 7일 안에 만료될 대기·확정 건과 활성 승인(같은 범위·도구로 더 늦게 끝나는 승인이 없는 것)마다 한 번 열리며, 운영자가 닫은 뒤에는 다시 열리지 않는다. `approval_recert_due`는 승인이 재확인 주기에 닿으면, `approval_recert_held`는 유예 안에 확인이 없어 승인이 보류되면 열리고, 콘솔 승인 내역의 「재확인」으로 확인하면 닫힌다.

경보가 열리면 `alert_opened`(순번 0), 확인되면 `alert_acknowledged`(순번 1), 해결되면 `alert_resolved`(순번 2) 사건을 같은 트랜잭션에 남긴다.

`MINT_WEBHOOK_URLS`를 설정하면 새로 열린 경보마다 주소별로 전송 작업이 하나 생긴다. 주소는 `https`만 받고, 호스트는 이 목록의 호스트로 한정한다. 전송은 총 3회 시도하며 요청마다 5초 제한을 둔다. 3번 모두 실패하면 전송 행을 `failed`로 두고 작업은 완료로 끝난다. 응답 본문은 저장하지 않는다.

서명 형식(수신 쪽이 검증하는 방법):

- 요청 헤더 `X-MINT-Signature`는 `t=<유닉스 초>,v1=<서명>`이다.
- 서명은 `HMAC-SHA256(키, "<t>.<본문>")`의 16진수 소문자 64자이며, `<본문>`은 요청 본문의 바이트 그대로다. 키는 `MINT_WEBHOOK_HMAC_KEY`다.
- 헤더 `X-MINT-Delivery`는 전송 식별자이며 수신 쪽이 중복을 거를 때 쓴다. 재시도는 같은 식별자로 새 서명을 붙여 보낸다.
- 수신 쪽은 `t`와 현재 시각의 차이가 5분을 넘으면 거부하고, 서명을 상수 시간 비교로 확인한다. 구현 예시는 `mint_litellm.control.webhook.verify`다.

본문 `console_url`은 `MINT_CONSOLE_URL`(선택)을 그대로 쓰며, 설정이 없으면 `null`이다. 본문 `summary`는 위험 요지, `action`은 담당자가 취할 조치 절차이며 경보 종류마다 정해진 문구다(알 수 없는 종류는 일반 문구).

`MINT_WEBHOOK_FORMATS`로 주소마다 형식을 고른다. `json`은 위 본문 그대로이고, `slack`은 Slack 수신 웹훅(블록), `teams`는 Microsoft Teams 수신 웹훅·Workflows(적응형 카드)용이다. 두 채팅 형식 모두 한국어 요지, 심각도, 서버, 조치 문구를 담고 콘솔 링크 버튼을 붙인다. 서명 헤더는 형식과 관계없이 같다.

승인 요청 경보(`call_approval_requested` 호출별 승인 요청, `intake_pending` 승인을 기다리는 도입 신청, `approval_recert_due`·`approval_recert_held` 승인 재확인, `approval_dormant` 미사용 승인)에는 `MINT_CONSOLE_URL`이 있을 때 해당 화면으로 가는 서명 링크(`/link/<토큰>`)가 붙는다(`json` 본문에서는 `action_url`). 토큰은 웹훅 서명 키에서 파생한 키로 서명하고 `MINT_LINK_TTL_SECONDS`(기본 24시간) 뒤 만료된다. 링크는 항목을 미리 골라 보여 줄 뿐이며 승인·철회를 하지 않는다. 열려면 평소처럼 콘솔에 로그인해야 하고, 승인은 콘솔에서 확인 단계(CSRF 포함)를 거쳐야 한다. 호출별 승인 요청과 신청 승인 대기 경보는 결정되거나 만료되면 승인 만료 검사 작업이 닫는다.

작업 `approval_dormant_scan`은 1시간마다 `MINT_DORMANT_DAYS`(기본 30일) 동안 판정에 한 번도 선택되지 않은 활성 승인을 찾는다. 기준 시각은 마지막 재확인(없으면 승인 시작)이라 갓 승인한 건은 들지 않는다. 서버마다 요약 경보 `approval_dormant`를 하나 열고(열려 있는 동안 다시 열지 않는다), 해당 승인이 없어지면 닫는다. 콘솔 승인 내역의 「미사용」 필터에서 관리자가 선택한 승인을 한꺼번에 「유지」(재확인으로 기준 시각을 새로 시작)하거나 「철회」(기존 철회 경로)한다.

## 패키지·취약점 통제

로컬 실행(stdio) 서버를 `server register-local`로 등록하면 실행 계약에서 쓰는 패키지를 알아내 제공처·이름·버전과 함께 적는다. npm(`npx`·`npm exec`·`pnpm dlx`·`bunx`), PyPI(`uvx`·`pipx run`·`uv tool run`·`python -m`), 컨테이너 이미지(`docker run`)의 호출 형태를 알아보고 계약의 실행 파일 내용 해시를 함께 적는다. 정확한 버전(이미지는 다이제스트나 `latest`가 아닌 태그)이 아닌 지정은 「버전 미고정」으로 보고 `package_unpinned` 경보를 연다. 이런 서버는 `unpinned_acceptance` 증빙 없이는 승인할 수 없다. 계약이 바뀌어 패키지 버전이 달라지면 계약 변경 경보의 요약과 본문 `package_changes`에 패키지 변화가 적힌다.

작업 `package_vuln_scan`은 `MINT_VULN_SCAN_SECONDS`마다 현재 계약의 npm·PyPI 패키지(버전이 고정된 것)를 OSV 형식 API(`POST /v1/querybatch`, 취약점 상세 `GET /v1/vulns/{id}`)로 조회해 결과를 저장하고 취약점마다 `package_vulnerable` 경보를 연다. 등급은 CVSS 3.x 점수와 조회처가 알려 주는 등급 중 높은 쪽이며, 악용 확인 표지(`known_exploited`)가 있으면 치명으로 본다. 조회가 안 되면 `vuln_feed_unreachable` 경보 하나만 열고 호출은 막지 않는다. 컨테이너 이미지는 조회하지 않는다.

치명 취약점(점수 9.0 이상, 등급 CRITICAL, 악용 확인)은 처음 확인한 시각부터 48시간 안에 조치해야 한다. 남은 시간이 24시간 이하가 되면 `package_vuln_due` 경보(`state: escalated`)를 열고, 기한이 지나면 같은 경보(`state: overdue`)와 함께 그 서버의 호출을 사유 `CONTRACT_DRIFT_vuln_overdue`로 막는다. 관측 모드로 풀 수 없다. 패키지를 고쳐 다시 등록·승인해 취약점이 조회에서 사라지거나, admin·approver가 `evidence attach vuln_exception <서버>`로 사유와 기한(30일 이하)을 붙이면 다음 주기에 풀린다.

## 조직 연결 제안

작업 `org_suggest_scan`은 LiteLLM 관리 API(`/team/list`, `/user/list`)로 팀·사용자를 읽어 아직 조직에 묶이지 않은 주체의 조직을 제안한다. 규칙은 이 순서로 처음 맞는 것을 쓴다: 팀 메타데이터의 `MINT_ORG_META_KEY` 값이 활성 조직 식별자와 같음(`team_metadata`), 팀 별칭이 조직 식별자나 이름으로 시작하고 뒤가 문자·숫자가 아님(`team_alias`, 같은 길이로 두 조직에 맞으면 제안하지 않음), 사용자 이메일 도메인이 대응표(`org domain set`)에 있음(`email_domain`). 키는 팀·사용자를 거쳐 조직이 정해지므로 제안하지 않는다. 최근 7일 안에 판정 사건이 있는 주체가 먼저 나온다. 제안은 저장만 하며 관리자가 콘솔 「운영자·조직」의 「적용」·「무시」(규칙별 일괄 적용 포함)나 `org suggest apply`로 적용해야 묶인다. 적용할 수 없는 제안(이미 묶임, 닫힌 조직)은 일괄 적용에서 건너뛴다. 제어 평면 키의 허용 경로에 `/user/list`가 있어야 한다.

## 원장 조회

`ledger list`는 `--kind`, `--since`, `--until`, `--invocation-id`로 사건을 거른다. 호출이 차단되었을 때 오류 본문의 `reference`(`<호출 식별자>:<시도 번호>`)는 `--decision-ref`에 그대로 넣으면 그 판정 사건 하나를 찾는다. `--decision-ref`와 `--invocation-id`는 함께 쓸 수 없다. 한 호출의 판정 사건이 시도 번호별로 여럿이면(감사 기록 결과가 불명이어서 호출을 막은 경우 등) 시도 번호가 가장 큰 사건이 최종 집행이다. 사람이 읽는 출력에는 그 줄 끝에 `최종`이 붙고, 판정 사유(`사유 CANCELLED` 등)와 이전 시도 참조(`이전 시도 <호출 식별자>:<시도 번호>`, 사건 `payload`의 `original_decision_ref`)도 나온다. `--json`에서는 사건마다 `final`이 `true`(그 호출의 시도 중 번호가 가장 큰 사건) 또는 `false`이며, 호출 식별자가 없는 사건은 `false`이다. 목록 판정(발견) 사건도 같은 규칙이다. 호출이 어떻게 끝났는지는 `final`이 `true`인 사건의 집행 결과와 사유로 읽고, 이전 시도의 사건은 최종 집행에 이르기 전의 기록으로 본다. `--kind`나 `--limit`으로 걸러도 `final`은 걸러지지 않은 전체 시도를 기준으로 정해진다.

## 지문 키 점검

`check`는 `MINT_FINGERPRINT_KEY`(base64url, 32바이트 이상)와 `MINT_FINGERPRINT_KEY_VERSION`(1 이상의 정수)을 필수 행으로 확인한다. 환경 변수에 없으면 `MINT_SECRETS_FILE`의 비밀 파일을 읽는다. 키가 없거나 형식이 틀리면 종료 코드 1이고, 파일의 권한·링크·디렉터리 정책 위반이나 읽기·해독 오류로 읽을 수 없으면 확인하지 못한 것으로 종료 코드 3이다. 결과 줄에는 검사한 값의 출처(이 프로세스의 환경 변수, `--env-file`, 비밀 파일 경로)가 함께 나온다. 이 행은 제공된 값의 유효성만 확인하며, 이미 실행 중인 LiteLLM 서비스가 실제로 받은 값과 대조하지는 않는다. 서비스를 다시 만든 뒤에 같은 비밀 파일을 읽는 `check`를 실행해야 서비스와 같은 값을 검사한다.

## 집행 점검 상태

`status`는 워커마다 가장 최근의 `enforcement_verified`·`enforcement_unverified` 사건을 읽어 통과 여부, 실패와 원인, 마지막 전환 시각, 그 전환을 일으킨 실행 식별자를 보여 준다. 재시작한 워커는 같은 워커 식별자의 기록이 한 줄로 합쳐지며, 다른 워커의 기록이 밀려나지 않는다. 표시는 「최근 전환」이며, 그 워커가 지금 살아 있다는 뜻이 아니다.

## 설정 조각과 기동 전 검사

`init`이 만드는 설정 조각에는 `litellm_settings.callbacks`가 없다. MINT 로거는 MINT 가드레일이 등록하므로 `callbacks`에 로거가 적혀 있으면 기동 전 검사와 `check`가 거부한다. 기동 전 검사와 `check`는 주 설정 파일이 아니라 LiteLLM의 설정 로더가 `include`까지 병합한 설정을 검사한다. 이 로더를 쓸 수 없으면 `include`가 있는 설정을 거부하고, 파생 이미지의 기동 전 검사는 로더가 없으면 통과시키지 않는다.

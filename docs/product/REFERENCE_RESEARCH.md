# 레퍼런스 조사: 웹 콘솔·PC 터미널(`mint`)

작업 번호 PC-REF-01 · 기준 커밋 96b7f85

기존 결정(LiteLLM 테마 콘솔, 단독형 kit_screen 터미널 화면)은 바꾸지 않는다. 이 문서는 그 위에서 정보 구조·권한·거부 안내·승인·긴급 통제·CLI 규칙을 정하기 위한 근거다.

## 0. 출처 표기 규칙

| 표기 | 뜻 |
|---|---|
| 실행 캡처 | 이 PC에서 실제로 실행해 `docs/product/references/cli/`에 원문을 저장함 |
| 문서 확인 | 공식 문서 페이지를 가져와(WebFetch) 읽음. 가져오기 도구가 요약해 준 쪽이라 표·문구를 그대로 옮긴 곳은 따옴표로 구분함 |
| 미확보 | 가져오지 못했거나 시도하지 않음. 이 문서의 어떤 결론도 미확보 출처에 기대지 않음 |

## A. 웹 UI 레퍼런스

### A.1 확인한 출처

| # | 제품 | URL | 표기 |
|---|---|---|---|
| W1 | GitHub | https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization | 문서 확인 |
| W2 | GitHub | https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/reviewing-deployments | 문서 확인 |
| W3 | GitHub | https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization | 문서 확인 |
| W4 | GitHub | https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-and-revoking-personal-access-tokens-in-your-organization | 문서 확인 |
| W5 | Vercel | https://vercel.com/docs/deployment-protection | 문서 확인 |
| W6 | Vercel | https://vercel.com/docs/rbac/access-roles | 문서 확인 |
| W7 | Vercel | https://vercel.com/docs/deployment-protection/methods-to-protect-deployments/vercel-authentication | 문서 확인 |
| W8 | Cloudflare | https://developers.cloudflare.com/cloudflare-one/policies/access/ | 문서 확인 |
| W9 | Cloudflare | https://developers.cloudflare.com/waf/tools/security-level/ | 문서 확인 |
| - | 1Password | https://support.1password.com/manage-team-members/ , https://support.1password.com/cs/suspend-team-member/ | 미확보(둘 다 HTTP 404) |
| - | Cloudflare Under Attack 전용 페이지 | https://developers.cloudflare.com/fundamentals/security/under-attack-mode/ | 미확보(404, W9로 대체) |
| - | GitLab, Sentry, Grafana, Datadog | - | 미확보(시도하지 않음. 필수 3개 이상은 GitHub·Vercel·Cloudflare로 충족) |

화면 캡처(스크린샷)는 하지 않았다. 모든 화면 설명은 문서 글에 근거하며, 실제 화면의 배치·문구는 확인하지 못했다.

### A.2 제품별 분석

#### GitHub (W1~W4)

- **정보 구조·역할 분리.** 권한(permission)은 단일 동작, 역할(role)은 권한 묶음이다. 역할은 저장소·팀·조직 세 층에 있다. 조직에는 소유자(Owner, "전체 관리 권한"; 최소 2명 권장)와 구성원(Member, 기본 비관리 역할)이 있고, 사전 정의 역할(moderator, billing manager, security manager, GitHub App manager)이 그 사이를 메운다. 사용자 지정 조직 역할로 "감사 로그 보기" 같은 좁은 권한만 줄 수 있다(Enterprise Cloud 한정). 앱 관리자 역할은 앱 설치·제거 권한은 없다. (W1)
- **승인·검토 흐름.** 배포 검토는 실행 화면 알림 -> 「Review deployments」 -> 대상 환경 선택 -> 선택 의견 -> 「Approve and deploy」 또는 「Reject」다. 승인은 다른 보호 규칙이 모두 통과된 뒤에야 작업을 진행시키고, 반려하면 작업이 실패한다. 환경이 자기 승인 금지를 켜면 실행을 시작한 사람은 승인할 수 없다. (W2)
- **감사 로그.** 소유자만 설정 > Logs > Audit log로 본다. 자유 텍스트 검색은 없고 `operation`·`repo`·`actor`·`action`·`created`·`country` 한정자와 `-` 제외 연산자로 거른다. 거른 뒤 JSON/CSV로 내보내며(100MB·10분 제한) 보존은 180일, 기본 표시는 최근 3개월이다. (W3)
- **긴급 통제·회수.** 소유자가 설정 > Personal access tokens > Active tokens에서 세부 토큰을 보고 이름을 눌러 접근 범위·권한을 확인한다. 일괄 회수 때는 소유자(만든 구성원)·저장소 접근·권한으로 거른다. 회수하면 만든 사람에게 이메일이 가고, 토큰이 만든 SSH 키는 남으며 공개 자원 읽기는 계속된다. 이 화면은 세부 토큰만 다루고 클래식 토큰은 만료 전까지 쓸 수 있다. (W4) 한계가 화면에 명시돼 있다는 점이 좋은 선례다.
- **문서가 다루지 않은 것.** W1은 감사 로그를 기본으로 누가 보는지 설명하지 않는다. W4는 토큰 "신청 -> 승인" 흐름을 설명하지 않는다(문서 확인, 이 문서는 해당 흐름을 근거로 삼지 않는다).

#### Vercel (W5~W7)

- **정보 구조.** 보호는 프로젝트 설정 > Deployment Protection 한 곳에서 「방법」(Vercel Authentication·Password·Trusted IPs)과 「범위」(Standard·All Deployments 등)를 따로 고른다. 팀 기본값을 두고 프로젝트에서 덮어쓴다. 요금제별 가용성을 문구로 표시한다. (W5)
- **역할 분리.** 팀 층(Owner, Member, Developer, Security, Billing, Viewer, Contributor)과 프로젝트 층(Administrator, Developer, Viewer)의 두 층이다. 소유자만 역할 변경·구성원 초대·결제를 한다. Member는 프로젝트를 다 만지지만 초대·결제는 못 한다. Security 역할은 방화벽·보호만 관리하고 기본으로 배포 권한이 없다. Contributor는 명시적으로 배정되지 않은 프로젝트에 접근할 수 없다. 역할에 권한 그룹(Usage Viewer 등)을 얹어 맞춤 구성한다. (W6)
- **권한 거부 처리(핵심).** 보호된 배포에 접근 권한이 없는 로그인 사용자는 「접근 요청」으로 보내진다. 요청은 분기 작성자에게 이메일과 알림을 보내고, 소유자·구성원·관리자·개발자가 수락/거절하며, 허용한 접근은 언제든 회수한다. 처리 화면은 프로젝트 설정의 Requests(대기)와 Access(부여됨) 두 구역이고 배포 공유 창에서도 처리한다. (W7)
- **긴급 통제.** 보호를 끄면 모든 기존 배포가 즉시 무보호가 된다고 문서가 경고한다. 다시 켜도 이미 로그인한 사용자는 쿠키로 접근이 유지된다. 우회 비밀을 재발급·삭제하면 자동화가 같이 끊긴다는 영향도 화면 문서에 적혀 있다. WAF Deny 규칙은 "재배포 없이 게시 즉시" 적용된다. (W5, W7)

#### Cloudflare (W8, W9)

- **Access 정책 모델.** 정책은 동작(Allow/Block/Bypass/Service Auth) 하나와 규칙(Include=OR, Exclude=NOT, Require=AND)으로 이뤄진다. 기본 거부(deny by default)이고, Bypass·Service Auth가 먼저 평가되고 Block·Allow는 위에서 아래로 첫 일치에서 끝난다. Bypass는 로그가 남지 않고 신원 선택자를 쓸 수 없다는 경고가 붙는다. (W8) 승인·사유 요구는 이 페이지에 없다. 차단 화면 문구도 이 페이지에 없다.
- **긴급 스위치.** Under Attack 모드는 켜면 방문자에게 관리형 챌린지 화면이 보이고, 「활성 DDoS 공격 중에만 켜라」「API 같은 트래픽이 끊길 수 있다」「일부 경로에만 쓰려면 구성 규칙」이라는 사용 조건과 부작용이 함께 적혀 있다. (W9) 켜는 위치가 대시보드 판에 따라 다르다는 설명도 있어, 위치 안내가 문서 부담이 됨을 보여 준다.

### A.3 비교표

| 항목 | GitHub | Vercel | Cloudflare | 우리 콘솔 현재(근거) |
|---|---|---|---|---|
| 역할 층 | 조직(소유자·구성원·사전 정의·사용자 지정) | 팀 8종 + 프로젝트 3종, 권한 그룹 | (문서 미확인) | viewer·approver·admin + root(`admin.html` 권한 선택) |
| 직무 분리 | 환경별 자기 승인 금지 | 소유자만 역할 변경 | - | 운영자 직무 분리 코드 `SEPARATION_OF_DUTIES` |
| 승인 화면 | 실행 알림 -> 검토 -> 의견 -> 승인/반려 | Requests 구역에서 수락/거절, 공유 창에서도 | - | `approval_center.html`, `intakes.html` |
| 거부 시 안내 | - | 「접근 요청」 화면으로 보냄 | (문서 미확인) | 403 제목만 「이 작업을 할 수 있는 역할이 아닙니다」(`error_pages.py` 20행) |
| 감사 | 한정자 검색, 내보내기, 180일 | - | - | `audit_report.html`, `ledger.html` |
| 긴급 정지 | 토큰 일괄 회수(범위·한계 명시) | 보호 끄기 경고, 우회 비밀 재발급 영향 | Under Attack(조건·부작용 명시) | 서버 중지 확인창(`_server_actions.html`) |

### A.4 우리 콘솔 규칙 (출처 인용)

번호는 `W-nn`. 근거 열의 W번호는 A.1의 출처다.

| 규칙 | 내용 | 근거 |
|---|---|---|
| W-01 | 모든 권한 거부 화면은 (1) 어떤 정책·역할 때문인지, (2) 영향 범위(어느 서버·팀), (3) 「권한 요청」 버튼(승인할 수 있는 사람 이름 포함)을 보여 준다. 제목만 있는 403 화면은 쓰지 않는다. | W7(권한 없는 사용자를 접근 요청으로 보냄, 요청이 담당자에게 알림) |
| W-02 | 권한 요청은 신청 목록(직원)과 승인 대기(승인자)에서 같은 하나의 항목으로 보이고, 승인자 화면에 대기/부여됨 두 구역을 둔다. 부여한 것은 같은 화면에서 회수한다. | W7(Requests·Access 두 구역, 회수) |
| W-03 | 승인 화면의 결정은 승인·반려 두 개와 선택 의견뿐이다. 반려는 흐름을 실패 상태로 끝내고, 승인은 다른 보호 규칙이 통과된 뒤에만 효력이 생긴다고 화면에 쓴다. | W2 |
| W-04 | 자기 신청은 자기가 승인할 수 없다. 그 이유를 버튼 비활성 대신 한 줄 설명으로 보여 준다. | W2(자기 승인 금지) |
| W-05 | 역할은 「누가 무엇을 못 하는가」로도 적는다(예: 승인자는 역할 변경·초대 불가). 역할 선택 화면에 각 역할이 하지 못하는 일 한 줄을 병기한다. | W6(Member는 초대·결제 불가, Security는 배포 불가) |
| W-06 | 역할에 없는 권한은 별도 권한 묶음으로 얹는 구조를 유지하고, 조직 전체 권한은 root 하나로 모은다. root는 최소 2명을 권장한다는 경고를 설정 화면에 둔다. | W1(소유자 최소 2명), W6(권한 그룹) |
| W-07 | 감사 목록은 자유 텍스트가 아닌 한정자 필터(행위자·행위·대상·기간·결과)와 내보내기(JSON/CSV), 기본 표시 기간·보존 기간을 화면 위에 적는다. 내보내기 전에 거르라는 한도 안내를 둔다. | W3 |
| W-08 | 긴급 정지·차단 버튼은 확인 창에 (1) 영향받는 대상 수, (2) 즉시 일어나는 일, (3) 되돌리는 방법, (4) 남는 것(예: 이미 발급된 것은 유지)을 모두 적는다. 현재 서버 중지 확인창이 (1)(2)(3)을 갖췄고 (4)가 없다. | W4(회수 후 남는 것 명시), W5(끄면 즉시 무보호), W9(사용 조건·부작용) |
| W-09 | 보호를 약화하는 설정(보호 끄기, 우회 허용, 감사 끄기)은 저장 전에 영향 문구를 보여 주고 감사에 남긴다. 우회는 로그가 안 남는다는 식의 예외를 만들지 않는다. | W5, W8(Bypass는 로그 없음 경고) |
| W-10 | 정책은 동작(허용·차단·검토)과 조건(포함·제외·필수)을 분리해 보여 주고, 평가 순서와 「기본 거부」를 화면에 적는다. | W8 |
| W-11 | 한 화면에 설정이 많을 때 「방법」과 「범위」를 나눈 두 단계 선택을 쓰고, 기본값(조직)과 개별 덮어쓰기를 구분해 표시한다. | W5 |
| W-12 | 요금제 같은 사용 불가 사유는 숨기지 말고 비활성 옆에 사유 한 줄을 적는다. 우리 쪽은 「이 정책은 root만 바꿈」 같은 사유에 해당한다. | W5, W6 |
| W-13 | 회수 화면에는 기능의 한계를 명시한다(예: 「이 PC 키만 회수, 이미 받은 파일은 남음」). | W4 |

## B. CLI 레퍼런스

### B.1 확인한 출처

| # | 도구 | 출처 | 표기 |
|---|---|---|---|
| C1 | `gh` 2.102.0 | 이 PC에서 실행. 저장 파일 `references/cli/gh-*.txt` 11개 | 실행 캡처 |
| C2 | `mint`(우리) | `python src/mint_litellm/endpoint/kit/mint_kit.py ...`. 저장 파일 `references/cli/mint-*.txt` 9개 | 실행 캡처 |
| C3 | Vercel CLI | https://vercel.com/docs/cli/global-options | 문서 확인(실행 안 함) |
| C4 | AWS CLI | https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-output-format.html | 문서 확인(실행 안 함) |
| C5 | kubectl | https://kubernetes.io/docs/reference/kubectl/ | 문서 확인(실행 안 함). 출력 형식·종료 코드 부분은 가져오기가 잘려 미확보 |
| C6 | wrangler | https://developers.cloudflare.com/workers/wrangler/commands/ | 문서 확인(실행 안 함). 인증·전역 플래그·CI는 이 페이지에 없어 미확보 |
| - | aws, az, docker, kubectl, wrangler, vercel, stripe | Windows와 WSL kali 모두에 없음(설치하지 않음) | 실행 안 함 |

`gh auth status` 출력은 계정 정보가 있어 저장소에 넣지 않았다(토큰은 출력에서도 가려진다).

### B.2 `gh`(실행 캡처) 분석

| 관점 | 관찰(파일) |
|---|---|
| 계층 | `gh <command> <subcommand> [flags]`. 최상위 도움말이 「CORE / GITHUB ACTIONS / ALIAS / ADDITIONAL COMMANDS」 묶음별로 한 줄 설명을 나열한다(`gh-help-top.txt`). |
| 이름 규칙 | 명사 -> 동사(`pr list`, `repo view`, `issue view`). 별칭 `pr ls`, `co`(=`pr checkout`)를 도움말에 표시한다(`gh-help-pr-list.txt`). |
| 도움말 배치 | 설명 -> USAGE -> ALIASES -> FLAGS(짧은/긴 이름·값 종류·설명·기본값) -> 예시 -> 「더 알아보기」 링크. 플래그마다 설명이 있고 기본값이 괄호로 적힌다. |
| 비대화형 | 필터 플래그(`--state`, `--limit`)와 `--json`, `--jq`, `--template`이 모든 목록·조회 명령에 공통이다. 대화형 프롬프트는 `gh config`의 `prompt=enabled`로 끌 수 있다(`gh-config.txt`). |
| JSON | `gh repo view cli/cli --json name,visibility,defaultBranchRef` -> 한 줄 JSON(`gh-json-repo.txt`). 없는 필드를 쓰면 「Unknown JSON field」와 쓸 수 있는 필드 전체 목록을 보여 준다(`gh-err-bad-json-field.txt`). |
| 오류 | 알 수 없는 플래그: `unknown flag: --bogus` 뒤에 그 명령의 도움말 전체(`gh-err-unknown-flag.txt`). 인자 부족: `accepts 1 arg(s), received 0`로 한 줄뿐이다(`gh-err-missing-arg.txt`, 회복 힌트 없음). 없는 저장소: 서버 메시지 그대로(`gh-err-notfound.txt`). 종료 코드는 이 세 오류 모두 1이다(각 캡처 마지막 줄 `[exit=1]`). 사용법 오류와 실행 오류를 코드로 구분하지 않는다. |
| 인증·설정 | `gh auth status`가 계정·프로토콜·토큰(가림)·범위를 보여 준다(실행 확인, 캡처는 계정 정보 때문에 저장소에 넣지 않음). 설정은 `gh config list`로 키=값(`gh-config.txt`). |

### B.3 문서 기준(실행 안 함)

| 도구 | 확인한 사실 | 출처 |
|---|---|---|
| Vercel CLI | 전역 옵션 `--cwd`, `--debug/-d`, `--scope/-S`(팀), `--project`, `--token/-t`와 `VERCEL_TOKEN`(CI는 환경 변수 권장, 명령줄은 프로세스 목록에 노출), `--no-color`와 `NO_COLOR`, `--non-interactive`(에이전트 환경이면 기본). 종료 코드: 0 성공·도움말, 1 운영 실패, 2 사용법 오류(없는 하위 명령 도움말도 2), 도움말은 stdout. 프로젝트 지정 우선순위(플래그 > 환경 변수 > 연결 파일)가 문서화돼 있다. | C3 |
| AWS CLI | 출력 `json`(기본)·`yaml`·`yaml-stream`·`text`·`table`·`off`. 지정 순서(`--output` > `AWS_DEFAULT_OUTPUT` > 설정 파일). `--query`로 필드를 고른다. `text`는 항상 `--query`와 쓰라고 권고(열 순서가 바뀌므로). `off`는 stdout만 끄고 오류는 stderr에 남아 종료 코드로 판단한다. | C4 |
| kubectl | `kubectl [command] [TYPE] [NAME] [flags]`. 자원 이름이 단수·복수·약어 모두 허용(`pod`, `pods`, `po`). 하위 명령 중첩(`config set-context`, `rollout undo`, `auth can-i`). `auth can-i`는 권한 사전 확인용 하위 명령이다. 출력 형식 세부는 미확보. | C5 |
| wrangler | `wrangler <COMMAND> <SUBCOMMAND> [PARAMETERS] [OPTIONS]`. 21개 그룹. 로컬 설치 후 `npx`·스크립트로 쓰라고 권장. 인증·CI는 미확보. | C6 |

### B.4 `mint` 현황(실행 캡처 + 코드 읽기)

구조: `main()`은 첫 인자가 `CLI_COMMANDS`(`screen add requests get inspect relink app`)에 있으면 `cli_main`(prog=`mint`), 아니면 설치기 파서로 간다(`mint_kit.py` 6393·6743행 근처). 사용자가 보는 `mint --help`는 설치기 쪽 도움말이다.

| 관점 | 관찰(파일) |
|---|---|
| 최상위 도움말 | 설명 한 줄(「MINT endpoint kit」)과 옵션 이름만 있고 옵션 설명이 모두 비어 있다. `add`·`app`·`get`·`requests` 등 사용자 명령이 아예 나오지 않는다(`mint-help-top.txt`). |
| 하위 도움말 | `mint add --help`는 인자·옵션 이름만 있고 설명이 없다. `--grade`, `--ro`, `--rw`, `--request-id` 의미를 알 수 없다(`mint-help-add.txt`). `mint app --help`도 하위 명령 이름만(`mint-help-app.txt`). |
| 이름 규칙 | 동사 단독(`add`, `get`, `inspect`, `relink`)과 `app new|list|rm|run|env|mcp`(명사 -> 동사)가 섞여 있다. 설치기 쪽은 `install|uninstall|status|check|sync|report`. |
| 오류: 알 수 없는 플래그 | argparse 기본 문구(`mint: error: unrecognized arguments: --bogus`), 종료 코드 2(`mint-err-unknown-flag.txt`). 힌트 없음. |
| 오류: 인자 부족 | `the following arguments are required: name`(영문 argparse 문구, 한국어 아님)(`mint-err-missing-arg.txt`). |
| 오류: 키트 없음 | `mint --kit C:/nonexistent add ...`는 `--kit`이 앞에 오면 `CLI_COMMANDS` 판별이 안 돼 설치기 파서로 가서 `invalid choice: 'add'`가 나온다(`mint-err-no-key-add.txt`, `mint-requests-nokit.txt`). 사용자에게는 혼란스러운 오류다. |
| 오류: 설치 안 됨 | `status --json`을 키트 폴더 없이 실행하면 파이썬 트레이스백과 `FileNotFoundError ... kit.json`이 그대로 나온다(`mint-json-status.txt`). 사용자 문구 없음. |
| JSON | 설치기 쪽만 `--json`(전역 옵션)이 있다. `mint get/requests/inspect/add/app list`에는 없다. 비 TTY에서 `mint`(화면)는 `state`를 JSON으로 출력한다(코드 6417행 근처). |
| 비대화형 | `mint add`는 TTY 여부로 대화형을 고르고 `--yes`로 확인을 건너뛴다. `--non-interactive`, `NO_COLOR` 같은 명시 옵션은 없다. |
| 한국어 오류 | 서버 통신 오류는 한국어 문구(`NO_GATEWAY`=「게이트웨이에 닿지 못함」, `KEY_REJECTED_TEXT`=「한 줄 설치 명령을 다시 붙여 넣으십시오 (mint relink 주소)」). 이쪽은 회복 힌트가 있어 좋은 편이다. |
| 종료 코드 | argparse 오류는 2, 앱 명령 실패는 1(`run_app`). 문서화돼 있지 않다. |

### B.5 `mint` CLI 규칙과 격차

규칙(근거는 B.2·B.3):

| 규칙 | 내용 | 근거 |
|---|---|---|
| C-01 | 모든 옵션에 한국어 한 줄 설명을 단다. 최상위 도움말은 사용자 명령을 묶음(자주 쓰는 일 / 앱 자격 / 설치·유지)으로 보인다. 예시 2~3개를 도움말 끝에 둔다. | C1(`gh` 도움말 구성) |
| C-02 | 이름은 `명사 동사`로 통일한다(`mint app new`처럼). 새 명령은 이 형태로 만들고, 기존 단독 동사는 별칭으로만 유지한다. | C1, C5 |
| C-03 | 목록·조회 명령은 모두 `--json`을 받는다. 없는 필드를 쓰면 가능한 필드 목록을 보여 준다. | C1(`gh-err-bad-json-field.txt`), C4 |
| C-04 | 종료 코드: 0 성공·도움말, 1 실행 실패, 2 사용법 오류. 문서에 표로 적는다. | C3 |
| C-05 | 사용법 오류는 한국어로 쓰고, 맞는 사용 예를 한 줄 덧붙인다. 도움말 전체를 뿌리지 않는다. | C1(전체 도움말 덧붙임은 길어서 일부러 피함) |
| C-06 | 모든 오류 문구는 「무슨 일 + 이유 + 다음에 칠 명령」 세 부분이다. 트레이스백은 `--debug`에서만 보인다. | C1(`gh-err-missing-arg.txt`가 반례), C3(`--debug`) |
| C-07 | `--non-interactive`(또는 TTY 아님 자동 감지), `NO_COLOR`, 인증은 환경 변수 우선을 지원한다. 명령줄에 비밀을 받는 옵션은 두지 않는다. | C3 |
| C-08 | 상태 확인 하위 명령(`mint whoami`/`mint status`)이 계정·서버·키 상태·범위를 한 번에 보인다. 권한 사전 확인(`mint can-i <서버>`)은 선택 항목. | C1(`gh auth status`), C5(`auth can-i`) |
| C-09 | 설정은 `mint config list` 같은 단일 위치로 보이게 한다. | C1(`gh config list`) |

격차(구체적 결함, 중요도 순 상위 10개는 보고 8항에 있음):

1. `mint --help`가 사용자 명령(`add`, `get`, `app` 등)을 보이지 않는다.
2. 옵션 설명이 전부 없다(`add`의 `--grade`, `--ro`, `--rw`).
3. 키트가 없을 때 트레이스백이 나온다(`status --json`).
4. `--kit`이 서브명령 앞이면 엉뚱한 파서로 간다.
5. `--json`이 `get`·`requests`·`inspect`·`app list`에 없다.
6. 인자 오류가 영어 argparse 문구이고 예시·다음 명령이 없다.
7. 종료 코드 규약 문서 없음.
8. `--non-interactive`·`NO_COLOR` 없음.
9. `app`의 하위 명령 이름(`rm`)이 `add`의 반대(`remove`)와 일관되지 않음.
10. 설치기 쪽 `--json`은 전역이라 `check`·`sync` 등과 어떻게 다른지 도움말에 없다.

## C. 우리 콘솔 현재 상태 점검(코드 읽기)

- 403 오류 화면: 제목 「이 작업을 할 수 있는 역할이 아닙니다」와 참조 번호, 되돌아가기 버튼뿐이다(`console/error_pages.py` 16~22행, `templates/error.html`). 정책 이름·영향 범위·요청 버튼이 없다. W-01 위반.
- 역할 선택: 조회자·승인자·관리자 세 가지이고 각 항목은 「할 수 있는 일」만 적었다(`templates/admin.html` 34행). 하지 못하는 일은 적지 않았다. W-05.
- 서버 중지 확인창: 영향 서버 수·승인 수·되돌리기(재개)를 적었다(`templates/_server_actions.html` 4행). 남는 것(이미 받은 키 등)은 적지 않았다. W-08.
- 메뉴 분리: 관리자 메뉴와 직원 화면이 분리돼 있다(`templates/base.html` 20~34행). 역할 바꾸기·세션 폐기는 서버에서 처리된다(`docs/CLI.md`).

## D. 한계

- 웹 화면의 실제 배치·문구는 보지 못했고 문서 글만 근거다. 다른 제품(GitLab·Sentry·Grafana·Datadog·1Password)은 확보하지 못했다.
- `kubectl`·`aws`·`vercel`·`wrangler`는 설치돼 있지 않아 실행하지 않았다. 오류 출력·도움말 배치는 이 네 도구에 대해 확인하지 못했다.
- 가져오기 도구는 페이지를 요약해 준다. 따라서 문서 확인 항목은 원문과 단어까지 같지 않을 수 있다.

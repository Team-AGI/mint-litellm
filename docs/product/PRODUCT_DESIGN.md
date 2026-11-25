# 제품 재설계 (PC-DESIGN-01)

작성: Claude Mythos 5.2(설계·UX 검토). 채택·보류는 DECISION_LOG와 CHANGE_PROPOSALS를 따른다.
구현 작업 묶음(WP)과 화면 동작 ID는 이 문서와 SCREEN_ACTION_MATRIX가 기준이다.

근거는 직접 읽은 파일·줄과 캡처 파일명만 썼습니다. 코드로 확인하지 못한 것은 「추정」 또는 「확인 필요」로 표시했습니다. 경로 약칭: `T/` = `src/mint_litellm/console/templates/`, `P/` = `src/mint_litellm/console/pages/`, `C/` = `src/mint_litellm/console/`.

---

## A. 현재 제품 진단

### A.1 역할별 여정에서 막히는 곳

| # | 역할 | 막히는 곳 | 근거 |
|---|---|---|---|
| A1 | 직원 | 승인된 서버가 2개인데 직원 화면에는 「쓸 수 있는 MCP 서버가 없습니다」만 나오고, 할 수 있는 일은 새 신청뿐이다. 이미 승인된 서버를 「나도 쓰게 해 달라」고 요청할 길이 없다. | staff-staff.png(승인됨 0), admin-servers.png(승인됨 2), `T/staff_servers.html:49` |
| A2 | 직원 | 「내 요청 → 내 승인 요청」은 읽기 전용이다. 막힌 도구의 권한 요청 양식이 없다(FM-60, E2E-09). | `T/staff_requests.html:41-50`, staff-staff_requests.png |
| A3 | 직원 | 본인 확인 「확인」 단추가 호출한 키와 같은 키로 로그인하면 비활성이고 안내는 툴팁뿐이다. 키가 하나뿐인 직원은 확인할 수 없다(추정). | `T/staff_requests.html:22` |
| A4 | 직원 | 거부 응답 첫 줄이 「관리자에게 요청하십시오」에서 끝나고, 어디서 어떻게 요청하는지 없다. | `types/errors.py:30-33, 250-252` |
| A5 | 직원 | 「내 단말 → 연결 해제」 문구는 「이 단말의 키가 지워집니다」인데 실제로는 그 사람의 모든 PC 키를 해제한다. | `T/staff_endpoint.html:85`, `C/staff_pages.py:1166-1167` |
| A6 | 직원 | 「내 사용량」의 「서버별 호출」 차트가 빈 상자다. 직원 화면 틀이 차트 스크립트를 싣지 않는다. | staff-staff_usage.png, `T/staff_base.html:10-11`, `T/_usage_tables.html:8` |
| A7 | 승인자 | 승인 센터 기본 탭이 「호출」이라 대기 1건(서버 도입)이 있어도 빈 화면부터 본다. | admin-approvals.png, `P/approvals.py:96` |
| A8 | 승인자·조회자 | 메뉴가 역할로 걸러지지 않는다(가입 요청만 예외). 할 수 없는 화면에 들어가면 사유 없는 403을 만난다. | `T/macros.html:118`, `C/error_pages.py:17-23` |
| A9 | 관리자 | 로컬 신청이 「판별 불가」일 때 쓰는 단말 검사 권한(`/intakes/{id}/inspect`) 단추가 화면에 없다. 처리기는 `inspect.can`까지 계산하지만 템플릿은 대기 문구만 그린다. | `P/servers.py:876, 1078-1090`, `T/intake_detail.html:24`, admin-intakes.png(binary_ninja_mcp 3시간 정체) |
| A10 | 관리자 | 「예외 승인」(`decision=except`) 처리기는 있는데 단추는 승인·거부 둘뿐이다. | `P/servers.py:1164`, `T/intake_detail.html:122-125` |
| A11 | 관리자 | 승인 뒤 「키 반영 대기」에서 멈춘 원인이 신청 상세에 없다. 경보에는 「승인 대상(키·팀) 없음」이 따로 있다(같은 건인지는 추정). 대상 바꾸기 단추도 없다. | admin-detail-intakes.png, admin-alerts.png |
| A12 | 관리자 | 서버 목록에서 승인 대기 서버를 누르면 「요청을 처리하지 못했습니다」가 뜬다. 원인은 확인하지 못했다. | admin-detail-servers.png, index.json(`/servers/binary_ninja_mcp`) |
| A13 | 관리자 | 「서버 폐기」는 서비스와 서버 명령에만 있고 웹 라우트가 없다. 웹에서는 이용 관계 단위 종료만 된다. | `control/services/servers.py:53-58`, `docs/CLI.md:51`, `P/servers.py:470` |
| A14 | 관리자 | 「사람·설정·가입 요청」(관리 그룹)이 1440×900에서 사이드바 아래로 밀려 보이지 않는다. 스크롤 표시도 없다. | `C/templating.py:34-35`, `static/console.css:79-83`, admin-people.png(강조된 메뉴 없음) |
| A15 | 관리자 | 관리자가 4명인데 시작하기가 「승인자 없음 · 확인 필요」를 필수 항목으로 센다. 관리자도 승인할 수 있으므로 설계 결정 7과 어긋난다(추정: 의도와 다름). | admin-setup.png, `C/setup_state.py:115-136` |
| A16 | 관리자 | 콘솔에 LiteLLM 읽기 키가 없으면 「명령줄에서 하십시오」로 끝난다. | `C/core.py:277-284` |
| A17 | Root | root는 별도 역할이 아니라 이름이 root인 관리자다. Root 전용 통제가 없다. | `types/cli_commands.py:14-17`, admin-admin.png |
| A18 | Root | 운영 모드는 집행·관측 둘뿐이고 관측은 통제를 약하게 하는 쪽이다. 전역 정지가 없다. | `types/settings.py:15-17`, `T/policy.html:35` |
| A19 | Root | 접수·검사 중에는 결정 양식이 없고(통과·판별 불가·실패에서만), 철회는 신청자 본인만 한다. | `T/intake_detail.html:6-7, 100` |
| A20 | Root | 키 차단은 시스템 탐지가 만든 제안에만 걸 수 있다. 수동으로 「이 키 지금 차단」을 시작할 수 없다. | `control/key_block.py:200-236`, `T/_approvals_blocks.html:28-45` |
| A21 | Root | 전파 확인은 단말 중지(4상태)와 승인 7단계에만 있다. 서버 중지·사람 차단·키 폐기에는 없다. | `T/endpoints.html:15-23`, `P/servers.py:690-739` |

### A.2 연결 안 된 버튼·막다른 길 (check.py: 오류 0 · 경고 27)

| 구분 | 대상 | 판정 |
|---|---|---|
| 실제 미연결 | `/intakes/{id}/inspect`, `/intakes/{id}/inspect-revoke` | A9. 양식 없음 |
| 실제 미연결 | `/setup/webhook`, `/setup/webhook-test` | FM-41 양식 유실(`T/setup.html` 전체 17줄에 양식 없음) |
| 실제 미연결 | `/operators/{name}/chat-bind` | 템플릿 전체 검색 0건 |
| 실제 미연결(구 경로) | `/staff/endpoint/kit`, `/staff/login` | 템플릿에 없음. 정리는 CP 대상 |
| 외부 콜백 | `/chat/slack/actions` | 화면 양식 대상 아님(FM-25 BLOCKED) |
| 도구 오탐 | `/approvals/renew`, `/approvals/dormant/keep`, `/org-suggestions/rule`, `/servers/…/terminate`, `/intakes/{id}/evidence`, `/staff/intakes/probe` | 양식이 있다(`T/_approvals_renewals.html:12`, `T/access.html:58`, `T/admin.html:120`, `T/_server_usage.html:7`, `T/staff_intake_new.html:10`). inventory가 `formaction`, 매크로 인자, 변수 action을 읽지 못한다 |
| 도구 누락 | `GET /staff/confirmations` | 상수 경로(`C/staff_pages.py:844`)라 ROUTES.csv에 없다 |
| 도구 누락 | 예외 확인·거절, 키 차단 승인·거절, 호출 승인 거부·연장·취소·일괄 | `formaction` 단추라 SCREEN_INVENTORY에 일부만 잡힌다(`T/_approvals_second.html:11-12`, `T/_approvals_blocks.html:33-35`, `T/_approvals_calls.html:18-19, 67-73`) |
| FM 13건 「화면 동작 없음」 | FM-37·47·54는 동작이 FM-04로만 연결됨. FM-60·63은 미구현. FM-19·26·27·42·49·51·52·53은 화면 동작이 아닌 성질 | SCREEN_ACTION_MATRIX의 `feature_id`를 여러 값으로 보강 |
| 막다른 길 | `/approvals/new` 직접 진입 시 400 「입력 값이 올바르지 않습니다: 입력 항목」 | admin-approvals_new.png |
| 막다른 길 | 선택 값 오류가 「입력 값이 올바르지 않습니다.」 한 줄 | `P/common.py:41-43` |

결론: inventory가 고쳐지기 전에는 check.py로 「모든 버튼이 기능에 연결됨」(REQ-26)을 판정할 수 없습니다.

FM-61 관련 사실: PRODUCT_BRIEF는 `/exceptions/{hold_id}/{decision}`이 「화면에서 닿지 않음」이라 적었지만, 대기 건이 있으면 승인 센터에 「두 번째 승인」 탭이 나타납니다(`P/approvals.py:153-154`). 건이 없으면 탭이 숨겨질 뿐입니다.

### A.3 정보 구조 문제

| # | 문제 | 근거 |
|---|---|---|
| I1 | 같은 대기 1건이 대시보드 「승인 센터 1」「도입 신청 1」「승인 대기 1」과 메뉴 배지 두 곳에 따로 보인다(추정: 같은 건). | admin-dashboard.png |
| I2 | 차단·해제 입구가 5곳(호출 기록 행, 서버 계약 탭, 접근 통제 거부 탭, 사람, 승인 센터 차단 제안)이고 서로 연결이 없다. | `T/ledger.html:36-38`, `T/_tool_controls.html`, `T/access.html:64-89`, `T/people.html:24-29`, `T/_approvals_blocks.html` |
| I3 | 「호출 기록」 첫 쪽이 로그인·내보내기·수용검증 같은 시스템 사건으로 차서 조치 열이 비어 있다. | admin-ledger.png |
| I4 | 직원 메뉴 「MCP 서버 도입 신청」과 「내 MCP 서버 → 내 신청 이력」 탭이 같은 목록이다. | `C/templating.py:39-40`, `T/staff_servers.html:20` |
| I5 | 같은 대상을 단말·엔드포인트·PC 세 가지로 부른다. | 메뉴 「엔드포인트」, 「내 단말」, 카드 「내 PC 연결」, `mint_kit.py:5071` |
| I6 | 출처·공급망 정보가 「검사 결과」 표의 사유 칸과 「실행 묶음」 탭으로 흩어져 있다. | admin-detail-intakes.png, `T/intake_detail.html:62`, `T/_intake_pack.html` |
| I7 | 사람·팀이 UUID로 보인다. | admin-ledger.png(주체), admin-reports_usage.png(팀별), admin-alerts.png |

### A.4 캡처에서 보이는 시각 문제

| # | 문제 | 캡처 |
|---|---|---|
| V1 | 빨간 채움 단추가 행마다 반복된다(하네스 10개, 사람 6개, 운영자 4개). | admin-builtin-tools.png, admin-people.png, admin-admin.png, staff-staff_intakes.png |
| V2 | 역할 선택 기본값이 현재 역할이 아니다(관리자 행에 「승인자」). 한 번 누르면 강등되고 root 행에도 삭제 단추가 있다. | admin-admin.png, `T/admin.html:17-22` |
| V3 | 단추가 카드·표에 붙어 있다. 「모드 변경」 단추는 아래 목록과 겹친다. | admin-intakes.png, staff-staff.png, staff-staff_endpoint.png, admin-policy.png |
| V4 | 차트 축 이름이 잘린다(「ncp_server_fetch」, 「스트 제한 미집행」). | admin-dashboard.png, admin-reports_usage.png, admin-endpoints.png |
| V5 | 경보 심각도 막대가 모두 같은 파란색이다. | admin-dashboard.png |
| V6 | 호출 2건에 280px 차트 4~6개가 놓여 대시보드가 1800px이다. | admin-dashboard.png |
| V7 | 심각도 「높음」과 상태 「열림」이 같은 ▲ 빨강이고, 심각도 「보통」이 대기 아이콘 ◷다. | admin-alerts.png |
| V8 | 번역 안 된 종류 `operational_check`. 서버 이름과 같은 식별자가 다시 표시되고 복사 단추가 붙는다. | admin-alerts.png, admin-intakes.png |
| V9 | 지금 처리할 일 카드가 숫자 「1」만 있고 무엇을 하라는지 없다. | admin-dashboard.png |
| V10 | 모바일에서 표 오른쪽 열이 잘리고 스크롤 표시가 없다. KPI 카드 5장이 세로로 쌓여 본문이 600px 아래로 밀린다. | mobile-intakes.png, mobile-staff.png |
| V11 | 「연결 해제」 빨간 단추가 「앱」 절 바로 아래에 있어 앱 동작으로 읽힌다. | staff-staff_endpoint.png |
| V12 | 오류 화면이 제목과 같은 문장을 반복하고 참조 번호만 준다. | admin-detail-servers.png |

### A.5 보안 정책이 정상 사용을 막는 지점

F.4에 목록(FC-01~12)과 고칠 방향을 함께 두었습니다.

---

## B. 새 정보 구조

원칙은 세 가지입니다. 기존 화면·경로는 유지하고 그룹과 순서만 바꿉니다. 새 화면은 3개(긴급 통제, 강제 조치 기록, 거부 화면 틀)입니다. 화면 합치기는 I절의 CP로만 제안합니다.

### B.1 용어 통일

| 대상 | 직원 화면·CLI | 관리자 화면 |
|---|---|---|
| 직원 PC | 내 PC | 단말(메뉴 이름 「단말」, 「엔드포인트」는 부제) |
| 서버 도입 요청 | 서버 신청 | 도입 신청 |
| 막힌 것을 풀어 달라는 요청 | 권한 요청 | 권한 요청 |
| 관리자가 건 사후 막기 | 차단 / 해제 | 차단 / 해제(내부 이름 denial은 화면에 쓰지 않음) |
| 서버 전체 멈춤 | 중지됨 | 중지 / 재개 |

### B.2 메뉴와 페이지

관리 콘솔(역할별로 보이는 항목만 그린다):

| 그룹 | 메뉴(경로) | 목적 한 줄 | 보이는 역할 |
|---|---|---|---|
| — | 대시보드 `/` | 지금 처리할 일과 오늘 막은 것 | 전체 |
| — | 시작하기 `/setup` (필수 항목이 남았을 때만 여기, 끝나면 설정 그룹) | 설치 직후 할 일 | 관리자·Root |
| 처리할 일 | 승인 센터 `/approvals` — 탭: 신청 심사 · 호출 승인 · 권한 요청(신규) · 예외·2인 확인 · 갱신 · 규칙 · 차단 제안 | 내 결정을 기다리는 모든 것 | 승인자 이상 |
| 처리할 일 | 경보 `/alerts` | 위반·장애 대응 | 전체 |
| MCP 서버 | MCP 서버 `/servers` | 서버 상태·통제 | 전체 |
| MCP 서버 | 도입 신청 `/intakes` | 신청과 검사 진행 | 전체 |
| MCP 서버 | 접근 통제 `/access` — 승인 · 미사용 · 차단 · 허용 목록 | 누구에게 무엇이 열려 있나 | 전체(조작은 승인자 이상) |
| MCP 서버 | 하네스 기본 기능 `/builtin-tools` | 내장 도구 차단 | 관리자 이상 |
| 사람·단말 | 사람 `/people` | 사람별 권한·PC·차단 | 관리자 이상 |
| 사람·단말 | 단말 `/endpoints` | PC 설치·격리·AI 도구 | 전체 |
| 사람·단말 | 가입 요청 `/signup-requests` | 가입 승인 | 관리자 이상 |
| 감사 | 호출 기록 `/ledger` · 감사 보고서 `/reports/audit` · 사용량 `/reports/usage` | 기록과 보고 | 전체 |
| 설정 | 정책 `/policy` · 설정·운영자 `/admin` | 모드, 운영자, 백업, SIEM | 관리자 이상 |
| Root | 긴급 통제 `/root`(신규) · 강제 조치 기록 `/root/actions`(신규) | 전역 정지, 강제 조치, 전파 확인 | Root(기록 열람은 관리자) |

직원 화면:

| 메뉴(경로) | 목적 |
|---|---|
| 내 MCP 서버 `/staff` | 쓸 수 있는 서버·도구, 막힌 도구, 권한 요청 |
| 서버 신청 `/staff/intakes` | 신청과 진행 |
| 내 요청 `/staff/confirmations` — 본인 확인 · 승인 대기 · 권한 요청(신규) | 내가 기다리는 것 |
| 내 사용량 `/staff/usage` | 내 호출·차단 |
| 내 PC `/staff/endpoint` | 설치 명령, 연결 상태, 앱 |

사이드바 규칙: 항목 높이 36px, 그룹 제목 24px로 1440×900에서 스크롤 없이 전 항목이 보여야 합니다(시작하기 완료 뒤 16항목 기준). 넘치면 아래쪽에 스크롤 그림자를 둡니다(QA-NAV-001).

### B.3 옛 화면 → 새 화면

| 옛 화면 | 새 위치 | 바뀌는 것 |
|---|---|---|
| 대시보드 | 대시보드 | 「지금 처리할 일」을 동사 문장 카드로(「신청 1건 심사하기」). 같은 건은 한 번만 센다 |
| 승인 센터(호출·서버 도입·갱신·규칙·차단 제안, 두 번째 승인은 조건부) | 승인 센터 | 기본 탭은 대기가 있는 첫 탭. 「권한 요청」 추가. 「예외·2인 확인」 항상 표시 |
| 도입 신청 목록·상세 | 같은 경로 | 상세 탭을 「심사 요약 · 출처·공급망 · 실행 묶음 · 신청 내용 · 증빙」으로. 단말 검사·예외 승인 단추 연결 |
| MCP 서버 목록·상세 | 같은 경로 | 상세 오른쪽에 「통제」 패널(중지·재개·도구 차단·이용 종료·폐기), 「전파 상태」 줄 |
| 접근 통제 | 같은 경로 | 탭 이름 「거부」→「차단」. 행에 출처(호출 기록, 사람, 서버) 표시 |
| 사람 | 같은 경로 | 행을 누르면 서랍(권한, PC, 앱, 키, 세션). 「전체 차단」 |
| 엔드포인트 | 단말(같은 경로) | 이름만 변경 |
| 호출 기록 | 같은 경로 | 기본 보기 「도구 호출」(판정·응답만), 「관리 기록」은 탭으로. 차단 단추는 테두리형 |
| 정책 | 같은 경로 | 모드 확인 창에 영향 수치. 전역 정지는 여기가 아니라 `/root` |
| 설정·운영자 | 같은 경로 | 역할 선택 기본값을 현재 역할로. Root 지정 추가 |
| 시작하기 | 같은 경로 | 알림 주소 양식 복구(FM-41). 승인자 항목은 「관리자도 승인 가능」이면 선택으로 |
| 직원 내 MCP 서버 | 같은 경로 | 「조직에서 쓰는 서버」 구역과 도구 표, 「권한 요청」 |
| 직원 내 요청 | 같은 경로 | 「권한 요청」 탭과 양식 |
| 직원 내 단말 | 내 PC(같은 경로) | PC별 연결 해제 |
| 403·400·404·409·500 오류 화면 | 거부 화면 / 오류 화면 두 틀 | F절 |

---

## C. 화면별 설계

모든 양식에 공통으로 적용합니다. 제출 단추는 누르면 잠기고 라벨이 「처리 중…」으로 바뀝니다(현재는 표시 없음). 성공은 화면 위 초록 띠, 실패는 같은 화면 빨간 띠에 사유와 해결 단추를 둡니다. 감사 사건 이름 뒤 「(신규)」는 새로 만들 사건입니다.

### C.1 공통 셸 (S00)

- 상단 바: 왼쪽에 제품명과 화면 구분. 오른쪽에 시간대, 「이름 · 역할」(Root는 「root · Root」), 직원 화면, LiteLLM 콘솔, 계정 메뉴(비밀번호·로그아웃). Root에게만 「긴급 통제」 테두리 단추를 둡니다.
- 전역 정지 중에는 모든 화면 위에 빨간 띠를 고정합니다: 「전역 정지 중 · 범위 · 시작 시각 · 실행자 · [전파 상태 보기]」. 직원 화면에도 「관리자가 MCP 사용을 일시 정지했습니다」를 띄웁니다.
- 좁은 화면(600px 이하): 계정 메뉴와 LiteLLM 콘솔은 사이드바 맨 아래에 둡니다(현재 방식 유지).

### C.2 직원 · 내 MCP 서버 (S-staff_servers)

배치는 위에서 아래로 다음과 같습니다.
1. 요약 띠 한 줄(카드 5장 대신): PC 연결, 사용 가능, 준비 중, 막힌 도구, 만료 임박.
2. 「사용 가능」 카드 격자(현재 유지).
3. 「조직에서 쓰는 서버」 구역: 조직에 승인돼 있지만 내 권한이 없는 서버의 이름과 목적만 보이고(도구 목록은 비노출, POL-O-02) 「사용 요청」을 둡니다.
4. 탭: 내 호출 · 내 기록(「내 신청 이력」 탭 제거는 CP-004).

서랍(서버 하나): 상태, 도구 표(도구 · 상태[사용 가능 / 관리자 차단 / 호출마다 승인] · 마지막 호출 · 「권한 요청」), 이용 방법, 동의.

- 빈 상태: PC 미연결이면 「먼저 PC를 연결하십시오 [설치 명령 만들기]」, 연결됐으면 「쓸 수 있는 서버가 없습니다 [서버 신청] [조직에서 쓰는 서버 보기]」.
- 오류 상태: 서버 목록을 읽지 못하면 오류 화면 틀(F.2)과 「다시 시도」.

### C.3 직원 · 서버 신청 (S-staff_intake_new)

3단계를 화면 위에 표시합니다: ① 주소·목적 → ② 확인(고정된 커밋·판본, 실행 명령, 출처) → ③ 접수.
- 1단계의 주 단추는 「다음: 주소 확인」입니다. 2단계에서만 「신청 제출」이 나옵니다(현재는 1단계 주 단추가 「신청 제출」).
- 저장소 주소면 2단계에 「소유자/저장소 · 고정 커밋(40자, 태그·브랜치에서 해석했으면 원래 이름 병기) · 실행 명령 · 직원 PC에서 격리 실행」을 읽기 전용으로 보입니다.
- 오류: 주소 해석 실패는 입력 칸 아래에 「무엇이 틀렸는지 + 맞는 예」를 둡니다. 중복 신청은 기존 신청으로 이동합니다(유지).

### C.4 직원 · 내 요청 (S-staff_requests)

탭: 본인 확인 대기 · 승인 대기(호출) · 권한 요청(신규).
- 권한 요청 탭의 열은 서버, 도구, 막힌 사유, 요청 시각, 상태[대기·허용됨·거절됨·취소], 처리자·사유입니다. 대기 행에는 「요청 취소」를 둡니다.
- 양식(서랍): 서버(선택), 도구(선택, 비우면 서버 전체), 사유(필수 한 줄), 기간 희망[이번만 / 계속].
- 빈 상태: 「막힌 도구가 없습니다」. 최근 7일 차단 호출이 있으면 그 목록을 「권한 요청」 단추와 함께 보입니다.
- 본인 확인: 같은 키 로그인으로 확인할 수 없으면 행에 「다른 로그인으로 확인해야 합니다 [방법 보기]」 한 줄을 보입니다(비활성 단추와 툴팁 대신).

### C.5 관리자 · 승인 센터 (S-approvals)

- 화면 순서: 탭 → 요약 띠 → 목록. 기본 탭은 대기 건이 있는 첫 탭입니다.
- 권한 요청 탭의 열: 요청자, 서버 · 도구, 막힌 사유(사유 코드의 한국어 이름), 요청 사유, 경과, 「제안 조치」.
- 서랍: 막힌 원인(어느 차단·어느 승인·어느 정책), 영향 범위(해제하면 누구에게 열리는가), 최근 같은 요청 횟수, 결정 단추.
- 결정 단추는 원인에 따라 하나만 주 단추로 제시합니다. 관리자 차단이면 「차단 해제」, 승인 없음·범위 밖이면 「이 사람에게 허용(30일·90일·기한 없음)」, 호출별 승인이면 「30분만 허용 / 규칙 만들기」, 만료면 「갱신」, 재확인이면 「재확인」입니다. 옆에 「거절」(사유)을 둡니다.
- 같은 사람·서버·도구가 7일 안에 2번 이상 허용되면 「계속 허용으로 바꾸기」를 제안합니다(반복 승인 금지, REQ-25).
- 자기 요청은 「본인 요청은 본인이 처리할 수 없습니다」 한 줄을 보입니다(W-04). 직무 분리가 꺼져 있고 Root면 처리할 수 있습니다(결정 7).

### C.6 관리자 · 신청 상세 (S-intake_detail)

- 머리: 서버 이름, 상태 배지, 진행 4단계와 적용 7단계(유지). 멈춘 단계에는 「원인 + 해결 단추」를 같은 줄에 둡니다(예: 키 반영 대기 · 승인 대상 팀이 삭제됨 [대상 바꾸기]).
- 본문 탭: 심사 요약 · 출처·공급망 · 실행 묶음 · 신청 내용 · 증빙.
- 오른쪽 결정 패널: 「승인하면: 대상 · 기간」 한 줄, 승인·거부(같은 무게), 「예외 승인」(판별 불가에서만, 사유 필수), 「PC에서 도구 목록 확인 요청」(로컬 판별 불가에서만).
- Root에게만 결정 패널 아래 「강제 조치」 접힘 구역: 접수·검사 중 「강제 반려」, 「검사 생략 승인」(실행 묶음이 없으면 비활성 + 사유).

「출처·공급망」 탭은 6줄 점검표입니다. 각 줄은 판정 배지 + 핵심 값 + 펼침이고, 표 아래에 원본 검사 표를 둡니다. 값은 지금 수집되는 것만 씁니다.

| 줄 | 보이는 값(출처) | 판정 |
|---|---|---|
| 출처·소유자 | 저장소 주소에서 뗀 소유자/저장소, 제공자 허용 여부(`c.inputs.source.repo`, `provider_blocked`) | 허용 / 허용 목록 밖 |
| 고정 | 커밋 12자·판본·npm 무결성, 소스 지문(`src.commit`, `src.tree_sha256`, `pack.sha`) | 고정됨 / 미고정 |
| 의존성 | 구성요소 n개, 묶음 파일 해시, SBOM 내려받기(`sbom` 검사, `pack.files`) | 통과 / 판별 불가 |
| 라이선스 | 라이선스 이름, 주의 건수(`src.license`, `license_findings`) | 통과 / 검토 필요 |
| 취약점·코드 | 심각·높음·보통·낮음 건수, 코드·비밀·설정 발견 건수(`dependency_vulns`, `code_scan`) | 통과 / 검토 필요 / 실패 |
| 권한·네트워크·격리 | 네트워크[차단·허용 호스트만·제한 없음], 파일 경로와 읽기·쓰기, 환경 변수 이름, 격리 방식(`pack.network`, `pack.access`, `pack.env`) + 「승인 때 좁히기」 링크 | 최소 / 넓음(제한 없음이면 주의) |

저장소 소유자의 평판(별, 최근 활동)은 지금 수집하지 않으므로 넣지 않습니다(추정: GitHub API 호출이 필요, 보류).

- 빈 상태: 검사 전이면 「검사 중입니다 · 보통 n분」과 자동 재시도 줄.
- 오류 상태: 검사 작업 실패는 빨간 띠 「무엇이 · 왜 · n/12회 · 다음 시도 · [지금 재검사]」.

### C.7 관리자 · 서버 상세 (S-server_detail)

- 머리: 이름, 상태 배지, (있으면) 중지 사유·실행자·시각.
- 오른쪽 「통제」 패널(위에서 아래로 약한 순): 도구 차단(계약 탭으로 이동) → 중지/재개 → 이용 종료(이용 탭) → 서버 폐기(이름 입력). Root에게는 「진행 중 실행 취소 요청」을 더합니다.
- 통제 직후에는 머리 아래 「전파 상태」 줄을 둡니다: MINT 판정 ✓ 즉시 · LiteLLM 키 권한 ◷ 최대 60초 · PC n/m대 수신 · 실행기 정지 n/m · [자세히].
- 승인 대기·거절 상태의 서버도 열려야 합니다(A12). 열지 못하면 오류 화면 틀에 「신청 상세로 가기」를 둡니다.

### C.8 관리자 · 사람 (S-people)

- 표: 사람(이름, UUID는 툴팁), LiteLLM 역할, 팀 이름, 최근 로그인, MINT 권한, 상태[정상·일부 차단·전체 차단], PC 수. 행을 누르면 서랍이 열립니다.
- 서랍: ① 권한(승인 목록, 차단 목록) ② PC·앱(대수, 마지막 보고) ③ 키·세션(LiteLLM 키 상태, 콘솔·직원 세션 수) ④ 조치.
- 조치는 테두리 단추 「MCP 차단」(기존)과 Root·관리자의 「전체 차단…」입니다. 전체 차단 확인 창은 E.3과 같습니다.

### C.9 Root · 긴급 통제 (S-root)와 강제 조치 기록 (S-root_actions)

S-root는 세 구역입니다.
1. 전역 상태: 「정상 운영」 또는 「정지 중」 큰 배지와 시작 시각·실행자·사유.
2. 전역 정지 양식: 범위 선택[모든 MCP 호출 / 로컬 실행만 / 새 승인·배포만 동결], 사유(필수), 예상 영향(활성 서버 n, 연결 PC n, 최근 1시간 호출 n).
3. 최근 강제 조치 5건과 「전체 보기」.

S-root_actions의 표: 시각, 조치, 대상, 실행자, 사유, 전파(지점별 ✓·◷·▲), 되돌리기. 행을 누르면 서랍에 지점별 시각표가 나옵니다(E.4).

- 빈 상태: 「강제 조치 기록이 없습니다」.
- 오류 상태: 전파 확인을 못 읽으면 지점별 「확인 못 함 · [다시 확인]」.

### C.10 새로 생기거나 바뀌는 동작

```csv
screen_id,screen,component_id,action_id,label,roles,feature_id,preconditions,action,api,policy_id,loading_state,success_state,failure_state,audit_event,test_id,status
S00,공통 상단 바,긴급 통제 단추,S00.root_open,긴급 통제,root,FM-55,Root 로그인,클릭,GET /root(신규),,화면 이동,긴급 통제 화면,Root가 아니면 거부 화면,,QA-S00-001,SPECIFIED
S00,거부 화면,요청 문구 복사,S00.denied_copy,요청 문구 복사,viewer approver admin,FM-62,콘솔 역할 부족으로 거부됨,클릭,(화면 내 복사),,즉시,필요 역할·권한을 줄 수 있는 사람·참조 번호가 복사됨,해당 없음,,QA-S00-002,SPECIFIED
S-staff_servers,직원 내 MCP 서버,서랍 도구 표,S-staff_servers.tools,도구 상태 보기,staff,FM-60,서버 서랍 열림,보기,GET /staff?open={ref},POL-O-02,화면 이동,도구별 사용 가능·관리자 차단·호출마다 승인 표시,읽지 못하면 오류 화면,,QA-E2E-08-001,SPECIFIED
S-staff_servers,직원 내 MCP 서버,도구 행 단추,S-staff_servers.request_access,권한 요청,staff,FM-60,도구가 차단·범위 밖·만료,사유 한 줄 입력 후 제출,POST /staff/access-requests(신규),REASON-DENIED REASON-TOOL_NOT_IN_APPROVAL REASON-APPROVAL_EXPIRED,버튼 잠금,「요청했습니다. 내 요청에서 진행을 봅니다」,같은 대기 요청이 있으면 그 요청으로 이동,ACCESS_REQUEST_OPENED(신규),QA-E2E-09-001,SPECIFIED
S-staff_servers,직원 내 MCP 서버,내 호출 탭 차단 행,S-staff_servers.request_from_call,권한 요청,staff,FM-60,차단된 호출 기록이 있음,클릭(서버·도구·사유 코드 자동 채움),POST /staff/access-requests(신규),REASON-DENIED,버튼 잠금,요청 접수·행에 「요청함」 표시,요청할 수 없는 사유면 안내만,ACCESS_REQUEST_OPENED(신규),QA-E2E-09-002,SPECIFIED
S-staff_servers,직원 내 MCP 서버,조직에서 쓰는 서버 카드,S-staff_servers.request_server,사용 요청,staff,FM-60,조직에 승인된 서버·내 승인 없음,사유 입력 후 제출,POST /staff/access-requests(신규),REASON-APPROVAL_ABSENT,버튼 잠금,요청 접수,오류 띠(사유·해결),ACCESS_REQUEST_OPENED(신규),QA-E2E-09-003,SPECIFIED
S-staff_requests,직원 내 요청,권한 요청 탭,S-staff_requests.tab_access,권한 요청,staff,FM-60,직원 로그인,탭 클릭,GET /staff/confirmations?tab=access(신규),,화면 이동,내 권한 요청 목록·상태,빈 상태 안내,,QA-E2E-09-004,SPECIFIED
S-staff_requests,직원 내 요청,대기 행 단추,S-staff_requests.cancel_access,요청 취소,staff,FM-60,내 대기 요청,확인 창 후 제출,POST /staff/access-requests/{request_id}/cancel(신규),,버튼 잠금,「요청을 취소했습니다」,이미 처리됐으면 최신 상태 표시,ACCESS_REQUEST_CANCELLED(신규),QA-S-staff_requests-001,SPECIFIED
S-staff_intake_new,직원 서버 신청,1단계 주 단추,S-staff_intake_new.probe,다음: 주소 확인,staff,FM-37 FM-47 FM-04,주소·목적 입력,제출,POST /staff/intakes/probe,POL-R-16 POL-I-01,버튼 잠금,2단계 미리보기(고정 커밋·실행 명령),입력 칸 아래 사유와 맞는 예,,QA-E2E-01-001,SPECIFIED
S-staff_intake_new,직원 서버 신청,2단계 주 단추,S-staff_intake_new.intake_submit,신청 제출,staff,FM-04 FM-37,미리보기 확인,제출,POST /staff/intakes,POL-I-11,버튼 잠금,신청 상세로 이동·「신청을 등록했습니다」,중복이면 기존 신청으로 이동,INTAKE_RECEIVED,QA-E2E-01-002,SPECIFIED
S-staff_endpoint,직원 내 PC,PC 행 단추,S-staff_endpoint.revoke_one,이 PC 연결 해제,staff,FM-50,연결된 PC가 있음,확인 창(남는 것 표시) 후 제출,POST /staff/endpoint/revoke(변경: key_alias),,버튼 잠금,「이 PC 연결을 해제했습니다」·다른 PC 유지,오류 띠(사유·해결),ENDPOINT_REVOKED,QA-S-staff_endpoint-001,SPECIFIED
S-staff_endpoint,직원 내 PC,화면 아래 단추,S-staff_endpoint.endpoint_revoke,내 PC 모두 해제,staff,FM-50,PC 2대 이상,확인 창(대수 표시) 후 제출,POST /staff/endpoint/revoke,,버튼 잠금,「PC n대 연결을 해제했습니다」,오류 띠(사유·해결),ENDPOINT_REVOKED,QA-S-staff_endpoint-002,SPECIFIED
S-approvals,승인 센터,탭,S-approvals.default_tab,기본 탭,approver admin root,FM-64,승인 센터 열기,보기,GET /approvals,,화면 이동,대기 건이 있는 첫 탭이 열림,해당 없음,,QA-S-approvals-001,SPECIFIED
S-approvals_access,승인 센터 권한 요청 탭,탭,S-approvals_access.open,권한 요청,approver admin root,FM-60,로그인,탭 클릭,GET /approvals?tab=access(신규),,화면 이동,대기 요청 목록(경과 시간순),빈 상태 안내,,QA-E2E-09-005,SPECIFIED
S-approvals_access,승인 센터 권한 요청 탭,서랍 주 단추,S-approvals_access.resolve_lift,차단 해제,admin root,FM-60 FM-13,원인이 관리자 차단,클릭 1회,POST /access-requests/{request_id}/resolve(신규),REASON-DENIED,버튼 잠금,「해제했습니다. 요청자는 바로 다시 호출할 수 있습니다」,상태가 바뀌었으면 최신 내용 다시 표시,DENIAL_LIFTED + ACCESS_REQUEST_RESOLVED(신규),QA-E2E-09-006,SPECIFIED
S-approvals_access,승인 센터 권한 요청 탭,서랍 주 단추,S-approvals_access.resolve_grant,이 사람에게 허용,approver admin root,FM-60,원인이 승인 없음·범위 밖·만료,기간 선택 후 클릭,POST /access-requests/{request_id}/resolve(신규),REASON-APPROVAL_ABSENT REASON-TOOL_NOT_IN_APPROVAL REASON-APPROVAL_EXPIRED,버튼 잠금,「허용했습니다」·전파 상태 줄,LiteLLM 대상 없음이면 「대상 바꾸기」 안내,APPROVAL_GRANTED + ACCESS_REQUEST_RESOLVED(신규),QA-E2E-09-007,SPECIFIED
S-approvals_access,승인 센터 권한 요청 탭,서랍 보조 단추,S-approvals_access.resolve_temp,30분만 허용,approver admin root,FM-60 FM-64,원인이 호출별 승인,클릭 1회,POST /access-requests/{request_id}/resolve(신규),REASON-CALL_APPROVAL_REQUIRED,버튼 잠금,「30분 동안 허용했습니다」,오류 띠(사유·해결),CALL_APPROVAL_APPROVED + ACCESS_REQUEST_RESOLVED(신규),QA-E2E-09-008,SPECIFIED
S-approvals_access,승인 센터 권한 요청 탭,서랍 단추,S-approvals_access.reject,거절,approver admin root,FM-60,대기 요청,사유 입력 후 제출,POST /access-requests/{request_id}/reject(신규),,버튼 잠금,「거절했습니다」·요청자 화면에 사유 표시,사유가 비면 입력 칸 강조,ACCESS_REQUEST_REJECTED(신규),QA-S-approvals_access-001,SPECIFIED
S-approvals_second,승인 센터 예외·2인 확인 탭,탭,S-approvals_second.open,예외·2인 확인,approver admin root,FM-61,로그인,탭 클릭,GET /approvals?tab=second,,화면 이동,대기 0건이어도 탭이 보임,빈 상태 안내,,QA-S-approvals_second-001,SPECIFIED
S-intake_detail,신청 상세,탭,S-intake_detail.source_tab,출처·공급망,viewer approver admin root,FM-43 FM-37,신청 상세 열림,탭 클릭,GET /intakes/{intake_id}?tab=source(신규 탭),POL-O-06 POL-O-07 POL-I-08,화면 이동,6줄 점검표와 원본 검사 표,검사 전이면 「검사 중」 안내,,QA-E2E-03-001,SPECIFIED
S-intake_detail,신청 상세,결정 패널 단추,S-intake_detail.inspect,PC에서 도구 목록 확인 요청,approver admin root,FM-43,로컬 신청·판별 불가·실행 묶음 준비됨,클릭 1회,POST /intakes/{intake_id}/inspect,POL-I-06,버튼 잠금,「요청했습니다. 신청자 PC가 다음 보고 때 실행합니다」·남은 시간 표시,조건이 안 맞으면 비활성과 사유 한 줄,확인 필요,QA-S-intake_detail-001,SPECIFIED
S-intake_detail,신청 상세,결정 패널 단추,S-intake_detail.inspect_revoke,확인 요청 취소,approver admin root,FM-43,검사 권한이 열려 있음,클릭 1회,POST /intakes/{intake_id}/inspect-revoke,,버튼 잠금,「취소했습니다」,오류 띠(사유·해결),확인 필요,QA-S-intake_detail-002,SPECIFIED
S-intake_detail,신청 상세,결정 패널 단추,S-intake_detail.except,예외 승인,approver admin root,FM-61 FM-06,판별 불가 신청,사유 필수 입력 후 제출,POST /intakes/{intake_id}/decision,POL-R-02,버튼 잠금,직무 분리 꺼짐: 「예외 승인했습니다」 / 켜짐: 「두 번째 승인자의 확인을 요청했습니다」,사유 누락이면 입력 칸 강조,INTAKE_DECIDED,QA-S-intake_detail-003,SPECIFIED
S-intake_detail,신청 상세,멈춘 단계 줄,S-intake_detail.fix_target,대상 바꾸기,admin root,FM-08 FM-06,승인 대상(키·팀)이 LiteLLM에 없음,클릭,GET /approvals/review/{relation_id},,화면 이동,승인 범위 지정 화면(대상 다시 선택),이용 관계가 없으면 404 안내,,QA-S-intake_detail-004,SPECIFIED
S-intake_detail,신청 상세,강제 조치 구역,S-intake_detail.force_reject,강제 반려,root,FM-56,접수·검사 중 신청,사유 필수·확인 창 후 제출,POST /root/actions(신규),,버튼 잠금,「반려했습니다. 남은 검사를 멈췄습니다」·전파 상태 줄,오류 띠(사유·해결),INTAKE_DECIDED + FORCED_ACTION_RECORDED(신규),QA-E2E-11-003,SPECIFIED
S-intake_detail,신청 상세,강제 조치 구역,S-intake_detail.force_approve,검사 생략 승인,root,FM-56,접수·검사 중·실행 묶음 또는 원격 주소 있음,사유 필수·대상 선택·확인 창 후 제출,POST /root/actions(신규),POL-R-02,버튼 잠금,「예외 승인했습니다(30일)」·건너뛴 검사 목록 표시,묶음이 없으면 비활성과 사유,INTAKE_DECIDED + FORCED_ACTION_RECORDED(신규),QA-E2E-11-004,SPECIFIED
S-server_detail,서버 상세,통제 패널,S-server_detail.suspend,중지,admin root,FM-14,서버 승인됨,확인 창(영향·즉시·되돌리기·남는 것)과 사유 입력 후 제출,POST /servers/{server_id}/suspend(변경: reason),POL-O-19,버튼 잠금,「서버를 중지했습니다」·전파 상태 줄,오류 띠(사유·해결),SERVER_SUSPENDED,QA-E2E-11-001,SPECIFIED
S-server_detail,서버 상세,통제 패널,S-server_detail.terminate,서버 폐기,admin root,FM-45 FM-53,서버 승인·중지 상태,이름 입력 확인 후 제출,POST /servers/{server_id}/terminate(신규),POL-D-01 POL-D-03,버튼 잠금,「폐기를 시작했습니다」·폐기 중 배지·남은 증빙 안내,오류 띠(사유·해결),SERVER_TERMINATING,QA-S-server_detail-001,SPECIFIED
S-server_detail,서버 상세,통제 패널,S-server_detail.cancel_runs,진행 중 실행 취소 요청,root,FM-58,응답 대기 호출 또는 대기 작업이 있음,확인 창(취소 가능 n건·취소 불가 n건) 후 제출,POST /root/actions(신규),,버튼 잠금,「n건 취소 요청·m건은 취소할 수 없습니다」,오류 띠(사유·해결),RUN_CANCEL_REQUESTED(신규),QA-S-server_detail-002,SPECIFIED
S-server_detail,서버 상세,전파 상태 줄,S-server_detail.propagation,전파 상태 자세히,admin root,FM-59,최근 통제 조치가 있음,클릭,GET /root/actions/{action_id}(신규),,화면 이동,지점별 반영 시각표,확인 못 한 지점은 「확인 못 함」,,QA-E2E-12-002,SPECIFIED
S05,호출 기록,행 단추,S05.block,이 도구 차단 / 이 사용자 차단,approver admin root,FM-12,도구 호출 행,클릭 1회(확인 없음·테두리 단추),POST /ledger/{event_id}/block,REASON-DENIED,버튼 잠금,초록 띠 「차단했습니다 [되돌리기]」·목록 유지,오류 띠(사유·해결),DENIAL_CREATED,QA-E2E-08-002,SPECIFIED
S05,호출 기록,성공 띠,S05.undo_block,되돌리기,approver admin root,FM-13,방금 차단함,클릭 1회,POST /denials/{denial_id}/lift,,버튼 잠금,「해제했습니다」,이미 해제됐으면 안내,DENIAL_LIFTED,QA-S05-001,SPECIFIED
S-people,사람,행,S-people.open,사람 상세,admin root,FM-44,사람 목록,행 클릭,GET /people?open={user_id}(변경),,화면 이동,서랍(권한·PC·앱·키·세션),없는 사람은 404 안내,,QA-S-people-001,SPECIFIED
S-people,사람,서랍 조치,S-people.lockout,전체 차단,admin root,FM-57,대상이 본인이 아님,확인 창(항목별 체크·즉시/지연/되돌릴 수 없음) 후 제출,POST /people/{user_id}/lockout(신규),REASON-DENIED,버튼 잠금,「차단했습니다」·항목별 결과와 전파 상태,일부 실패면 항목별 실패 사유와 「다시 시도」,PERSON_LOCKOUT(신규) + DENIAL_CREATED + ENDPOINT_REVOKED + ENDPOINT_APP_REVOKED + KEY_BLOCK_APPROVED + CONSOLE_SESSION_ENDED,QA-E2E-12-001,SPECIFIED
S-people,사람,서랍 조치,S-people.unlock,차단 해제,admin root,FM-57 FM-13,전체 차단 상태,확인 창(되돌아오는 것·안 돌아오는 것) 후 제출,POST /people/{user_id}/unlock(신규),,버튼 잠금,「해제했습니다. PC는 다시 설치해야 합니다」,오류 띠(사유·해결),DENIAL_LIFTED + KEY_BLOCK_UNBLOCK_REQUESTED,QA-S-people-002,SPECIFIED
S-people,사람,서랍 조치,S-people.end_sessions,세션 종료,root,FM-57,활성 세션이 있음,클릭 1회,POST /people/{user_id}/sessions/end(신규),,버튼 잠금,「세션 n개를 끝냈습니다」,오류 띠(사유·해결),CONSOLE_SESSION_ENDED,QA-S-people-003,SPECIFIED
S-admin,설정·운영자,역할 선택,S-admin.set_operator_role,역할 변경,admin root,FM-38 FM-62,운영자 목록,선택 값이 현재와 다를 때만 단추 활성,POST /operators/{name}/role,,버튼 잠금,「역할을 변경했습니다. 그 사람의 세션이 끝납니다」,마지막 관리자·본인·Root 행은 비활성과 사유 한 줄,OPERATOR_ROLE_CHANGED,QA-S-admin-001,SPECIFIED
S-admin,설정·운영자,운영자 행,S-admin.set_root,Root 지정 / 해제,root,FM-62,대상이 관리자,확인 창 후 제출,POST /operators/{name}/root(신규),,버튼 잠금,「Root로 지정했습니다」,마지막 Root는 해제 불가 안내,OPERATOR_ROLE_CHANGED,QA-S-admin-002,SPECIFIED
S-setup,시작하기,알림 줄,S-setup.webhook_save,저장,admin root,FM-41,관리자 로그인,주소 입력 후 제출,POST /setup/webhook,,버튼 잠금,「저장했습니다」,주소 형식 오류는 입력 칸 아래 안내,확인 필요,QA-S-setup-001,SPECIFIED
S-setup,시작하기,알림 줄,S-setup.webhook_test,시험 전송,admin root,FM-41,주소 저장됨,클릭 1회,POST /setup/webhook-test,,버튼 잠금,「시험 전송을 요청했습니다」·결과 시각 표시,전송 실패 사유 표시,확인 필요,QA-S-setup-002,SPECIFIED
S-policy,정책,모드 확인 창,S-policy.set_mode,모드 변경,admin root,FM-70,모드 선택,확인 창(관측이면 최근 24시간 차단 n건이 통과로 바뀜) 후 제출,POST /policy/mode,,버튼 잠금,「모드를 변경했습니다」,환경 상한이 집행이면 관측 비활성과 사유,SETTINGS_CHANGED,QA-S-policy-001,SPECIFIED
S-root,긴급 통제,전역 정지 양식,S-root.halt,전역 정지,root,FM-55,정상 운영 중,범위 선택·사유 입력·「정지」 입력 확인 후 제출,POST /root/halt(신규),REASON-GLOBAL_HALT(신규),버튼 잠금,빨간 띠 「전역 정지 중」·전파 상태 줄,오류 띠(사유·해결),GLOBAL_HALT_SET(신규) + FORCED_ACTION_RECORDED(신규),QA-E2E-11-002,SPECIFIED
S-root,긴급 통제,정지 상태 구역,S-root.halt_lift,정지 해제,root,FM-55,전역 정지 중,확인 창 후 제출,POST /root/halt/lift(신규),,버튼 잠금,「정지를 해제했습니다」·지점별 복귀 시각,오류 띠(사유·해결),GLOBAL_HALT_LIFTED(신규),QA-S-root-001,SPECIFIED
S-root_actions,강제 조치 기록,목록,S-root_actions.list,강제 조치 기록,admin root,FM-59,로그인,보기,GET /root/actions(신규),,화면 이동,조치별 전파 상태 목록,빈 상태 안내,,QA-E2E-12-003,SPECIFIED
S-root_actions,강제 조치 기록,서랍 단추,S-root_actions.verify,전파 다시 확인,admin root,FM-59,미확인·지연 지점이 있음,클릭 1회,POST /root/actions/{action_id}/verify(신규),,버튼 잠금,지점별 최신 시각,확인 못 하면 「확인 못 함」과 사유,확인 필요,QA-E2E-13-001,SPECIFIED
S-root_actions,강제 조치 기록,서랍 단추,S-root_actions.undo,되돌리기,root,FM-56,되돌릴 수 있는 조치,확인 창(되돌아오는 것·안 돌아오는 것) 후 제출,POST /root/actions/{action_id}/undo(신규),,버튼 잠금,「되돌렸습니다」,되돌릴 수 없는 조치는 단추 없음과 사유,FORCED_ACTION_RECORDED(신규),QA-S-root_actions-001,SPECIFIED
```

---

## D. 사용자 여정 (필수 E2E-01~13)

GitHub 저장소로 등록한 서버 하나를 끝까지 씁니다. 시작 상태는 직원 PC에 `mint`가 설치돼 있고 관리자가 Root로 로그인한 상태입니다.

| E2E | 단계(화면 · 동작 ID) | 통과 기준 | 감사 기록 |
|---|---|---|---|
| 01 저장소 등록 | 직원: 서버 신청 → 주소·목적 입력 → `S-staff_intake_new.probe` → 2단계에서 소유자/저장소·고정 커밋·실행 명령 확인 → `S-staff_intake_new.intake_submit`. 터미널은 `mint server add <저장소 주소>`(별칭 `mint add`) | 입력 2칸, 커밋 40자 고정, 신청 상세로 이동 | INTAKE_RECEIVED |
| 02 관리자 확인 | 대시보드 「신청 1건 심사하기」 카드 또는 승인 센터(`S-approvals.default_tab`으로 신청 심사 탭) → 행 클릭(`S02.open`) | 대기 건이 한 번만 세어짐, 출처 배지, 신청자 이름 | — |
| 03 검수·승인 | `S-intake_detail.source_tab`에서 6줄 확인. 판별 불가면 `S-intake_detail.inspect` 또는 `.except` → 결정 패널 `S03.approve` 1회. 네트워크·파일은 「추가 설정」에서 좁힘 | 승인 1클릭, 6줄에 판정이 있음 | INTAKE_DECIDED, SERVER_APPROVED, APPROVAL_GRANTED, RELATION_CREATED |
| 04 등록·실행 | 신청 상세 적용 7단계(`S03.stages`)가 승인 → (로컬은 LiteLLM 등록 해당 없음) → 키 반영 → PC 수신 → 시작 → 도구 발견까지 진행. 멈추면 그 줄에 원인과 해결 단추(`S-intake_detail.fix_target` 등) | 수동 조작 0, 1분 안 PC 수신, 격리 안 시작 | 단계별 영수증 |
| 05 직원 사용 가능 | 직원: 내 MCP 서버에 「준비 중」 → 「사용 가능」 카드, 서랍 도구 표(`S-staff_servers.tools`). 터미널 `mint server list` | 웹과 CLI의 서버·도구 목록이 같음 | — |
| 06 도구 목록 | Claude Code를 새 세션으로 열고 MCP 도구 목록 조회(`H1.call` / `H2.call`) | 승인 서버 도구가 보이고 차단 도구는 안 보임 | DISCOVERY_EVALUATED |
| 07 도구 호출 | Claude Code에서 업무 요청 → 실제 응답. 관리자 호출 기록 「도구 호출」 보기에 허용 행, 직원 「내 호출」에 같은 행 | 확인 창 없음, 호출 기록 1행, 첫 응답 단계 체크 | DECISION_EVALUATED, CALL_RESPONSE_RECEIVED |
| 08 권한 없는 도구 거부 | 관리자: `S05.block`(이 도구 차단) → 직원이 같은 도구 호출 → 거부 첫 줄(F.1) → 직원 서랍에서 그 도구가 「관리자 차단」 | 그 도구만 막힘, 서버에 전송 안 됨, 안내에 권한 요청 방법 포함 | DENIAL_CREATED, DECISION_EVALUATED(deny) |
| 09 권한 요청·승인 | 직원: `S-staff_servers.request_access`(또는 `mint request access <서버> <도구> --reason …`) → 관리자: `S-approvals_access.open` → 서랍 → `S-approvals_access.resolve_lift` | 요청 1건이 양쪽에 같은 항목으로 보임, 관리자 1클릭 | ACCESS_REQUEST_OPENED, DENIAL_LIFTED, ACCESS_REQUEST_RESOLVED |
| 10 승인 뒤 사용 | 직원: 같은 세션에서 같은 호출 재시도 → 응답. 「내 요청 → 권한 요청」이 「허용됨」 | 재설치·재로그인 없이 즉시 | DECISION_EVALUATED(allow) |
| 11 Root 비활성화 | Root: 서버 상세 `S-server_detail.suspend`(사유 입력). 전체를 멈추려면 `S-root.halt` | 확인 창에 영향 수·즉시 범위·늦는 범위·남는 것 표시 | SERVER_SUSPENDED (+ GLOBAL_HALT_SET) |
| 12 권한·세션 무효화 | 직원의 열린 Claude Code 세션에서 호출 → 거부(「중지된 서버」). 전파 상태 줄(`S-server_detail.propagation`)에 MINT 판정 즉시, LiteLLM 키 60초 이내, PC 수신·실행기 정지 시각. 사람까지 막으려면 `S-people.lockout` | 중지 뒤 첫 호출부터 거부, PC 실행기 정지 확인, 미전파는 경보 | DECISION_EVALUATED(deny), 전파 영수증 |
| 13 재접속 뒤 유지 | 직원: Claude Code 재시작, PC 재부팅, `mint` 재실행, 재로그인 뒤 호출 → 계속 거부. `S-root_actions.verify`로 다시 확인. 재개(`S04.toggle`) 뒤에는 즉시 복귀 | 재시작 3종 모두 거부 유지, 재개 뒤 2초 안 허용 | SERVER_RESUMED |

위험 요소: 저장소 기반 서버(uvx·npx 커밋 고정)를 끝까지 돌린 실측이 없고(USER_SCENARIOS E2E-04), Claude Code로 목록을 조회한 기록도 없습니다(E2E-06). 화면 설계와 별개로 가장 먼저 실측해야 합니다.

---

## E. Root Admin 통제

### E.1 역할과 권한 차이 (FM-62)

역할 값은 조회자 < 승인자 < 관리자 3단계를 유지하고, 운영자 행에 Root 표지를 더합니다(기본 계정 root는 항상 Root). 「보안 관리자」는 관리자와 가를 권한 차이의 근거를 찾지 못해 보류합니다.

| 조치 | 승인자 | 관리자 | Root |
|---|---|---|---|
| 신청 승인·거부, 호출 승인, 권한 요청 처리 | ○ | ○ | ○ |
| 도구·사용자 차단과 해제, 서버 중지·재개, 이용 종료, 서버 폐기 | 차단·해제만 | ○ | ○ |
| PC 연결 중지·해제, 앱 자격 회수, 사람 MCP 차단 | × | ○ | ○ |
| 사람 전체 차단(키 차단·세션 종료 포함) | × | ○(본인·Root 대상 제외) | ○ |
| 접수·검사 중 강제 반려, 검사 생략 승인 | × | × | ○ |
| 진행 중 실행 취소 요청 | × | × | ○ |
| 전역 정지·해제, Root 지정 | × | × | ○ |
| 강제 조치 되돌리기 | × | 본인이 한 조치 | ○ |
| 자기 신청 승인(직무 분리 꺼짐) | 설정에 따름 | 설정에 따름 | 항상 가능(결정 7) |

관리자가 지금 하는 일(모드 변경, 운영자 삭제 등)을 Root 전용으로 줄이는 것은 기존 기능 축소이므로 CP-003으로만 제안합니다. 승인 전까지는 현행을 유지합니다.

### E.2 단계별 강제 조치 (모두 기존 메커니즘 재사용)

| 단계 | 조치 | 쓰는 메커니즘 | 즉시 적용 | 늦게 적용 | 되돌리기 |
|---|---|---|---|---|---|
| 신청 대기(접수) | 강제 반려 | 신청 결정(reject) + 철회가 쓰는 재시도 중단 | 신청 상태, 남은 검사 중단 | 원격 제출이면 LiteLLM 제출 거절(작업 실행기) | 재신청(FM-54) |
| 신청 대기 | 검사 생략 승인 | 예외 승인(except, 기본 30일) | 서버·승인·이용 관계 생성 | LiteLLM 등록, 키 반영, PC 수신(약 1분) | 승인 철회 / 서버 중지 |
| 검사 중 | 강제 반려 / 검사 생략 승인 | 위와 같음 + 작업 취소 | 위와 같음 | 실행 중 검사 작업은 임대 만료 때 멈춤(최대 60초, `docs/CLI.md` 148행) | 위와 같음 |
| 검사 완료 | 승인 / 거부 / 예외 승인 | 기존 결정 | — | — | — |
| 승인됨(배포 전) | 중지 / 승인 철회 / 이용 종료 | 서버 중지, 승인 철회, 이용 관계 종료 | MINT 판정 | LiteLLM 키 권한 최대 60초, PC 다음 보고 | 재개. 철회·종료는 재승인 |
| 설치됨·사용 중 | 도구 차단 / 사용자 차단 | denials | MINT 판정(같은 세션 즉시) | 없음 | 해제 1클릭 |
| 사용 중 | 서버 중지 | 서버 중지 + LiteLLM `reject` 보조(D-004 권고) | MINT 판정, LiteLLM 레지스트리 | PC 실행기 정지(다음 보고 약 20초), 키 권한 60초 | 재개 |
| 사용 중 | PC 연결 중지 / 해제 | 관리 AI 연결 중지 / 키트 키 폐기 | 결정 경로 거절 | PC 수신 뒤 실행기 정지 | 재개. 해제는 재설치 |
| 사용 중 | 진행 중 실행 취소 요청 | 호출 승인 취소, 작업 취소, PC 실행기 정지 지시 | 승인 대기 호출 취소 | 로컬 서버 프로세스 종료(다음 보고) | 없음 |
| 모든 단계 | 서버 폐기 | 서버 폐기 서비스(웹 라우트 신규) | 호출 차단 | 자격 삭제와 확인(작업 실행기), 증빙 뒤 종료 | 불가 |
| 모든 단계 | 전역 정지 | 설정에 정지 상태 추가 + PC 일괄 중지 지시 | 게이트웨이 판정(요청마다 DB 읽기) | PC 실행기 정지(다음 보고). LiteLLM에는 전역 스위치가 없어 보조로 활성 서버 일괄 `reject`(선택) | 정지 해제 |

### E.3 확인 창 규격 (W-08 네 줄)

모든 강제 조치 확인 창은 같은 순서로 씁니다.

```
[조치 이름] — 대상 이름
영향:        서버 1개 · 유효 승인 3건 · 사용자 4명(PC 5대) · 응답 대기 중 호출 2건
즉시:        MINT 판정이 다음 호출부터 거부합니다.
늦게:        LiteLLM 키 권한 최대 60초 · PC 실행기 정지는 다음 보고(약 20초)
취소 불가:   이미 원격 서버로 보낸 호출 2건은 끝까지 실행됩니다. 이미 받은 결과와 파일은 남습니다.
되돌리기:    「재개」로 즉시 복귀 / 또는 「되돌릴 수 없습니다. 다시 설치해야 합니다」
사유(필수):  [                ]
                                         [취소]  [서버 중지]
```

- 「취소 불가」 줄은 건수가 0이어도 「없음」으로 둡니다.
- 「이미 원격으로 보낸 호출」 건수는 허용 판정이 있고 응답 기록이 아직 없는 호출 수로 셉니다(추정: 원장에서 계산할 수 있음).
- 이름 입력 확인은 되돌릴 수 없는 조치(서버 폐기, 운영자 삭제, 조직 닫기, 전체 차단의 키 폐기)와 전역 정지에만 씁니다.

### E.4 전파 확인 (FM-59)

지금 단말 중지 화면이 쓰는 4상태(`T/endpoints.html:19-22`)를 모든 강제 조치에 같은 모양으로 넓힙니다.

| 지점 | 확인 방법 | 기준 시간 | 넘기면 |
|---|---|---|---|
| MINT 판정(플러그인) | DB 커밋 시각 + 집행 처리기 상태(대시보드 「집행 처리기 n/n」) | 즉시 | 처리기 미확인이면 ▲ 경보 |
| LiteLLM 레지스트리 | `reject`/`approve` 응답과 재조회 | 즉시(요청마다 개정 번호) | ▲ |
| LiteLLM 키·팀 권한 | 키 동기화 작업 완료 시각 + 재조회 | 60초(캐시 기본값) | 「미전파」 경보 |
| PC 수신 | 보고 응답의 수신 확인 시각, n/m대 | 다음 보고(약 20초, 꺼진 PC는 「수신 대기」) | 24시간 넘으면 기존 보고 끊김 경보 |
| PC 실행기 정지 | 프로세스 종료 보고 | 수신 직후 | 「확인 전」 |
| 관리 밖 경로 | 확인할 수 없음 | — | 항상 「확인되지 않음」으로 적음(W-13) |

판정 서버 장애 중에 건 조치는 PC에 닿지 않습니다. 이 경우 「PC 수신 대기 · 장애 복구 뒤 전달」로 표시합니다. 전역 정지·중지 상태는 PC가 마지막으로 받은 값을 장애 중에도 유지해야 합니다. 이것은 결정 6의 「이미 승인된 호출 통과」 범위 밖이라는 해석이며 소유자 확인이 필요합니다(CP-005).

### E.5 감사

- 모든 강제 조치는 기존 사건에 더해 `FORCED_ACTION_RECORDED`(신규) 1건을 남깁니다. 항목은 조치, 대상, 사유, 실행자, 영향 수치, 호출한 기존 사건 식별자입니다.
- 사유는 필수이고, LiteLLM은 서버 변경을 기록하지 않으므로 MINT 원장이 유일한 근거입니다(D-004).
- 강제 조치 기록 화면은 한정자 필터(실행자, 조치, 대상, 기간, 전파 결과)와 CSV·JSON 내보내기를 둡니다(W-07).

---

## F. 보안·사용성 균형

### F.1 거부 메시지 (하네스·CLI에 보이는 첫 줄)

모든 정책 거부의 첫 줄을 다음 틀로 맞춥니다.

```
[막힘] <무엇이> — <왜(정책·차단 이름)>. <누구에게 영향>. 해결: <다음 행동 한 가지>.
```

| 예 | 문구 |
|---|---|
| 관리자 차단 | [막힘] github_mcp의 delete_repo 도구 — 관리자가 막았습니다(사유: 삭제 도구 검토 중). 이 도구만 막혔고 다른 도구는 됩니다. 해결: `mint request access github_mcp delete_repo` 또는 직원 화면 「권한 요청」. 해제되면 바로 다시 호출하십시오. |
| 승인 없음 | [막힘] github_mcp — 이 서버를 쓸 승인이 없습니다. 해결: `mint request access github_mcp`. |
| 호출별 승인 | [승인 대기] github_mcp의 create_issue — 관리자 승인을 요청했습니다. 약 30초 뒤 같은 호출을 다시 하십시오. 진행: 직원 화면 「내 요청」. |
| 서버 중지 | [막힘] github_mcp — 관리자가 서버를 중지했습니다(사유: …). 재개되면 자동으로 다시 됩니다. 다시 시도하지 마십시오. |
| 시스템 오류 | [일시 오류] 판정 서비스에 연결하지 못했습니다. 정책 거부가 아닙니다. 약 5초 뒤 다시 하십시오. 참조 번호 … |

- 정책 거부는 「[막힘]」과 「[승인 대기]」, 시스템 오류는 「[일시 오류]」와 「[오류]」로 첫 단어부터 구분합니다(REQ-25).
- 오류 본문 JSON에 `resolution`(요청 명령)과 `request_link`(직원 화면 서명 링크)를 더합니다. 본인 확인에 쓰는 서명 링크 방식을 재사용합니다(`types/errors.py:134-135`).
- 사유 문구에 인증 정보나 내부 자료는 넣지 않습니다(POL-E-29).

### F.2 웹 거부 화면과 오류 화면 (두 틀)

| 틀 | 쓰는 때 | 구성 |
|---|---|---|
| 거부 화면(403·409 정책) | 역할 부족, 직무 분리, 상태상 불가 | 제목 「이 작업은 <필요 역할>이 할 수 있습니다」 / 지금 내 역할 / 막은 규칙 이름 / 영향 범위(어느 서버·어느 신청) / 해결: 권한을 줄 수 있는 사람 이름 + 「요청 문구 복사」 / 참조 번호 / 돌아가기 |
| 오류 화면(400·404·500) | 입력 오류, 없는 대상, 시스템 오류 | 제목 / 「정책 거부가 아닙니다」 한 줄 / 무엇을 하다 실패했는지 / 다시 시도 / 관련 목록으로 / 참조 번호(복사) |

- 409(낡은 화면)는 오류 화면으로 보내지 않고 같은 화면을 최신 값으로 다시 그리고 「상태가 바뀌었습니다. 확인하고 다시 누르십시오」 띠를 둡니다(현재 문구 유지, `C/core.py:98-100`).
- 조회자·승인자에게는 할 수 없는 단추를 숨기지 않고 비활성 + 사유 한 줄로 둡니다(W-12). 단, 메뉴는 들어갈 수 없는 화면을 빼고 그립니다. 이전 설계(11-14)의 「단추 제거」와 다르므로 DECISION_LOG에 남겨야 합니다.

### F.3 실행 전 안내

| 지점 | 안내 |
|---|---|
| 신청 2단계 | 「직원 PC에서 격리해 실행합니다 · 네트워크: 자동 · 파일: 선언된 경로만 · 승인 뒤 약 1분 안에 PC에 반영」 |
| 승인 단추 옆 | 「승인하면: 대상 · 기간 · LiteLLM 등록 → 키 반영 → PC 반영까지 자동」(현재 「승인하면」 줄을 넓힘) |
| 직원 서버 서랍 | 도구별 「호출마다 승인」 표시. 호출하기 전에 승인이 필요함을 압니다 |
| CLI | `mint server show <서버>`가 도구별 상태를 같은 말로 보입니다(H절). `mint can <서버> [도구]`는 선택 항목(C-08)으로 보류 |
| 강제 조치 | E.3 확인 창 |

### F.4 과도한 fail-closed 지점과 고칠 방향

| # | 지점 | 근거 | 방향 |
|---|---|---|---|
| FC-01 | 조직에 승인된 서버가 직원에게 안 보이고 요청도 못 함 | A1 | 「조직에서 쓰는 서버」 + 사용 요청 |
| FC-02 | 관리자 차단·범위 밖 도구의 요청 경로 없음 | A2, A4 | 권한 요청(FM-60) |
| FC-03 | 본인 확인이 「다른 키 로그인」을 요구하는데 방법 안내가 없음 | A3 | 방법 안내 줄. 키가 하나뿐인 조직에서 이 설정의 기본값은 소유자 확인(CP-006) |
| FC-04 | 로컬 판별 불가 신청을 웹에서 풀 수 없음 | A9, A10 | 단말 검사·예외 승인 단추 연결 |
| FC-05 | 승인 대상 삭제 시 「키 반영 대기」가 무한히 이어짐 | A11 | 단계 줄에 원인과 「대상 바꾸기」 |
| FC-06 | 승인 재확인 기한 초과 시 직원 책임이 아닌데 호출이 막힘 | REASON-APPROVAL_RECERT_REQUIRED, POL-O-14 | 기한 전 경보, 승인 센터 갱신 탭 일괄 재확인. 유예 기간 값(`recert_grace_days`)을 화면에 표시. 정책 자체는 유지 |
| FC-07 | 허용 목록 만료 시 그 제공자의 모든 호출이 막힘 | REASON-ALLOWLIST_EXPIRED | 만료 7일 전 경보와 「90일 연장」 1클릭 |
| FC-08 | 콘솔에 LiteLLM 읽기 키가 없으면 승인·운영자 지정이 「명령줄에서」로 끝남 | A16 | 시작하기에 「설정 누락」 항목과 설정 이름. 해당 단추는 비활성 + 사유 |
| FC-09 | 입력 오류가 무엇인지 말하지 않음 | `P/common.py:41-43` | 항목 이름과 허용 값 예시 |
| FC-10 | 403이 사유 없이 제목뿐 | `C/error_pages.py:20` | F.2 거부 화면 |
| FC-11 | 관리자가 여럿인데 시작하기가 「승인자 없음」을 필수로 셈 | A15 | 승인 가능한 사람(관리자 포함)이 1명 이상이면 완료 |
| FC-12 | 감사 기록 실패·집행 상태 미확인 시 호출 차단 | REASON-AUDIT_FAILURE, REASON-ENFORCEMENT_UNVERIFIED | 결정 6과의 경계를 확인 필요(추정: 버퍼가 넘칠 때만). 화면에는 「일시 오류」로 표시하고 경보를 연결 |

### F.5 POLICY_CONTROL_MATRIX deny_reason 행에 채울 값

```csv
control_id,applies_to,resolution,root_override,ux_review
REASON-SERVER_UNREGISTERED,게이트웨이·PC의 등록 안 된 서버 호출,직원: 서버 신청(mint server add 주소),없음(결정 6: 처음 보는 서버는 막음),문구에 신청 명령 추가
REASON-SERVER_NOT_APPROVED,심사 중인 서버 호출,직원: 서버 신청 진행 보기 / 관리자: 신청 상세 승인,Root 검사 생략 승인(사유 필수),「승인되면 자동으로 쓸 수 있음」 한 줄 추가
REASON-APPROVAL_ABSENT,승인된 서버·내 범위 승인 없음,직원: 권한 요청 → 관리자: 이 사람에게 허용,승인 부여,가장 흔한 막힘(A1)·요청 명령과 링크 필수
REASON-TOOL_NOT_IN_APPROVAL,도구를 명시한 승인의 범위 밖 도구,직원: 권한 요청 → 관리자: 승인 범위에 도구 추가,승인 범위 수정,결정 4와 어긋나 보이므로 관리자 화면에 「도구 명시 승인」 표시
REASON-POLICY_DETECT,인자 정책(경로·주소·내부 주소·정의 안 된 인자),인자를 고쳐 재호출 / 정당하면 권한 요청(허용 호스트·경로 추가),승인 조건 수정(허용 호스트·경로·인자),정책 이름은 이미 표시됨·걸린 인자 이름(값 제외) 추가
REASON-CONTRACT_DRIFT,승인 때와 달라진 서버 계약,관리자: 서버 상세 계약 탭 재승인,재승인 계획 등록,직원에게 「관리자 재확인 중」과 경보 연결
REASON-OUTPUT_SCAN,결과 검사(도구는 이미 실행됨),다시 시도하지 않음·참조 번호를 관리자에게 전달,없음,「이미 실행됨」 문구 양호·유지
REASON-SERVER_REJECTED,거절된 서버,직원: 새 판본으로 재신청,재신청 뒤 승인,거절 사유 보기 링크 추가
REASON-SERVER_SUSPENDED,중지된 서버,기다림(재개되면 자동 복귀),재개,중지 사유·실행자 표시 추가·재시도 금지 안내
REASON-SERVER_TERMINATED,폐기된 서버,직원: 재신청,없음(폐기는 되돌릴 수 없음),PC에서 항목이 제거됨을 안내
REASON-RELATION_TERMINATED,종료된 이용 관계,직원: 권한 요청(사용 요청),새 승인,「이용 종료」를 직원 말로 풀어 씀
REASON-DENIED,관리자 차단(도구·사용자·서버),직원: 권한 요청 → 관리자: 해제 1클릭,해제,사유 표시 추가·「해제되면 바로」 안내 양호
REASON-APPROVAL_REVOKED,철회된 승인,직원: 권한 요청,승인 재부여,철회 사유 표시
REASON-APPROVAL_EXPIRED,만료된 승인,직원: 권한 요청(갱신) / 관리자: 승인 센터 갱신 탭,일괄 갱신,만료 7일 전 직원 카드에 갱신 요청 단추
REASON-APPROVAL_RECERT_REQUIRED,재확인 기한이 지난 승인,관리자: 접근 통제 재확인(직원 조치 없음),재확인,직원 책임 아님을 명시·FC-06
REASON-CALL_APPROVAL_REQUIRED,관리자가 호출별 검토로 지정한 도구,자동 요청됨·약 30초 뒤 같은 호출 재시도,승인(1회·10분·30분) 또는 상시 규칙,양호·「내 요청」 위치 추가
REASON-CALL_APPROVAL_STALE,승인 뒤 인자가 달라진 호출,같은 호출을 다시 보내 새 승인 요청,승인,「다시 확인」이 모호함 → 「승인받은 내용과 인자가 다릅니다」
REASON-CALL_APPROVAL_DENIED,거부된 호출 승인,거부 사유 확인·반복 금지·이의는 권한 요청,새 요청 승인,양호
REASON-CONSENT_REQUIRED,동의가 필요한 서버,직원 본인: 내 MCP 서버에서 동의,없음(본인 동의는 대신할 수 없음),동의 링크를 첫 줄에
REASON-CONSENT_EXPIRED,만료된 동의,직원 본인: 다시 동의,없음,만료 7일 전 직원 화면 알림
REASON-CONSENT_REVOKED,철회한 동의,직원 본인: 다시 사용하기 또는 동의,없음,본인이 그만둔 것임을 명시
REASON-ALLOWLIST_EXPIRED,만료된 제공자·주소 허용 목록,관리자: 허용 목록 연장(직원 조치 없음),허용 목록 추가,직원 책임 아님 명시·FC-07
REASON-SERVER_IDENTITY_MISMATCH,등록과 다른 서버 식별 정보,관리자: 서버 상세 재검사·재승인,재승인,직원에게 「관리자 확인 중」
REASON-SERVER_IDENTITY_AMBIGUOUS,같은 이름이 여러 서버로 풀림(시스템),관리자: LiteLLM 등록 중복 정리,없음,오류 화면 틀·경보 연결
REASON-SERVER_UNRESOLVED,서버를 식별하지 못함(시스템),잠시 뒤 재시도·계속되면 참조 번호 전달,없음,「정책 거부가 아닙니다」 명시
REASON-MASTER_KEY_FORBIDDEN,마스터 키로 한 도구 호출,본인 키 사용(PC 설치 키),없음(무조건),현재 문구 양호
REASON-EXTERNAL_MCP_FORBIDDEN,게이트웨이 밖 외부 MCP 호출,직원: 그 서버를 신청,없음,신청 명령 추가
REASON-REALTIME_FORBIDDEN,실시간 호출 경로,지원하지 않음·일반 호출 사용,없음,대안 한 줄 추가
REASON-CODE_EXECUTION_FORBIDDEN,제공자 코드 실행 도구,지원하지 않음,없음(추정),대안 한 줄 추가
REASON-TOKEN_FORWARD_FORBIDDEN,호출자 토큰 전달이 필요한 서버,관리자: 승인 조건에 토큰 전달 허용,승인 조건 수정,관리자용 문구로 분리
REASON-RESOLVED_ADDRESS_FORBIDDEN,이름 풀이 결과가 금지 주소,관리자: 주소 허용 목록 검토,허용 목록 추가,직원에게 「관리자 확인 필요」
REASON-TOKEN_AUDIENCE_MISMATCH,다른 서버용 토큰,직원: 그 서버에 다시 인증,없음,재인증 방법 한 줄
REASON-TOKEN_SCOPE_EXCEEDED,승인보다 넓은 토큰 범위,관리자: 재승인,재승인,직원에게 「관리자 확인 필요」
REASON-UNSUPPORTED,지원하지 않는 호출 형태(시스템),하네스·키트 판본 확인,없음,오류 화면 틀
REASON-SCHEMA_ERROR,요청 형식 오류(시스템),하네스·키트 갱신(mint doctor),없음,오류 화면 틀
REASON-POLICY_VERSION_MISMATCH,정책 판본 전환 중(시스템),자동 복구·잠시 뒤 재시도,없음,「일시 오류」로 표시
REASON-DEPENDENCY_FAILURE,판정 서비스·DB 불통(시스템),약 5초 뒤 재시도(승인된 호출은 통과),없음,「일시 오류」 문구 양호
REASON-AUDIT_FAILURE,감사 기록을 남기지 못함(시스템),잠시 뒤 재시도·참조 번호,없음,결정 6과의 경계 확인 필요·FC-12
REASON-ORG_BOUNDARY,조직에 묶이지 않았거나 다른 조직의 서버,관리자: 조직 연결,조직 연결·기본 조직 지정,직원에게 「관리자에게 조직 연결 요청」
REASON-ANONYMOUS,사용자를 식별하지 못한 키,직원: 설치 명령 다시 붙여 넣기(mint relink),없음,재연결 명령 추가
REASON-ENFORCEMENT_UNVERIFIED,정책 적용 상태 미확인(시스템),자동 복구 대기,없음,「일시 오류」·대시보드 집행 상태와 연결·FC-12
REASON-CANCELLED,관리자·호출자가 취소한 호출,필요하면 다시 요청,없음,누가 취소했는지 표시
REASON-CONFIRMATION_REQUIRED,본인 확인이 필요한 도구,직원 본인: 확인 링크에서 확인 뒤 재요청,없음(본인만),링크 양호·다른 로그인 방법 안내(FC-03)
REASON-CONFIRMATION_STALE,확인 뒤 내용이 달라진 호출,직원 본인: 다시 확인,없음,「확인한 내용과 다릅니다」로 구체화
```

전역 정지용 사유는 신규로 한 줄 더합니다.

```csv
control_id,applies_to,resolution,root_override,ux_review
REASON-GLOBAL_HALT(신규),전역 정지 중 모든 MCP 호출,기다림(해제되면 자동 복귀)·요청 불가,정지 해제,「관리자가 MCP 사용을 일시 정지했습니다」·시작 시각 표시
```

---

## G. 디자인 시스템 초안 (DESIGN_SYSTEM.md 본문)

### G.0 범위와 원칙
웹 콘솔(관리자·직원)과 PC 터미널 화면의 규칙입니다. 밝은 LiteLLM 테마와 현재 `console.css` 토큰을 유지하고(FM-26), 아래 규칙을 더합니다.

### G.1 색
| 토큰 | 값 | 쓰임 |
|---|---|---|
| `--text` / `--muted` | #030712 / #4b5563 | 본문 / 보조 |
| `--bg` / `--bg-subtle` / `--border` | #ffffff / #f9fafb / #e5e7eb | 배경 / 표 머리·띠 / 선 |
| `--accent` | #111827 | 주 단추(한 구역에 하나) |
| `--ok` / `--wait` / `--danger` / `--off` | #15803d / #92400e / #b91c1c / #4b5563 | 허용·정상 / 대기·검토 / 차단·실패 / 해당 없음 |
| `--chart-1..6` | 파랑 계열 | 양을 나타내는 차트 전용 |
| `--sev-critical/high/medium/low`(신규) | #7f1d1d / #b91c1c / #92400e / #4b5563 | 경보 심각도 전용 |

- 규칙 G1-1: 결정 색은 허용 `--ok`, 승인 필요 `--wait`, 차단 `--danger`, 관측 `--off`로 고정합니다. 근거: 현재 주석(`console.css:235`).
- 규칙 G1-2: 심각도 차트는 심각도 색을 씁니다. 파랑 한 색을 금지합니다. 근거: admin-dashboard.png(V5).
- 규칙 G1-3: 색만으로 구분하지 않고 아이콘과 글자를 함께 씁니다(현재 `ICONS` 유지).

### G.2 글꼴·크기
본문 14px/1.6, 제목 24px, 절 16px, 소제목 14px 굵게, 보조 12px, 숫자 카드 28px. 숫자는 고정폭 숫자(tabular-nums). 12px 보조 글자에 조치 안내를 넣지 않습니다. 조치 안내는 본문 크기로 씁니다. 근거: staff-staff_intakes_new.png(작은 회색 안내).

### G.3 간격·배치
- 토큰 `--s1..s5` = 4·8·16·24·32. 본문 여백 32px(1100px 이하 24px, 767px 이하 16px).
- 규칙 G3-1: 제목 아래 단추 줄(`.actions`)과 다음 요소 사이는 `--s3`(16px). 근거: V3.
- 규칙 G3-2: 화면 순서는 제목 → (탭) → 요약 → 필터 → 목록·상세. 탭이 요약보다 먼저 옵니다. 근거: 현재 화면마다 순서가 다름(admin-approvals.png와 admin-access.png).
- 규칙 G3-3: 숫자 요약이 4개를 넘거나 화면 폭이 600px 이하이면 카드 대신 한 줄 요약 띠(`.strip`)를 씁니다. 근거: mobile-staff.png(V10).
- 규칙 G3-4: 차트는 기간 내 표본이 5건 미만이면 그리지 않고 숫자만 보입니다. 근거: V6.
- 규칙 G3-5: 차트 축 이름은 24자까지 보이고 넘치면 말줄임 + 툴팁입니다. 왼쪽 여백은 가장 긴 이름에 맞춥니다. 근거: V4.

### G.4 표
- 행 높이 48px, 촘촘한 표 40px(현재 값).
- 첫 열은 이름이고 링크입니다. 식별자는 이름과 다를 때만 둘째 줄에 보입니다. 근거: V8.
- 사람·팀은 이름으로 보이고 식별자는 툴팁입니다. 근거: I7.
- 숫자는 오른쪽 정렬, 시각은 `연-월-일 시:분`입니다.
- 행 조치는 맨 오른쪽 열에 최대 2개, 나머지는 서랍에 둡니다.
- 좁은 화면에서는 표가 가로로 스크롤되고 첫 열을 고정하며 오른쪽 끝에 그림자를 둡니다. 근거: mobile-intakes.png.
- 빈 표는 한 줄 제목 + 다음 행동 단추 하나입니다.

### G.5 필터
시간 범위는 세그먼트, 상태는 세그먼트 또는 탭, 나머지는 선택 상자 + 「조회」입니다. 걸린 필터는 칩으로 보이고 「× 지우기」를 둡니다. 감사·기록 화면은 한정자 필터(행위자, 행위, 대상, 기간, 결과)와 내보내기, 기본 표시 기간을 화면 위에 적습니다(W-07).

### G.6 상태 배지
| 수준 | 아이콘 | 예 |
|---|---|---|
| ok | ✓ | 승인됨, 통과, 관리형, 허용 |
| wait | ◷ | 검사 중, 승인 대기, 판별 불가, 검토 필요 |
| error | ▲ | 검사 실패, 시작 실패, 갱신 실패 |
| block | ⊘ | 차단됨, 거절됨, 중지됨, 연결 해제 |
| off | – | 결정됨, 철회됨, 해당 없음 |

- 규칙 G6-1: 심각도는 상태 배지를 쓰지 않고 색 점 + 글자(심각·높음·보통·낮음)로 씁니다. 경보 상태 「열림」은 wait입니다. 근거: V7.
- 규칙 G6-2: 같은 상태는 모든 화면과 CLI에서 같은 말을 씁니다(H.5 상태 낱말 표).
- 규칙 G6-3: 화면에 영문 내부 이름을 내지 않습니다. 사전에 없는 값은 「알 수 없는 종류(원래 값)」로 보이고 검사에서 실패시킵니다. 근거: V8.

### G.7 단추
| 종류 | 모양 | 쓰는 곳 |
|---|---|---|
| 주 단추 | 검정 채움 | 한 구역에 하나. 다음 단계로 가는 행동 |
| 보통 | 흰 바탕 테두리 | 그 밖의 모든 행동, 행 조치 |
| 위험 테두리(신규 `.danger-outline`) | 빨간 글자 + 테두리 | 되돌릴 수 있는 차단·중지·취소를 여는 단추 |
| 위험 채움 | 빨간 채움 | 확인 창의 마지막 단추, 되돌릴 수 없는 조치만 |

- 규칙 G7-1: 표 행에는 빨간 채움 단추를 두지 않습니다. 근거: V1, W-08.
- 규칙 G7-2: 승인과 거부는 같은 크기로 나란히 둡니다. 승인만 주 단추입니다(W-03).
- 규칙 G7-3: 누르면 잠기고 「처리 중…」을 보입니다.
- 규칙 G7-4: 비활성 단추 옆에는 사유 한 줄을 둡니다. 툴팁만 두지 않습니다(W-12, FC-03).
- 규칙 G7-5: 선택 상자의 기본값은 현재 값입니다. 근거: V2.

### G.8 확인 창
제목은 「조치 — 대상」, 본문은 E.3의 영향·즉시·늦게·취소 불가·되돌리기 순서입니다(W-08). 이름 입력은 되돌릴 수 없는 조치에만 씁니다. 되돌릴 수 있고 한 사람·한 도구에만 영향이 가는 조치(도구 차단, 해제)는 확인 창 없이 실행하고 성공 띠에 「되돌리기」를 둡니다. 근거: U8·U9의 1클릭 요구.

### G.9 알림 띠·오류 화면
초록(성공) / 노랑(주의·기본 비밀번호) / 빨강(오류·전역 정지). 오류 띠는 「무엇이 · 왜 · 해결 단추」입니다. 거부 화면과 오류 화면은 F.2의 두 틀만 씁니다. 근거: V12, W-01.

### G.10 양식
라벨은 입력 위, 예시는 입력 아래 본문 크기, 필수는 「(필수)」 글자로 씁니다. 오류는 해당 입력 아래에 둡니다. 2단계 이상이면 단계 표시(1/3)를 둡니다. 근거: 터미널 신청 화면이 이미 1/3·2/3·3/3을 씀(`mint_kit.py:5185-5197`).

### G.11 반응형
| 폭 | 규칙 |
|---|---|
| 1101px 이상 | 사이드바 220px, 서랍 480px |
| 601~1100px | 사이드바 72px(아이콘), 표 가로 스크롤 |
| 600px 이하 | 사이드바는 서랍형, 카드는 요약 띠, 서랍은 전체 폭, 단추 줄은 세로로 쌓고 주 단추가 위 |

900px 높이에서 사이드바 전 항목이 보여야 합니다(B.2). 근거: A14.

### G.12 접근성
초점 테두리 2px 유지, 아이콘 단추에 이름 붙이기, 표 머리 `scope`, 대비 4.5:1 이상(12px 회색 글자 `--muted`는 현재 값 유지), 확인 창을 열면 초점을 창 안으로 옮기고 닫으면 원래 단추로 돌립니다.

### G.13 터미널 화면(`mint`)
- 맨 위 한 줄: 제품, 화면 이름, 연결 상태. 그다음 탭, 본문 상자, 맨 아래 키 안내(현재 구조 유지, `mint_kit.py:5067-5150`).
- 탭 이름은 웹 메뉴와 같은 말을 씁니다: 1 상태 · 2 내 MCP 서버 · 3 서버 신청 · 4 내 요청(신규).
- 색은 `NO_COLOR`와 TTY 아님에서 끕니다. 상태는 글자로도 구분합니다(현재 `[이름]` 방식 유지).
- 오류 줄은 「! 무슨 일 — 이유. 다음: 명령」 한 형식입니다.

---

## H. CLI 설계 (`mint`)

### H.1 명령 계층 (명사 → 동사, C-02)

| 명령 | 하는 일 | 옛 이름(별칭으로 유지) |
|---|---|---|
| `mint` | TTY면 화면, 아니면 `mint status --json`과 같음 | `mint screen` |
| `mint status` | 계정, 게이트웨이, 키 상태, PC 설치 방식, 서버 수, 대기 요청 수 | 설치기 `status` |
| `mint server list` | 내가 쓸 수 있는 서버와 상태 | (신규) |
| `mint server show <서버>` | 도구별 상태(사용 가능·관리자 차단·호출마다 승인), 만료 | (신규) |
| `mint server add <주소\|이름 -- 명령> [--purpose …]` | 서버 신청 | `mint add` |
| `mint server get <서버>` | 승인된 묶음 받기 | `mint get` |
| `mint request list` | 서버 신청 + 권한 요청 + 승인 대기 호출의 진행 | `mint requests` |
| `mint request show <번호>` | 한 건의 단계·사유·다음 할 일 | (신규) |
| `mint request access <서버> [도구] --reason …` | 막힌 도구 권한 요청 | (신규, FM-60) |
| `mint request cancel <번호>` | 신청·요청 취소 | (신규) |
| `mint request inspect <신청>` | 관리자가 요청한 도구 목록 확인 실행 | `mint inspect` |
| `mint app new\|list\|remove\|run\|env\|mcp` | 앱 자격 | `mint app rm` |
| `mint doctor` | 설치 점검과 고칠 명령 | 설치기 `check` |
| `mint config list` | 게이트웨이 주소, 설치 폴더, 판본(키 값은 보이지 않음) | (신규, C-09) |
| `mint link <주소>` | 설치 명령 다시 연결 | `mint relink` |
| `mint install\|uninstall\|sync\|report` | 설치·유지(도움말에서는 「설치·유지」 묶음) | 그대로 |

`--kit <폴더>`는 어느 위치에 와도 받습니다(지금은 앞에 오면 설치기 파서로 빠짐, REFERENCE_RESEARCH B.4).

### H.2 도움말
- `mint --help`는 묶음별로 보입니다: 자주 쓰는 일(status, server, request) / 앱 자격(app) / 설치·유지(doctor, link, install, uninstall, config). 끝에 예시 3개를 둡니다(C-01).
- 모든 옵션에 한국어 한 줄 설명과 기본값을 답니다. 지금 `add`의 `--grade` `--ro` `--rw` `--request-id`는 설명이 없습니다(`mint_kit.py:6364-6376`).
- 하위 명령 도움말은 설명 → 사용법 → 옵션 → 예시 순서입니다.

### H.3 오류와 복구 안내 (C-05, C-06)
형식은 `오류: <무슨 일> — <이유>.`와 `다음: <칠 명령>` 두 줄입니다. 트레이스백은 `--debug`에서만 보입니다.

| 상황 | 지금 | 바꿀 문구 |
|---|---|---|
| 설치 안 됨 | 트레이스백(`FileNotFoundError … kit.json`) | 오류: MINT가 이 PC에 설치돼 있지 않습니다. / 다음: 직원 화면 「내 PC」에서 설치 명령을 만들어 붙여 넣으십시오. |
| 키 없음·거절 | 「한 줄 설치 명령을 다시 붙여 넣으십시오」 | 유지 + 다음: `mint link <주소>` |
| 인자 부족 | 영문 argparse 문구 | 오류: 서버 이름이 필요합니다. / 예: `mint server show github_mcp` |
| 알 수 없는 옵션 | 영문 argparse 문구 | 오류: `--bogus`는 없는 옵션입니다. / 다음: `mint server add --help` |
| 정책 거부 | 서버 문구 그대로 | F.1 첫 줄 + 다음: `mint request access …` |
| 게이트웨이 불통 | 「게이트웨이에 닿지 못함」 | 유지 + 「정책 거부가 아닙니다」 + 다음: `mint doctor` |

### H.4 `--json`, 비대화형, 종료 코드
- 모든 목록·조회 명령은 `--json`을 받습니다(`status`, `server list/show`, `request list/show`, `app list`, `doctor`, `config list`). 출력은 한 객체이고 키 이름은 웹 API와 같습니다(C-03).
- `--fields a,b`로 고릅니다. 없는 필드면 쓸 수 있는 필드 목록을 보입니다.
- JSON 모드에서 오류는 stderr에 `{"error":{"code","message","next"}}`로 내고 stdout은 비웁니다.
- `--non-interactive`를 두고, TTY가 아니면 자동으로 켭니다. 이때 묻지 않으며 필요한 값이 없으면 사용법 오류(2)입니다. `server add`는 `--purpose`가 필수가 됩니다. `--yes`는 확인만 건너뜁니다.
- `NO_COLOR`를 지원합니다. 비밀을 받는 옵션은 두지 않습니다(C-07).

| 종료 코드 | 뜻 |
|---|---|
| 0 | 성공, 도움말 |
| 1 | 실행 실패(네트워크, 서버 오류) |
| 2 | 사용법 오류 |
| 3 | 연결 필요(키 없음·거절). `mint link`로 해결 |
| 4 | 정책 거부·권한 없음. `mint request access`로 해결 |
| 그 밖 | `mint app run`은 실행한 명령의 코드를 그대로 돌려줌(찾지 못하면 127) |

근거: C-04(0·1·2). 3·4는 정책 거부와 시스템 오류를 스크립트가 구분하도록 더했습니다(REQ-25). 서버 쪽 서비스가 권한 오류에 4를 이미 씁니다(`control/services/relations.py:28-29`).

### H.5 웹 ↔ CLI 대응

| 하는 일 | 웹 | CLI | 같아야 하는 결과 |
|---|---|---|---|
| 서버 신청 | 서버 신청 2단계 | `mint server add` | 같은 신청 1건, 같은 고정 커밋 |
| 신청 진행 보기 | 서버 신청 목록·상세 | `mint request list/show` | 같은 상태 낱말과 「다음 할 일」 |
| 신청 취소 | 「대기 취소」 | `mint request cancel` | 철회됨 |
| 쓸 수 있는 서버·도구 | 내 MCP 서버 서랍 | `mint server list/show` | 같은 서버·도구·상태 |
| 권한 요청 | 「권한 요청」 | `mint request access` | 같은 요청 1건 |
| 묶음 받기 | (자동) | `mint server get` | — |
| 도구 목록 확인 실행 | (관리자가 요청) | `mint request inspect` | 신청 상세에 결과 |
| 앱 자격 | 내 PC 「자격 회수」 | `mint app remove` | 회수됨 |
| PC 연결 | 「설치 명령 만들기」 | 붙여 넣기, `mint link` | 설치 상태 「관리형」 |
| 연결 해제 | 「이 PC 연결 해제」 | `mint uninstall` | 그 PC만 해제 |
| 상태 점검 | 내 PC | `mint status`, `mint doctor` | 같은 설치 상태·마지막 보고 |

상태 낱말(웹·CLI 공통): 접수 · 검사 중 · 검사 통과 · 판별 불가 · 검사 실패 · 승인됨 · 거절됨 · 철회됨 · 준비 중 · 사용 가능 · 시작 실패 · 중지됨 · 관리자 차단 · 호출마다 승인.

CLI 동작도 화면 동작표에 올립니다.

```csv
screen_id,screen,component_id,action_id,label,roles,feature_id,preconditions,action,api,policy_id,loading_state,success_state,failure_state,audit_event,test_id,status
T7,PC mint server,목록,T7.list,mint server list,staff,FM-63 FM-27,PC 연결됨,실행,GET /mint/v1/endpoint/me,,터미널 진행 줄,서버·상태 표 또는 JSON,「오류/다음」 두 줄과 종료 코드 1·3,,QA-T7-001,SPECIFIED
T7,PC mint server,상세,T7.show,mint server show 서버,staff,FM-63 FM-60,PC 연결됨,실행,GET /mint/v1/endpoint/me,POL-O-02,터미널 진행 줄,도구별 상태 표 또는 JSON,없는 서버면 종료 코드 1과 mint server list 안내,,QA-T7-002,SPECIFIED
T8,PC mint request,권한 요청,T8.access,mint request access 서버 도구,staff,FM-60 FM-63,PC 연결됨·도구가 막힘,실행(--reason 필수),POST /mint/v1/endpoint/access-requests(신규),REASON-DENIED,터미널 진행 줄,「요청했습니다. mint request list로 진행을 봅니다」,요청할 수 없는 사유면 종료 코드 4와 안내,ACCESS_REQUEST_OPENED(신규),QA-E2E-09-009,SPECIFIED
T8,PC mint request,취소,T8.cancel,mint request cancel 번호,staff,FM-36 FM-63,내 대기 신청·요청,실행(확인·--yes),POST /mint/v1/endpoint/requests/{request_id}/cancel(신규),,터미널 진행 줄,「취소했습니다」,이미 처리됐으면 최신 상태 표시,INTAKE_DECIDED(철회) 또는 ACCESS_REQUEST_CANCELLED(신규),QA-T8-001,SPECIFIED
T9,PC mint status,상태,T9.status,mint status,staff,FM-63,없음,실행,GET /mint/v1/endpoint/me,,없음,계정·게이트웨이·키·설치 방식·서버 수·대기 수,미설치면 한국어 안내와 종료 코드 3,,QA-T9-001,SPECIFIED
```

---

## I. 신규 기능 확정안

| FM | 판정 | 이유와 겹치는 기존 메커니즘 |
|---|---|---|
| FM-55 전역 정지 | 확정(MINT 자체) | 운영 모드는 집행·관측뿐이라 겹치지 않습니다(`types/settings.py:15-17`). 관측은 통제를 약하게 하는 반대 방향입니다. LiteLLM에는 전역 스위치가 없습니다(LITELLM_MCP_REUSE 8절). 설정 저장·변경 경로(`settings`)와 PC 중지 지시(FM-32)를 재사용합니다. 「비상 정책」은 범위 3종(모든 호출 / 로컬만 / 새 승인·배포 동결)으로 확정하고 별도 정책 편집기는 만들지 않습니다 |
| FM-56 Root 강제 상태 변경 | 확정(묶음 화면) | 새 판정 로직을 만들지 않습니다. 신청 결정·예외 승인·철회, 서버 중지·재개·폐기, 이용 종료, 승인 철회를 한 구역에서 부르고 기록 1건을 남깁니다. 새로 필요한 것은 접수·검사 중 반려 허용, 서버 폐기 웹 라우트, 기록 표입니다 |
| FM-57 사람·키 일괄 차단 | 확정(묶음 단추) | 사람 MCP 차단(denials) + PC 연결 해제 + 앱 자격 회수 + 키 차단(key-blocks) + 관리자 세션 폐기(`revoke_user_sessions`)를 한 번에 부릅니다. 새로 필요한 것은 수동 키 차단 시작과 직원 세션 폐기입니다 |
| FM-58 진행 중 실행 취소 | 확정(범위 축소) | 취소할 수 있는 것은 승인 대기 호출(호출 승인 취소), 대기·실행 작업, PC 로컬 서버(연결 중지)입니다. 이미 원격으로 보낸 호출은 취소할 수 없다고 표시합니다. LiteLLM 세션 삭제는 워커 하나에만 적용되어 쓰지 않습니다(D-004) |
| FM-59 전파 확인 | 확정, FM-56·57·55 화면에 병합 | 승인 7단계(FM-08) 영수증과 단말 중지 4상태를 같은 모양으로 넓힙니다. LiteLLM 키는 60초 상한으로 봅니다(D-004) |
| FM-60 막힌 도구 권한 요청 | 확정 | 요청 기록(얇은 표)만 새로 만들고, 처리는 차단 해제·승인 부여·호출 승인·갱신·재확인 중 하나를 부릅니다. 호출별 승인 자동 요청은 그대로 두고 같은 「내 요청」에 묶어 보입니다 |
| FM-61 정책 예외 관리 화면 | 병합(승인 센터 「예외·2인 확인」 탭 + 신청 상세 「예외 승인」 단추) | 화면은 이미 있고 대기가 있을 때만 보입니다(`P/approvals.py:153-154`). 별도 화면은 만들지 않습니다 |
| FM-62 역할 분리 | 확정(Root 표지 + 메뉴 역할 거르기 + 거부 화면), 「보안 관리자」는 보류 | 역할 3종과 명령별 역할 표를 재사용합니다. 관리자 권한을 줄이는 부분은 CP-003입니다 |
| FM-63 CLI 정비 | 확정 | H절. 옛 명령은 모두 별칭으로 유지합니다 |

### 변경 제안 (CHANGE_PROPOSALS.md에 넣을 본문)

```
## CP-001 · 화면 목록 생성기(inventory)가 formaction·매크로·상수 경로를 읽도록 고친다
- 제안자·모델: PC-DESIGN-01 · Claude Mythos 5.2
- 대상 FM / 화면 동작: FM-26 · check.py 경고 14건 중 6건, SCREEN_INVENTORY 누락
- 지금: 양식이 있는 라우트 6개를 「양식 없음」으로 경고하고, GET /staff/confirmations와 formaction 단추들을 목록에 넣지 못한다
- 바꿀 것: formaction 속성, confirm_dialog·confirm_submit 매크로의 action 인자, 변수 action, 상수로 준 라우트 경로를 읽는다
- 이유(근거·레퍼런스): REQ-26 판정을 이 도구에 맡기고 있음. A.2
- 영향(없어지거나 줄어드는 것): 없음
- 상태: 제안

## CP-002 · 쓰이지 않는 구 경로 정리(/staff/login POST, /staff/endpoint/kit, /approvals/new)
- 제안자·모델: PC-DESIGN-01 · Claude Mythos 5.2
- 대상 FM / 화면 동작: FM-22, FM-10
- 지금: 화면에서 닿지 않는 라우트가 남아 있고 /approvals/new는 직접 열면 400이다
- 바꿀 것: 통합 로그인·설치 명령 방식으로 대체된 것이 확인되면 제거하거나 새 경로로 넘긴다
- 이유(근거·레퍼런스): 템플릿 검색 0건, admin-approvals_new.png
- 영향(없어지거나 줄어드는 것): 구 경로로 직접 호출하던 스크립트(있다면). 묶음 파일 내려받기 방식 설치
- 상태: 제안(소유자 확인 전 구현 금지)

## CP-003 · 통제를 약하게 하는 조치를 Root 전용으로 한다
- 제안자·모델: PC-DESIGN-01 · Claude Mythos 5.2
- 대상 FM / 화면 동작: FM-70 S-policy.set_mode(관측 전환), FM-38 S-admin.remove_operator·set_operator_role(관리자 강등)
- 지금: 관리자면 누구나 관측 모드로 바꾸고 다른 관리자를 강등·삭제한다
- 바꿀 것: 관측 전환, 관리자 강등·삭제, Root 지정은 Root만. 나머지는 현행
- 이유(근거·레퍼런스): W-06(조직 전체 권한은 한 역할로), W-09(보호 약화 설정), V2
- 영향(없어지거나 줄어드는 것): 일반 관리자의 위 3가지 권한
- 상태: 제안(승인 전까지 현행 유지)

## CP-004 · 직원 「내 MCP 서버」의 「내 신청 이력」 탭을 없애고 메뉴 「서버 신청」으로 모은다
- 제안자·모델: PC-DESIGN-01 · Claude Mythos 5.2
- 대상 FM / 화면 동작: FM-04 S12.cancel(대기 취소는 서버 신청 목록에 유지)
- 지금: 같은 목록이 메뉴 항목과 탭 두 곳에 있다
- 바꿀 것: 탭 제거, 「준비 중」 카드의 진행 링크는 유지
- 이유(근거·레퍼런스): I4, T/staff_servers.html 20행
- 영향(없어지거나 줄어드는 것): 탭 하나(기능은 그대로)
- 상태: 제안

## CP-005 · 전역 정지·서버 중지는 판정 서버 장애 중에도 PC가 마지막 값을 유지한다
- 제안자·모델: PC-DESIGN-01 · Claude Mythos 5.2
- 대상 FM / 화면 동작: FM-55, FM-30, FM-20 (지킬 설계 결정 6과의 경계)
- 지금: 장애 중에는 승인된 서버 호출을 통과시킨다. 정지 상태를 어떻게 다룰지는 정해지지 않았다
- 바꿀 것: 장애 전에 받은 정지·중지 상태는 장애 중에도 막는다. 장애 중에 건 정지는 전달되지 않음을 전파 화면에 표시한다
- 이유(근거·레퍼런스): REQ-21·22, E.4
- 영향(없어지거나 줄어드는 것): 정지 중에는 「장애 시 통과」가 적용되지 않음
- 상태: 제안(결정 6 해석이므로 소유자 확인 필요)

## CP-006 · 본인 확인의 「다른 키로 로그인」 요구 기본값을 다시 정한다
- 제안자·모델: PC-DESIGN-01 · Claude Mythos 5.2
- 대상 FM / 화면 동작: 직원 본인 확인(POL-E-20·21), T/staff_requests.html 22행
- 지금: 호출한 키와 같은 키로 로그인하면 확인 단추가 비활성이다
- 바꿀 것: 기본은 같은 사람의 웹 로그인이면 확인 허용, 「다른 키 필요」는 선택 설정으로
- 이유(근거·레퍼런스): FC-03, 결정 5(입력 최소)와 결정 7(직무 분리는 선택)의 취지
- 영향(없어지거나 줄어드는 것): 기본 상태에서 키 분리 보장이 없어짐
- 상태: 제안(보안 판단이므로 소유자 확인 필요. 현재 기본값이 무엇인지는 확인하지 못함)
```

---

## J. 구현 작업 분할

파일은 묶음끼리 겹치지 않게 나눴습니다. 순서는 E2E-01~07을 막는 것부터, 그다음 E2E-08~10, E2E-11~13입니다. 독립 QA는 구현자가 아닌 검증자(D-003)가 실제 화면·터미널·하네스로 합니다.

| WP | 범위 | 손대는 파일 | 선행 | 모델 | 독립 QA 시험(동작 ID) |
|---|---|---|---|---|---|
| WP-00 계약·기준 문서 | 사건·사유·역할·오류 본문 형식, DB 표(권한 요청, 강제 조치, 정지 상태), 기준 시트 갱신, CP-001 | `src/mint_litellm/types/*`, `control/db/migrations/*`(신규 파일), `docs/product/*.csv`, `docs/product/DESIGN_SYSTEM.md`, `docs/product/CHANGE_PROPOSALS.md`, `scripts/product/*` | 없음 | Opus | QA-WP00-001: check.py 경고가 실제 미연결만 남는지 대조 |
| WP-01 공통 셸·디자인 시스템 | 사이드바(역할 거르기·높이), 상단 바, 단추 종류, 처리 중 표시, 거부·오류 화면 두 틀, 새 표시 낱말 | `C/static/console.css`, `C/static/console.js`, `T/base.html`, `T/staff_base.html`, `T/macros.html`, `T/error.html`, `T/error_bare.html`, `C/error_pages.py`, `C/templating.py`, `C/labels.py` | WP-00 | Sonnet | QA-NAV-001(1440×900에서 전 메뉴 보임), QA-S00-001·002, QA-RWD-001(390px에서 표 스크롤·단추) |
| WP-02 신청·서버 화면 | 신청 상세 탭 재구성(출처·공급망), 단말 검사·예외 승인 단추, 멈춘 단계 원인, 서버 상세 통제 패널·폐기 라우트, 승인 대기 서버 상세 오류 수정 | `P/servers.py`, `P/intake_submission.py`, `T/intake_detail.html`, `T/intake_new.html`, `T/intakes.html`, `T/_intake_pack.html`, `T/_repo_intake.html`, `T/server_detail.html`, `T/servers.html`, `T/_server_*.html`, `T/_tool_controls.html`, `T/_evidence.html` | WP-01 | Opus | QA-E2E-02-001, QA-E2E-03-001(`S-intake_detail.source_tab`), QA-S-intake_detail-001~004, QA-E2E-04-001(`S03.stages`), QA-S-server_detail-001 |
| WP-03 직원 화면 | 신청 2단계 단추 순서, 내 MCP 서버(요약 띠·조직 서버·도구 표), 내 요청 권한 요청 탭, 내 PC(PC별 해제), 사용량 차트 | `C/staff_pages.py`, `T/staff_servers.html`, `T/staff_requests.html`, `T/staff_intake_new.html`, `T/staff_intake_detail.html`, `T/staff_intakes.html`, `T/staff_endpoint.html`, `T/staff_usage.html`, `T/_staff_applications.html` | WP-01, WP-04(요청 서비스) | Sonnet | QA-E2E-01-001·002, QA-E2E-05-001, QA-E2E-08-001, QA-E2E-09-001~004, QA-S-staff_endpoint-001·002 |
| WP-04 권한 요청 서비스 | 요청 열기·취소·처리(기존 해제·승인·호출 승인 호출), 반복 승인 제안 계산, 서명 링크 | `control/services/access_requests.py`(신규), `control/links.py` | WP-00 | Opus | QA-WP04-001: 원인 5종별 처리 결과가 기존 화면(접근 통제·승인 센터)에 같은 기록으로 보이는지 |
| WP-05 승인 센터·접근 통제 화면 | 기본 탭, 권한 요청 탭·서랍, 예외·2인 확인 탭 상시 표시, 차단 탭 이름·출처 | `P/approvals.py`, `T/approval_center.html`, `T/_approvals_*.html`, `T/access.html`, `T/_allowlists.html`, `T/approval_new.html` | WP-01, WP-04 | Sonnet | QA-S-approvals-001, QA-E2E-09-005~008, QA-E2E-10-001(허용 뒤 같은 세션 재호출), QA-S-approvals_second-001 |
| WP-06 판정·단말 경로 | 거부 응답 첫 줄 틀과 `resolution`·`request_link`, 전역 정지 판정, 보고 응답에 정지·취소 지시, 단말용 권한 요청·취소 경로 | `src/mint_litellm/plugin/*`, `src/mint_litellm/endpoint/decide.py`, `src/mint_litellm/endpoint/routes.py`, `src/mint_litellm/endpoint/kit/mint_agent.py` | WP-00, WP-04, WP-07 | Opus | QA-E2E-06-001·QA-E2E-07-001(Claude Code 목록·호출), QA-E2E-08-002(거부 첫 줄), QA-E2E-12-001(열린 세션에서 거부) |
| WP-07 Root 통제 서비스 | 전역 정지 설정, 강제 조치 기록·전파 영수증, 접수·검사 중 반려·검사 생략 승인, 서버 중지에 LiteLLM `reject` 보조, 사람 전체 차단(수동 키 차단·직원 세션 폐기), 실행 취소, Root 표지 | `control/services/forced_actions.py`(신규), `control/services/lockout.py`(신규), `control/services/settings.py`, `control/settings_store.py`, `control/services/servers.py`, `control/services/intakes.py`, `control/services/console_sessions.py`, `control/sync_jobs.py`, `control/endpoint_coverage.py`, `control/key_block.py`, `control/operators.py` | WP-00 | Opus | QA-WP07-001: 조치별로 E.2 표의 즉시·지연 범위가 실제 시각으로 기록되는지 |
| WP-08 Root 화면 | 긴급 통제, 강제 조치 기록·전파 서랍, 신청·서버·사람 화면에 끼우는 강제 조치 조각 | `P/root.py`(신규), `T/root.html`(신규), `T/root_actions.html`(신규), `T/_root_panel.html`(신규), `P/__init__.py` | WP-01, WP-07 | Opus | QA-E2E-11-001~004, QA-E2E-12-002·003, QA-E2E-13-001, QA-S-root-001, QA-S-root_actions-001 |
| WP-09 사람·단말·설정 화면 | 사람 서랍·전체 차단, 운영자 역할 선택·Root 지정, 시작하기 알림 양식·승인자 판정, 단말 이름 | `P/people.py`, `T/people.html`, `P/endpoints_admin.py`, `T/endpoints.html`, `T/admin.html`, `P/setup.py`, `T/setup.html`, `C/setup_state.py`, `C/signup.py`, `T/signup_requests.html` | WP-01, WP-07, WP-08 | Sonnet | QA-S-people-001~003, QA-E2E-12-001(`S-people.lockout`), QA-S-admin-001·002, QA-S-setup-001·002 |
| WP-10 대시보드·기록 화면 | 처리할 일 카드 문장화·중복 제거, 호출 기록 기본 보기·차단 단추·되돌리기, 경보 심각도 표시, 정책 모드 확인 창, 차트 규칙 | `P/dashboard.py`, `T/dashboard.html`, `T/ledger.html`, `T/alerts.html`, `T/policy.html`, `C/alert_view.py`, `P/reports.py`, `T/usage.html`, `T/_usage_tables.html`, `T/audit_report.html`, `T/audit_macros.html`, `P/builtins.py`, `T/builtin_tools.html` | WP-01 | Sonnet | QA-E2E-07-002(호출 기록 행), QA-E2E-08-002(`S05.block`), QA-S05-001, QA-S-policy-001 |
| WP-11 CLI 정비 | 명령 계층·별칭, 도움말, 오류 두 줄, `--json`, 비대화형, 종료 코드, 터미널 화면 4번째 탭, 문서 | `src/mint_litellm/endpoint/kit/mint_kit.py`, `docs/CLI.md`(PC `mint` 절 추가), `docs/product/references/cli/*` | WP-06 | Sonnet(화면·도움말·오류). 설치·갱신·서명 경로는 건드리지 않음 | QA-T7-001·002, QA-T8-001, QA-T9-001, QA-E2E-09-009, QA-CLI-001(옛 명령 7개가 별칭으로 같은 결과), QA-CLI-002(종료 코드 표) |

끼우기 규칙: WP-02와 WP-09는 자기 템플릿에 `{% include "_root_panel.html" ignore missing %}` 한 줄만 넣고 내용은 WP-08이 소유합니다.

실행 순서:
1. WP-00 → WP-01
2. WP-02, WP-10 (E2E-01~07의 관리자 쪽)
3. WP-04 → WP-03, WP-05 (E2E-08~10)
4. WP-07 → WP-06 → WP-08 → WP-09 (E2E-11~13)
5. WP-11
6. 마지막에 E2E-01~13 연속 시험(QA-E2E-ALL-001, 저장소 서버 1개로 한 번에)

---

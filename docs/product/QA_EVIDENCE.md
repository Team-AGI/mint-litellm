# 시험 증거 색인

독립 검증자가 실제 화면·터미널·하네스를 조작한 시험만 적는다. 구현자의 단위 시험은 여기 적지 않는다.

| 시험 ID | 시나리오·화면 동작 | 검증자(모델) | 방법 | 결과 | 기준 커밋 | 증거 묶음 |
|---|---|---|---|---|---|---|

- 시험 ID: `QA-<시나리오 또는 화면 ID>-<nnn>`(예: `QA-E2E-07-001`)
- 결과: 통과 / 실패(버그 ID) / 막힘(이유)
- 증거 묶음: 화면 캡처·네트워크·콘솔 오류·터미널 기록을 모은 묶음 이름. 원본은 저장소 밖에 둔다(D-005).
| QA-E2E-01-001 | 직원 GitHub 신청 | GPT-6.2 Sol | Chromium 390px 입력·제출 | 통과 | f8e4dd4 | sol-qa-1126/evidence/e2e/ |
| QA-E2E-02-001 | 관리자 신청 목록 | GPT-6.2 Sol | Chromium 1440px 목록에서 상세 열기 | 통과 | f8e4dd4 | sol-qa-1126/evidence/e2e/ |
| QA-E2E-03-001 | 검사·한 번 승인 | GPT-6.2 Sol | SBOM·SAST·SCA 검토, 버튼, 원장 | 통과 | f8e4dd4 | sol-qa-1126/evidence/e2e/ |
| QA-E2E-04-001 | 관리형 Linux PC 자동 등록·실행 | GPT-6.2 Sol | SSH 기기 목록과 Codex 실제 응답 | 통과 | f8e4dd4 | sol-qa-1126/evidence/terminal/ |
| QA-E2E-05-001 | 직원 카탈로그·PC 수신 | GPT-6.2 Sol | 직원 화면과 적용 상태 시간 대조 | 관리형 통과, 조기 승인 표시 결함 | f8e4dd4 | sol-qa-1126/evidence/e2e/ |
| QA-E2E-05-002 | 사용자 수준 자동 등록 | GPT-6.2 Sol | 격리 키트 설치와 승인 후 보고 | 실패, 재설치 필요 | f8e4dd4 | sol-qa-1126/evidence/client/ |
| QA-E2E-06-001 | Claude Code 연결·목록 | GPT-6.2 Sol | 1회용 키트·격리 홈·Claude 초기화 | 막힘, Python 판본 불일치 | f8e4dd4 | sol-qa-1126/evidence/client-reinstall/ |
| QA-E2E-06-002 | Linux PC Codex 대체 도구 목록 | GPT-6.2 Sol | Codex App Server에서 MCP 목록 읽기 | 로컬 stdio 도구 3개 | f8e4dd4 | sol-qa-1126/evidence/terminal/ |
| QA-E2E-07-001 | 실제 시간 도구 호출 | GPT-6.2 Sol | Codex exec JSON과 TUI | 대체 통과, 실제 시간 응답 | f8e4dd4 | sol-qa-1126/evidence/terminal/ |
| QA-E2E-08-001 | 같은 대화의 도구 차단 | GPT-6.2 Sol | 관리자 도구 차단, 열린 Codex 재호출 | 대체 통과, MINT-DENIED | f8e4dd4 | sol-qa-1126/evidence/controls/ |
| QA-E2E-08-002 | 차단하지 않은 변환 도구 | GPT-6.2 Sol | Codex TUI 판정, App Server 정상 인자 호출 | 정책 허용 및 실제 변환 응답 | f8e4dd4 | sol-qa-1126/evidence/focused/ |
| QA-E2E-09-001 | 직원 권한 요청 | GPT-6.2 Sol | 직원 호출·도구 상세·요청 화면 | 실패, 작성 경로 없음 | f8e4dd4 | sol-qa-1126/evidence/controls/ |
| QA-E2E-10-001 | 관리자 해제 후 정상 사용 | GPT-6.2 Sol | 해제 뒤 같은 열린 Codex 대화 | 대체 통과, 즉시 실제 응답 | f8e4dd4 | sol-qa-1126/evidence/terminal/codex-tui-policy-first/ |
| QA-E2E-11-001 | root 서버 중지 | GPT-6.2 Sol | Confirm, POST, 화면·원장 | 통과 | f8e4dd4 | sol-qa-1126/evidence/controls/ |
| QA-E2E-12-001 | 열린 세션의 호출 권한 | GPT-6.2 Sol | 중지 전후 같은 Codex 대화 | 대체 통과, MINT-SERVER-SUSPENDED | f8e4dd4 | sol-qa-1126/evidence/terminal/codex-tui-policy-first/ |
| QA-E2E-13-001 | 신규 Codex 세션 | GPT-6.2 Sol | 새 대화 도구 요청 및 이용 종료 후 목록 | 신규 호출 판정 수집 막힘, 이용 종료 후 목록 제거 확인 | f8e4dd4 | sol-qa-1126/evidence/terminal/codex-tui-policy-first/ |
| QA-S03-001 | 재검사 중과 완료 후의 결정 | GPT-6.2 Sol | 관리자 재검사·거부·최신 화면에서 재시도 | 검사 중 강제 결정 없음, 최신 완료 상태 거부 성공 | f8e4dd4 | sol-qa-1126/evidence/admin-intake/ |
| QA-S03-002 | 적용 단계와 도구 집계 | GPT-6.2 Sol | 첫 응답 후 관리자 상세 재열기 | 단계 통과, 도구별 호출·차단 수 실패 | f8e4dd4 | sol-qa-1126/evidence/matrix-extra/ |
| QA-S05-001 | 원장 도구 차단·접근 통제 해제 | GPT-6.2 Sol | QA 버튼 클릭, 303·낡은 양식 409 | 화면 동작과 상태 유지 확인 | f8e4dd4 | sol-qa-1126/evidence/ledger-controls/ |
| QA-S08-001 | 관리자·직원 30일 사용량 | GPT-6.2 Sol | 1440·390px에서 선택 후 새로고침 | 기간 유지, 비용 누락 | f8e4dd4 | sol-qa-1126/evidence/matrix/ |
| QA-S13-001 | 중복 GitHub 신청 | GPT-6.2 Sol | 동일 저장소·판본·이름 제출 | 실패, 409 및 기존 신청 링크 없음 | f8e4dd4 | sol-qa-1126/evidence/matrix/ |
| QA-S01-001 | 역할별 LiteLLM 인계·로그아웃 | GPT-6.2 Sol | 두 세션 인계, 버튼, 양쪽 재접속 | 통과 | f8e4dd4 | sol-qa-1126/evidence/sessions/ |
| QA-ROLE-001 | 직원의 관리자 경로·root 404 | GPT-6.2 Sol | Chromium 쿠키별 URL 접근 | 직원 관리자 자료 미노출, root 404 확인 | f8e4dd4 | sol-qa-1126/evidence/matrix/ |
| QA-T1-001 | mint TUI 입력·종료 | GPT-6.2 Sol | Linux PC SSH PTY, pexpect·pyte | 화면 조작 가능, Ctrl+C 트레이스백·종료 표기 불일치 | f8e4dd4 | sol-qa-1126/evidence/terminal/ |
| QA-T3-001 | CLI 신청·웹 철회 | GPT-6.2 Sol | Linux PC mint add, 직원 390px 철회 | 통과 | f8e4dd4 | sol-qa-1126/evidence/matrix-extra/ |
| QA-APP-001 | 시험 앱 발급과 자격 회수 | GPT-6.2 Sol | CLI 발급·환경·웹 회수·PC 키 삭제 | 통과, 실제 모델 응답 미시험 | f8e4dd4 | sol-qa-1126/evidence/app/ |
| QA-CLEANUP-001 | 시험 이용 관계와 단말 정리 | GPT-6.2 Sol | UI, 조회 SQL, Linux PC 승인 서버·Codex 목록 | 종료·회수·제거 확인 | f8e4dd4 | sol-qa-1126/evidence/cleanup/ |
| QA-E2E-01-101 | 직원 GitHub 신청과 중복 재제출 | GPT-6.2 Sol | Chromium 390px 입력·미리보기·제출, 같은 저장소 재제출 | 통과, 중복은 기존 상세로 이동 | 581b15f2 | sol-qa-1126b/evidence/e2e/ |
| QA-E2E-02-101 | 관리자 신청 목록에서 상세 | GPT-6.2 Sol | Chromium 1440px 행 클릭 | 통과 | 581b15f2 | sol-qa-1126b/evidence/e2e/ |
| QA-E2E-03-101 | 검사·한 번 승인(로컬·원격) | GPT-6.2 Sol | 검사 심사·승인 단추·결정 기록 | 통과, 로컬 9/9·원격 8/8 | 581b15f2 | sol-qa-1126b/evidence/e2e/ |
| QA-E2E-04-101 | 관리형 Linux PC 자동 수신·실행 | GPT-6.2 Sol | pj1 CLI와 관리형 stdio 실행기 | 통과 | 581b15f2 | sol-qa-1126b/evidence/claude/ |
| QA-E2E-05-101 | 사용자 수준 승인 자동 반영 | GPT-6.2 Sol | 격리 WSL 설치→승인→보고 | 통과, 재설치 불필요(QA-BUG-002 수정 확인) | 581b15f2 | sol-qa-1126b/evidence/extra/ |
| QA-E2E-06-101 | Claude Code 도구 목록(로컬·원격) | GPT-6.2 Sol | Claude Code settings·mcp-config·strict, SSH stdio와 HTTP MCP | 통과, 로컬 3·원격 3 | 581b15f2 | sol-qa-1126b/evidence/claude/ |
| QA-E2E-07-101 | Claude Code 실제 호출 | GPT-6.2 Sol | 로컬 시간 도구·원격 문서 검색 tool_result | 통과 | 581b15f2 | sol-qa-1126b/evidence/claude/ |
| QA-E2E-08-101 | 같은 세션 도구 차단 | GPT-6.2 Sol | 관리자 도구 차단 뒤 열린 Claude 재호출 | 통과, MINT-DENIED와 해결 링크 | 581b15f2 | sol-qa-1126b/evidence/claude/ |
| QA-E2E-09-101 | 로컬 권한 요청→승인→같은 세션 사용 | GPT-6.2 Sol | 직원 거부 행 요청, 승인 센터 차단 해제, 같은 session_id 재호출 | 통과 | 581b15f2 | sol-qa-1126b/evidence/controls/ |
| QA-E2E-09-102 | 원격 권한 요청→승인→같은 세션 사용 | GPT-6.2 Sol | 같은 흐름, LiteLLM HTTP MCP | 통과 | 581b15f2 | sol-qa-1126b/evidence/controls/ |
| QA-E2E-10-101 | 해제 뒤 재시작 없이 사용 | GPT-6.2 Sol | 브라우저·Claude 재시작 없이 재호출, 직원 요청 목록 | 통과 | 581b15f2 | sol-qa-1126b/evidence/controls/ |
| QA-E2E-11-101 | Root 서버 중지·재개·전역 정지·동결 | GPT-6.2 Sol | Root 조각·긴급 통제 제출, 동결 중 승인 시도 | 통과, 동결 중 승인 409 | 581b15f2 | sol-qa-1126b/evidence/controls/ |
| QA-E2E-12-101 | 열린 세션 거부(개별 중지·전역 local·all) | GPT-6.2 Sol | 두 하네스 열린 세션 | 통과, 원격 개별 중지 안내는 QA-BUG-103 | 581b15f2 | sol-qa-1126b/evidence/claude/ |
| QA-E2E-13-101 | 재시작 뒤 유지·해제 뒤 복귀 | GPT-6.2 Sol | 새 세션과 해제 뒤 재호출 | 부분 통과, 기존 보호 서버 복귀 미시험(활성 승인 없음) | 581b15f2 | sol-qa-1126b/evidence/claude/ |
| QA-ROOT-101 | 전역 정지 local | GPT-6.2 Sol | 두 하네스 열린·새 세션, 해제, 전파 다시 확인 | 통과, 23.64초 이내 해제 | 581b15f2 | sol-qa-1126b/evidence/controls/ |
| QA-ROOT-102 | 전역 정지 all | GPT-6.2 Sol | 같은 흐름 | 통과, 16.76초 이내 해제 | 581b15f2 | sol-qa-1126b/evidence/controls/ |
| QA-ROOT-103 | 동결 중 새 승인 억제 | GPT-6.2 Sol | 새 신청 승인 제출 | 통과, 409·해제 뒤 303 | 581b15f2 | sol-qa-1126b/evidence/extra/ |
| QA-ROOT-104 | 사람 전체 차단·해제 | GPT-6.2 Sol | 키 없는 일반 사용자, 직원 세션 | 통과(PC 키 해제는 대상 없음) | 581b15f2 | sol-qa-1126b/evidence/actions/ |
| QA-REG-106 | 검사 중 Root 강제 반려 | GPT-6.2 Sol | 검사 중 제출·검사 뒤 제출 | 실패(QA-BUG-006 재발), 검사 뒤 303 | 581b15f2 | sol-qa-1126b/evidence/controls/ |
| QA-TUI-101 | PC 터미널 시작·탭·Ctrl+C | GPT-6.2 Sol | pj1 PTY 120×34 | 계약 수신 전 예외(QA-BUG-101), 수신 뒤 4탭·Ctrl+C 통과 | 581b15f2 | sol-qa-1126b/evidence/terminal/ |
| QA-CLI-102 | PC 권한 요청과 취소 | GPT-6.2 Sol | pj1 JSON과 웹 대조 | 통과, 사유 분류 결함(QA-BUG-104) | 581b15f2 | sol-qa-1126b/evidence/terminal/ |
| QA-SCREEN-101 | 시트의 IMPLEMENTED 화면 동작 62개 | GPT-6.2 Sol | 실제 브라우저 클릭·제출 | 통과 23·부분 10·실패 1·미시험 28 | 581b15f2 | sol-qa-1126b/evidence/SCREEN_ACTION_RESULTS.md |
| QA-CLEANUP-101 | 시험 자료·정지 원복 | GPT-6.2 Sol | UI·조회 SQL·pj1 CLI | 원복 확인 | 581b15f2 | sol-qa-1126b/evidence/cleanup/ |

## 결함 (QA-BASE-01 기준선)

| 버그 ID | 심각도 | 내용 | 기능 | 상태 |
|---|---|---|---|---|
| QA-BUG-001 | 높음 | 직원이 차단된 도구의 권한을 요청할 수 없음 | FM-19 FM-60 FM-64 | 수정 확인(QA-REG-01) |
| QA-BUG-002 | 높음 | 사용자 수준 설치는 승인된 로컬 MCP를 자동 등록하지 않음 | FM-10 FM-42 FM-50 | 수정 확인(QA-REG-01) |
| QA-BUG-003 | 높음 | 검사 통과한 GitHub 묶음이 단말의 Python 판본 차이로 시작 실패 | FM-28 FM-49 FM-50 FM-53 | 부분 재발(QA-REG-01) → 안내 경로 수정 #400(재검증 대기) |
| QA-BUG-004 | 중간 | 직원 카탈로그가 도구 발견 전에 사용 가능한 것처럼 표시 | FM-08 FM-42 | 수정 확인(QA-REG-01) |
| QA-BUG-005 | 중간 | 같은 GitHub 신청이 기존 상세 대신 409로 끝남 | FM-07 FM-37 | 수정 확인(QA-REG-01) |
| QA-BUG-006 | 높음 | root가 검사 중인 신청을 강제로 결정할 경로가 없음 | FM-06 FM-56 | 재발(QA-REG-01, 검사 중 400) → #398 수정(재검증 대기) |
| QA-BUG-007 | 중간 | 관리자와 직원의 사용량에 비용이 없음 | FM-16 | 수정(재검증 대기): LiteLLM 일별 지출로 비용·0·미집계 구분 |
| QA-BUG-008 | 중간 | 계약이 있는 신청의 도구별 호출·차단 수를 볼 수 없음 | FM-08 FM-16 | 수정 확인(QA-REG-01) |
| QA-BUG-009 | 중간 | 이용 종료 후에도 PC 신청 목록은 「승인」으로 표시 | FM-27 FM-45 FM-63 | 수정 확인(QA-REG-01) |
| QA-BUG-010 | 낮음 | mint TUI에서 Ctrl+C를 누르면 트레이스백이 뜸 | FM-04 FM-63 | 수정 확인(QA-REG-01) |
| QA-BUG-011 | 중간 | 최상위 CLI 도움말에 직원 명령이 빠지고 인자 오류가 영어로 나옴 | FM-27 FM-63 | 수정 확인(QA-REG-01) |
| QA-BUG-101 | 높음 | 승인 직후 PC가 계약을 받기 전 CLI 조회·터미널이 예외로 종료 | FM-27 FM-63 | 수정 #396(재검증 대기) |
| QA-BUG-103 | 중간 | 중지된 원격 MCP 거부가 해결 안내 없이 영어로 반환 | FM-55 FM-56 | 수정 #400·D-014(재검증 대기) |
| QA-BUG-104 | 중간 | PC에서 차단된 도구의 권한을 요청하면 승인 없음으로 분류 | FM-60 FM-63 | 수정 #400(재검증 대기) |

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

## 결함 (QA-BASE-01 기준선)

| 버그 ID | 심각도 | 내용 | 기능 | 상태 |
|---|---|---|---|---|
| QA-BUG-001 | 높음 | 직원이 차단된 도구의 권한을 요청할 수 없음 | FM-19 FM-60 FM-64 | 서비스 #380, 화면 작업 중 |
| QA-BUG-002 | 높음 | 사용자 수준 설치는 승인된 로컬 MCP를 자동 등록하지 않음 | FM-10 FM-42 FM-50 | 열림 |
| QA-BUG-003 | 높음 | 검사 통과한 GitHub 묶음이 단말의 Python 판본 차이로 시작 실패 | FM-28 FM-49 FM-50 FM-53 | 안내 수정(재검증 대기), 여러 판본 묶음은 CP-007 |
| QA-BUG-004 | 중간 | 직원 카탈로그가 도구 발견 전에 사용 가능한 것처럼 표시 | FM-08 FM-42 | 열림 |
| QA-BUG-005 | 중간 | 같은 GitHub 신청이 기존 상세 대신 409로 끝남 | FM-07 FM-37 | 열림 |
| QA-BUG-006 | 높음 | root가 검사 중인 신청을 강제로 결정할 경로가 없음 | FM-06 FM-56 | 강제 반려 WP-07 작업 중 |
| QA-BUG-007 | 중간 | 관리자와 직원의 사용량에 비용이 없음 | FM-16 | 열림 |
| QA-BUG-008 | 중간 | 계약이 있는 신청의 도구별 호출·차단 수를 볼 수 없음 | FM-08 FM-16 | 열림 |
| QA-BUG-009 | 중간 | 이용 종료 후에도 PC 신청 목록은 「승인」으로 표시 | FM-27 FM-45 FM-63 | 열림 |
| QA-BUG-010 | 낮음 | mint TUI에서 Ctrl+C를 누르면 트레이스백이 뜸 | FM-04 FM-63 | 수정(재검증 대기) |
| QA-BUG-011 | 중간 | 최상위 CLI 도움말에 직원 명령이 빠지고 인자 오류가 영어로 나옴 | FM-27 FM-63 | 수정 #378·#381(재검증 대기) |

# 제품 기준 문서

모든 작업자(사람·에이전트)가 같은 기준으로 일하기 위한 문서다. 작업을 시작하기 전에 이 폴더의 최신 내용을 읽는다.

| 파일 | 역할 | 관리 |
|---|---|---|
| PRODUCT_BRIEF.md | 제품 목표, 요구사항(REQ) 목록, 지킬 설계 결정 | 사람 |
| FEATURE_REGISTER.csv | 기능(FM) 목록과 상태 | 사람 |
| USER_SCENARIOS.md | 역할별 시작 상태부터 목적 달성까지의 시나리오(U·E2E) | 사람 |
| SCREEN_ACTION_MATRIX.csv | 화면의 모든 버튼·양식과 그 결과 | 사람 |
| POLICY_CONTROL_MATRIX.csv | 보안 정책과 실제 통제 지점, 거부 안내, 해결 경로 | 사람 |
| TRACEABILITY_MATRIX.csv | REQ→FM→시나리오→화면 동작→API→정책→시험→증거 | `scripts/product/check.py`가 생성 |
| DESIGN_SYSTEM.md | 웹 콘솔·PC 터미널 화면의 디자인 규칙 | 사람 |
| REFERENCE_RESEARCH.md | 웹·CLI 레퍼런스 조사와 출처 | 사람 |
| DECISION_LOG.md | 설계 결정(D-nnn) | 사람 |
| CHANGE_PROPOSALS.md | 변경 제안(CP-nnn). 기존 기능 삭제·축소는 여기서 승인된 뒤에만 | 사람 |
| QA_EVIDENCE.md | 시험 증거 색인(시험 ID별 방법·결과·커밋) | 사람 |
| generated/ | 코드에서 뽑은 라우트·화면 동작 목록 | `scripts/product/inventory.py`가 생성 |

## 상태 단계(lifecycle)

`DISCOVERED → SPECIFIED → IMPLEMENTED → BACKEND_VERIFIED → GUI_VERIFIED → POLICY_VERIFIED → REGRESSION_VERIFIED → RELEASE_READY`

- `BLOCKED`는 막힌 이유를 `open_issues`에 적는다.
- 단계는 증거가 있을 때만 올린다. 코드, 단위 시험, 문서, CLI 성공만으로는 `GUI_VERIFIED`가 아니다.
- `GUI_VERIFIED` 이상은 구현자가 아닌 독립 검증자(QA)가 실제 화면을 조작한 증거가 있어야 한다.
- 이전 실측(curl·터미널·구현자 확인)은 `BACKEND_VERIFIED`까지만 인정한다.

## FEATURE_REGISTER.csv 열

`feature_id,name,description,roles,priority,modules,screens,apis,policies,owner_agent,lifecycle,gui_status,evidence,open_issues,scenarios,reqs,prs`

- `priority`: P0(핵심 흐름), P1(운영 필수), P2(편의)
- `roles`: `staff`(직원·일반 사용자), `approver`, `admin`(일반·보안 관리자), `root`(Root Admin), `system`
- 여러 값은 공백으로 나눈다(예: `FM-04 FM-05`).

## SCREEN_ACTION_MATRIX.csv 열

`screen_id,screen,component_id,action_id,label,roles,feature_id,preconditions,action,api,policy_id,loading_state,success_state,failure_state,audit_event,test_id,status`

- `action_id`: `<screen_id>.<짧은 영문>`(예: `S03.approve`)
- `api`: `POST /intakes/{intake_id}/decision`처럼 메서드와 라우트
- `status`: lifecycle과 같은 값. 연결된 기능이 없는 버튼은 `feature_id`를 `UNMAPPED`로 두고 검사에서 실패시킨다.

## 운영 규칙

1. 작업 전에 이 폴더를 읽는다. 구현은 등록된 FM과 시나리오를 기준으로 한다.
2. 새 기능은 FEATURE_REGISTER부터 고친다. 화면을 바꾸면 SCREEN_ACTION_MATRIX도 같은 커밋에서 고친다.
3. 기존 기능을 지우거나 줄이려면 CHANGE_PROPOSALS에 제안하고 승인받는다.
4. 시험 결과는 QA_EVIDENCE에 시험 ID로 적고, 시트의 상태를 증거에 맞춰 고친다.
5. 저장소에는 IP 주소, 자격 증명, 키를 적지 않는다. 시험 장비는 역할 이름(기기, Linux PC, Windows PC)으로 적는다.
6. `python scripts/product/check.py`가 통과해야 병합한다.

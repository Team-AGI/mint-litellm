# Changelog

이 프로젝트는 [Semantic Versioning](https://semver.org/lang/ko/)을 따릅니다.

## [Unreleased]

- `intake recheck --url`이 플러그인이 기록한 관측 해시(레지스트리 값의 정규 해시)와 입력 주소를 같은 규칙으로 대조한다. 이전에는 올바른 주소도 해시 불일치로 거부돼 배포 드리프트를 재승인할 수 없었다.
- 정의 상한(도구 500개·응답 2MB·중첩 20·10초)을 넘어 판별 불가가 된 서버의 `intake except`는 「정의 상한 초과」로 원인을 밝히며 거부한다(예외로도 승인하지 않는 것은 그대로).
- LiteLLM 제출의 주소가 사설·루프백 등 거부 대상 리터럴 IP이면 운영자 입력을 기다리지 않고 첫 조회에서 `url_guard`(`IP_FORBIDDEN`)로 자동 거절하고 LiteLLM 제출도 거절한다(마이그레이션 `016_intake_address_reject`: 이 거절만 필수 입력 없이 `decided`가 된다).
- 계약 드리프트(도구 변경·추가, 배포 값 변경)를 처음 기록하면 서버를 승인한 신청의 재검사를 자동으로 등록한다. 재검사는 승인된 신청(`decided`)을 받아 후보 계약과 그 후보에 결속된 증거를 저장하고(배포 드리프트면 배포 후보까지), 운영자는 `contract reapprove`로 재승인한다. `intake recheck`와 콘솔 재검사 버튼도 승인된 신청을 받고, LiteLLM이 서버 URL을 돌려주지 않으면 `--url`(콘솔은 입력칸)으로 새 주소를 받는다(관측된 URL 해시와 다르면 거부). 서버 자격 흐름 드리프트도 승인된 값 그대로 배포 후보를 두고 OAuth 검사를 다시 한다. 계약 드리프트 경보는 `alert_opened` 사건을 남긴다.
- 모델 요청과 패스스루 경로에 담긴 공급자 쪽 MCP(게이트웨이 주소가 아닌 `tools[]`의 `type: "mcp"`, `mcp_servers`)를 `pre_call` 가드레일 모드에서 `MINT-EXTERNAL-MCP-FORBIDDEN`(403)으로 막고 판정 사건을 남긴다. MINT 가드레일의 모드에 `pre_call`이 필요해졌으므로, 기존 설정은 `mode`를 `[pre_call, pre_mcp_call, post_mcp_call]`로 고쳐야 자가 점검을 통과한다`./mint.sh up`·`upgrade`가 `init --fix-config`로 `config/litellm.config.yaml`의 `mode`에 빠진 모드를 더하고(사본 보관) 고칠 수 없으면 멈춘다. 검사는 요청 본문 전체의 구조화 객체(`extra_body`·`input`·`session`)와 문자열 `extra_body`를 보며(메시지 텍스트·`metadata` 문자열은 풀지 않고, 문자열 `tools`·`mcp_servers`·`session`은 지원하지 않는 형식으로 막는다), 게이트웨이 예외는 최상위 `tools[]`의 `litellm_proxy` 형식만이고 패스스루에서는 예외가 없다. 실시간 경로는 `MINT_ALLOW_REALTIME=true`가 아니면 `MINT-REALTIME-FORBIDDEN`으로 막고, `enable_openai_websocket_passthrough`가 켜진 설정은 이 값 없이는 자가 점검이 실패한다.
- 운영자 삭제(만료 설정)와 역할 강등을 부정 상태로 내보낸다(마이그레이션 `014_operator_negative`). DB를 되돌려 권한을 잃었던 운영자가 되살아나면 되돌림 판정이 잡고, `restore attest`가 삭제·강등 상태로 되돌린다. 판정이 읽는 운영자 상태에는 토큰 해시가 없다.
- 승인된 배포 계약이 `oauth2`인 서버는 정기 관측에서 LiteLLM 서버 설정의 `oauth2_flow`를 읽는다. 서버 자격 흐름이 아니거나 읽지 못하면 배포 드리프트로 호출을 막고 재승인을 요청한다.
- 콘솔 `--host *`는 이 호스트가 가진 모든 주소(IPv4·IPv6)에 연다. 배포 compose의 콘솔은 이를 써서 IPv4만 있는 컨테이너에서도 닿는다.
- 작업 실행기를 관측 주기를 줄여 다시 띄우면 이미 잡혀 있던 먼 다음 실행 시각이 남아 `contract_observe`를 비롯한 주기 작업이 새 주기로 등록되지 않던 결함을 고쳤다. 계약 관측은 LiteLLM이 서버 식별자만으로는 접속 대상을 알지 못해 승인된 배포 값(URL·전송·인증)을 함께 보내도록 바꿨다.
- 제어 평면 키의 토큰을 도구 목록 면제 키로 저장한다. `init`이 `MINT_LITELLM_KEY`로 자동 저장하고 `settings control-key`가 바꾸거나 해제한다. 저장되지 않아 도구를 고정하지 못하면 경보 `sync_divergence`(`control_key_not_set`)가 열린다.
- 배포 compose의 작업 실행기에 `MINT_OPA_URL`과 `MINT_OBSERVE_SECONDS`를 넘기고, LiteLLM에도 `MINT_OBSERVE_SECONDS`를 넘긴다.
- 배포 이미지를 비루트 사용자(65532)로 실행한다. 이전 판본이 루트로 만든 볼륨은 `./mint.sh up`·`upgrade`가 소유자를 맞춘다. 운영자 도구(`control`)만 호스트 비밀 디렉터리에 쓰기 위해 루트로 실행한다.

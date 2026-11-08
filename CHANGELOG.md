# Changelog

이 프로젝트는 [Semantic Versioning](https://semver.org/lang/ko/)을 따릅니다.

## [Unreleased]

- 작업 실행기를 관측 주기를 줄여 다시 띄우면 이미 잡혀 있던 먼 다음 실행 시각이 남아 `contract_observe`를 비롯한 주기 작업이 새 주기로 등록되지 않던 결함을 고쳤다. 계약 관측은 LiteLLM이 서버 식별자만으로는 접속 대상을 알지 못해 승인된 배포 값(URL·전송·인증)을 함께 보내도록 바꿨다.
- 제어 평면 키의 토큰을 도구 목록 면제 키로 저장한다. `init`이 `MINT_LITELLM_KEY`로 자동 저장하고 `settings control-key`가 바꾸거나 해제한다. 저장되지 않아 도구를 고정하지 못하면 경보 `sync_divergence`(`control_key_not_set`)가 열린다.
- 배포 compose의 작업 실행기에 `MINT_OPA_URL`과 `MINT_OBSERVE_SECONDS`를 넘기고, LiteLLM에도 `MINT_OBSERVE_SECONDS`를 넘긴다.
- 배포 이미지를 비루트 사용자(65532)로 실행한다. 이전 판본이 루트로 만든 볼륨은 `./mint.sh up`·`upgrade`가 소유자를 맞춘다. 운영자 도구(`control`)만 호스트 비밀 디렉터리에 쓰기 위해 루트로 실행한다.

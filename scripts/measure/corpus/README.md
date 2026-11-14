# 측정 코퍼스 형식

한 줄에 한 사례인 JSONL이다. 이 디렉터리의 `seed.jsonl`은 형식을 보이는 합성 표본이며 정확도 결론에 쓰지 않는다.

| 필드 | 뜻 |
|---|---|
| `id` | 고유 식별자 |
| `source` | `real`(실제 업무 표본) / `public`(공개 사례) / `synthetic`(합성) |
| `split` | `tune`(조정용) / `heldout`(최종 평가용). 최종 수치는 `heldout`만으로 낸다 |
| `group` | 템플릿·출처·세션 단위. 독립 표본 수는 사례 수가 아니라 `group` 수로 센다 |
| `surface` | `text` / `structured`(구조화 결과 전용) |
| `state` | `principal`, `team`, `org`, `approval`(none/call/period/expired/revoked), `contract`, `time`, `policy_version` |
| `request` | `server`, `tool`, `args` |
| `result` | 출력 사례의 도구 결과(없으면 생략) |
| `mode` | `enforce` / `observe` |
| `expect` | 기대 동작 `allow` / `deny` / `hold` / `mask` / `observe` |
| `reviewer` | 라벨 검토 기록(`labeler`, `second`, `agreed`). 일치한 판정도 무작위로 재검토한다 |

관측 파일(`runner`가 쓰는 JSONL과 별개로 채점기가 읽는 입력)은 한 줄에
`id`, `evaluated`(평가한 판정), `enforced`(실제 집행한 동작), `skipped`, `error`를 둔다.
평가 오탐과 실제 업무 방해는 `evaluated`와 `enforced`를 따로 채점해 구분한다.

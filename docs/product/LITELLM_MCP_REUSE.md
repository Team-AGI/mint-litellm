# LiteLLM 자체 MCP 기능 재사용 조사 (REQ-24 · D-004)

조사 판본: LiteLLM **1.106.6**(기기의 실행 컨테이너 패키지 소스를 읽기 전용으로 확인). 문서는 docs.litellm.ai의 `mcp_server_submissions`, `mcp_control`, `mcp` 쪽이다. 쓰기 API는 호출하지 않았고 실제 요청으로 재현한 항목은 없다. 코드만 읽은 항목은 「코드 확인」, 재현이 필요한 항목은 「미재현」으로 적는다.
경로 약칭: `LL/` = `litellm/proxy/_experimental/mcp_server/`, `ME` = `litellm/proxy/management_endpoints/mcp_management_endpoints.py`, `AUTH` = `LL/auth/user_api_key_auth_mcp.py`, `MINT/` = `src/mint_litellm/control/`.

## 한눈에 보는 결론

| 영역 | 결론 |
|---|---|
| 서버 등록·수정·승인·거절 | **재사용 중**. 그대로 유지 |
| 제출(submissions) | **재사용 중**. 직원 제출 → MINT 신청 변환, 승인 한 번 뒤 LiteLLM 승인 |
| 키·팀 서버 권한 | **재사용 중**(`mcp_servers`). 서버 단위 접근선만 LiteLLM에 맡긴다 |
| 도구 단위 통제 | **MINT 자체 유지**. LiteLLM 도구 권한은 허용 목록뿐이라 「새 도구도 기본 통과」(결정 4)를 표현하지 못한다 |
| 서버 즉시 중지 | LiteLLM에는 비활성 플래그가 없다. **활성 서버에 대한 `reject`가 즉시 비활성화**(재승인으로 복구)이므로 root 즉시 중지에 보조로 **추가 재사용 권장** |
| 전역 정지(Kill Switch) | LiteLLM에 전역 MCP 정지 설정이 **없다**. MINT 자체(플러그인 판정) 유지 |
| 키 폐기 지연 | 서버 접근은 요청마다 DB 확인이라 즉시. 키·팀·권한 캐시는 기본 60초, 이 기기는 Redis 방송이 있어 보통 즉시이나 보장은 60초 |

## 1. MCP 서버 등록·수정·삭제 API

| 항목 | 내용 |
|---|---|
| 문서 | `GET/POST/PUT /v1/mcp/server`. `store_model_in_db: true` 필요. 모델 기본 전송이 `sse`라 명시하라고 안내. stdio는 `LITELLM_ENABLE_MCP_STDIO=true`일 때만 |
| 1.106.6 | `POST /v1/mcp/server`(`ME` add_mcp_server, PROXY_ADMIN만, 항상 `approval_status=active`), `PUT /v1/mcp/server`(edit_mcp_server, 부분 갱신: 안 보낸 필드는 유지, null은 지움), `GET /v1/mcp/server`·`/{id}`, `DELETE /v1/mcp/server/{id}`(remove_mcp_server). 요청 필드: `server_id, server_name, alias, url, transport, auth_type, credentials, mcp_info, mcp_access_groups, allowed_tools, allow_all_keys, rpm, max_concurrent_requests, timeout, static_headers, env_vars, command/args/env(stdio), oauth2 필드군, source_url` 등(`litellm/proxy/_types.py` NewMCPServerRequest·UpdateMCPServerRequest). **서버 비활성 플래그는 없다.** `disallowed_tools`는 config.yaml 전용이고 API 필드에 없다 |
| 등록 반영 | 서버 목록은 요청 때마다 DB의 카탈로그 개정 번호를 확인해 달라졌으면 다시 읽는다(`LL/catalog.py` `_fresh_snapshot`). 그래서 등록·승인·거절·삭제는 워커·복제본 사이에 TTL 없이 다음 요청부터 반영된다(코드 확인, 미재현) |
| 함정 | 읽기 응답이 `mcp_info` 값을 지운다(이미 겪음, `MINT/litellm_control.py:107` 설명에 표지를 중복 기록). `DELETE`는 키·팀의 서버 권한을 정리하지 않는다(`ME` remove_mcp_server 안 「키·팀에서 지우기는 미구현」 주석). 서버 생성·수정·삭제는 감사 로그를 남기지 않는다(같은 곳 `if is_audit_logging_enabled(): pass`) |
| MINT 사용 | `provision_staff_server` → `POST /v1/mcp/server` (`MINT/litellm_control.py:99-109`, 허용 목록 `litellm_write.py:30-45`); `PUT`은 `allow_all_keys` 끄기와 한도만 (`litellm_write.py:319-327`, 호출 `intake_jobs.py:116,163`, `sync_jobs.py:1148`); 목록·상세 읽기 `litellm_admin.py:110-114`. `DELETE`·`allowed_tools`·`mcp_access_groups`는 쓰지 않는다 |
| 권장 | **재사용(유지)**. `DELETE`는 쓰지 않는 현재 결정이 맞다(삭제해도 키·팀 권한이 남는다). 이용 종료는 아래 4의 `reject`+권한 회수로 한다 |

## 2. 서버 제출(submissions) · 승인 흐름

| 항목 | 내용 |
|---|---|
| 문서 | `POST /v1/mcp/server/register`(팀 키 사용자), `GET /v1/mcp/server/submissions`, `PUT .../{id}/approve`, `PUT .../{id}/reject`(`review_notes`). 상태 `pending_review/active/rejected`. 활성 서버를 거절하면 레지스트리에서 즉시 제거, 거절된 서버 재승인 가능 |
| 1.106.6 | 같음. 추가로 확인: `register`는 PROXY_ADMIN 키를 403으로 거부하고 팀 소속 키가 필요(400), **stdio 제출은 400으로 거부**(`ME` register_mcp_server). 제출 시 `submitted_by/submitted_at`, 승인·거절 시 `reviewed_at/review_notes`(`LiteLLM_MCPServerTable`, `litellm/models/mcp_server.py`). 승인·거절·목록은 PROXY_ADMIN(목록은 조회용 관리자 포함). `approval_status`에 `draft`(관리자 OAuth 임시 행, 목록에서 제외)도 있다. 승인 시 레지스트리에 즉시 적재, 응답의 자격은 가려진다 |
| MINT 사용 | 제출 읽기 `list_submissions` (`litellm_control.py:94-97`) → `submission_poll`이 신청으로 변환(`intake_jobs.py:62`); 승인 `approve_submission` (`litellm_control.py:176`, 호출 `intake_jobs.py:168`); 거절 `reject_submission` (`litellm_control.py:180`, 호출 `intake_jobs.py:130,474`). 승인 직전 `allow_all_keys` 닫기와 재확인(`intake_jobs.py:114-130`) |
| 권장 | **재사용(유지)**. 결정 3(승인 한 번)과 맞다: MINT 승인 한 번 → LiteLLM `approve`. 제약: LiteLLM 제출은 원격(HTTP·SSE)만이라 **로컬 MCP(결정 2)는 이 경로를 쓸 수 없다**(PC 실행기가 맡음, 변경 없음). LiteLLM 제출의 승인 권한은 단일 PROXY_ADMIN이라 MINT의 역할 분리(승인자·직무 분리)는 MINT 안에서만 성립한다(제어 평면 키가 대신 승인) |

## 3. 접근 통제: 서버·도구 권한, 접근 그룹, 허용 도구

| 항목 | 내용 |
|---|---|
| 문서 | key/team/org/end user/agent/user의 `object_permission.mcp_servers`(비면 제한 없음, 단계 교집합, org는 상한). `mcp_access_groups`, `require_key_mcp_access_defined`, `no-mcp-servers`, `mcp_tool_permissions`(서버→도구 목록), 서버 `allowed_tools`(허용)·`disallowed_tools`(차단, config), `pinned_tools`, `allowed_params`, `allow_all_keys`, `mcp_rpm_limit`, 서버 `rpm` |
| 1.106.6 서버 권한 | `AUTH.get_mcp_server_access`(1721~): 키·팀·end user·agent 교집합, org 상한, 사용자 상한(`_apply_user_server_ceiling`). 팀이 목록을 가지면 키는 그 안만(MINT `kit_key_sync.py:170-177` `_within_team`과 일치). `LL`에서 `allow_all_keys`·`mcp_allow_all_keys_respects_mcp_scope`(`general_settings`)·`require_key_mcp_access_defined`(`AUTH` 1811) 확인. 접근 그룹은 `mcp_access_groups`(서버·object_permission 양쪽), `GET /v1/mcp/access_groups`(`ME` 1099) |
| 1.106.6 도구 권한 | `get_allowed_tools_for_server`(`AUTH` 2423~): `mcp_tool_permissions[서버]`는 **허용 목록**. 서버 항목이 없으면 `None`=전부 허용, 항목이 있으면 그 목록만, 키·팀 둘 다 있으면 교집합, 사용자·org·agent는 상한. 와일드카드 `*`(`litellm/constants.py:203` MCP_ALL_TOOLS_WILDCARD)가 현재·미래 도구를 모두 허용. 도구 목록·호출이 같은 함수(`tool_is_granted`)를 거친다. **키·팀의 차단 목록은 없다**: `object_permission.blocked_tools` 컬럼은 있으나 MCP 경로에서 읽는 코드가 없고(`litellm/proxy` 안에서 `_types.py`·`auth_object_prefetch.py`·`/v1/tool/policy`만 참조), `/v1/tool/policy`의 `input_policy=blocked`(키·팀 덮어쓰기 가능)를 집행하는 `tool_policy` 가드레일은 `pre_call/post_call/during_call` 훅이라 `pre_mcp_call` 경로가 아니다(코드 확인; 실제 MCP 호출에서 막히지 않는지는 미재현). 서버 `allowed_tools`는 API로 쓸 수 있으나 모든 호출자에 적용되는 전역 허용 목록이다 |
| MINT 사용 | 키 서버·도구 쓰기 `update_key_permission` (`litellm_write.py:274-288`), 팀 `update_team_permission` (`litellm_write.py:296-310`), 호출 `kit_key_sync.py:136`, `sync_jobs.py:167-168`. 도구는 승인이 도구를 명시했을 때만 맵에 넣고 「모든 도구」·도입 심사 승인은 맵에서 뺀다(`kit_key_sync.py:63-74` `fold_permission`, `open_tools`). `require_key_mcp_access_defined`·`mcp_allow_all_keys_respects_mcp_scope`·`allow_all_keys:false` 설정(`litellm_config.py:40-41,69`; `require_key_mcp_access_defined`는 40행)과 기동 점검(`checks.py:290-315`). `mcp_access_groups`·`mcp_toolsets`·서버 `allowed_tools`·`no-mcp-servers`는 쓰지 않는다 |
| 권장 | **서버 접근선은 재사용(유지)**, **도구 사후 차단은 MINT 자체 유지**. 결정 4(새로 발견된 도구까지 허용하고 관리자가 사후에 막는다)를 LiteLLM 허용 목록으로 구현하려면 막을 때마다 현재 도구를 전부 열거해야 하고 그 뒤 새 도구가 모두 막혀 결정과 어긋난다. 현재처럼 LiteLLM은 서버 단위·「승인이 도구를 명시했을 때만」 도구 목록을 쓰고, 사후 차단·호출별 검토는 플러그인(`pre_mcp_call`)이 DB 상태로 판정한다. 접근 그룹은 MINT의 승인 범위(키·사용자·팀·조직 + 유효 기간)로 이미 표현되고 그룹은 기간·회수 이력이 없어 **쓰지 않는다**. `blocked_tools`·서버 `disallowed_tools`(config 전용)는 **쓸 수 없다**. |

## 4. 서버 비활성화 · 도구 단위 비활성화

| 항목 | 내용 |
|---|---|
| 문서 | 전용 비활성 스위치 없음. 근접 수단: 서버 `rpm: 0`, 키의 `no-mcp-servers`, 활성 서버 거절 시 즉시 제거 |
| 1.106.6 | `PUT .../{id}/reject`가 **이미 활성인 서버**에도 동작하고 활성이었으면 레지스트리를 다시 읽어 즉시 제거한다(`ME` reject_mcp_server_submission, `was_active`). 상태는 `rejected`+`review_notes`, `PUT .../approve`로 복구(`approve`는 거절·대기 모두 허용). 자격·키 권한은 건드리지 않는다. `rpm: 0`은 API가 허용하나(`ge=0`) 집행 코드를 이번에 찾지 못했다(문서만, 미재현). 도구 단위 비활성은 위 3대로 기본 통과를 깨지 않는 방법이 없다 |
| MINT 사용 | `reject_server`는 도입 단계 거절에만 쓴다(`intake_jobs.py:130,474`). MINT의 서버 중지·이용 종료는 MINT DB 상태→플러그인 판정과 키 권한 동기화(`kit_key_sync.py`) 경로이고 LiteLLM 서버 상태는 바꾸지 않는다. `set_server_limits`는 양의 정수만 허용(`litellm_write.py:126-134`) |
| 권장 | **보조 재사용 추가**: root 즉시 비활성화·이용 종료 때 기존 판정 차단과 키 권한 회수에 더해 활성 서버를 `reject`해 LiteLLM 레지스트리에서도 내리고, 재개 때 `approve`한다. 이점: 플러그인이 죽었거나 우회된 경우에도 LiteLLM이 그 서버를 내놓지 않는다(다중 워커·복제본에도 즉시 전파). 주의: `reject`/`approve`는 이미 허용 목록에 있어(`litellm_write.py:40-41`) 허용 변경은 필요 없고, 「이미 활성」/「이미 거절」 400 응답 해석은 `_review`(`litellm_control.py:164-174`)가 처리한다. 필요한 변경은 서버 중지·재개 작업에서 호출을 추가하는 것 하나다(별도 승인 절차 없이 root 강제 조치이므로 결정 3과 충돌 없음). 도구 단위 즉시 정지는 MINT 사후 차단 유지 |

## 5. MCP 호출 가드레일

| 항목 | 내용 |
|---|---|
| 문서(`mcp`) | 가드레일 훅은 해당 페이지에 서술 없음 |
| 1.106.6 | `pre_mcp_call`, `during_mcp_call`, `post_mcp_call` 훅이 있고 MCP 호출을 LLM 형식의 합성 요청으로 변환해 기존 가드레일을 부른다(`LL/mcp_server_manager.py` ~5922~6105, `_convert_mcp_to_llm_format`). `pre_mcp_call`은 인자·헤더 변경·차단 가능. 내장 가드레일 중 MCP용은 `mcp_end_user_permission`(end user의 서버 제한), `mcp_security`(`pre_call`, 미등록 서버 참조 차단), `mcp_jwt_signer`. `tool_permission`(허용/거부 규칙)은 `pre_call/post_call`만이라 직접 MCP 호출에는 적용되지 않는다. 키·팀 `metadata`의 가드레일 제외 설정이 있다(MINT 문서 보장과-한계에 기록됨) |
| MINT 사용 | `MintGuardrail`이 `pre_call`·`pre_mcp_call`을 구독(`src/mint_litellm/plugin/guardrail.py:134`)하고 설정 조각이 세 모드를 심는다(`litellm_config.py:18,53`; 기동 점검 `selfcheck.py:61`). 사후는 `MintOutputGuardrail`(`plugin/output_guardrail.py`) |
| 권장 | **재사용(유지)**. 내장 가드레일로 MINT 판정을 대체할 수 없다(도구 사후 차단·승인 보류·가용성 우선 정책은 MINT 고유). 병행 가드레일이 인자를 수정본 없이 바꾸면 MINT가 차단한다는 기존 한계(보장과-한계.md)는 그대로다 |

## 6. MCP OAuth·자격 증명

| 항목 | 내용 |
|---|---|
| 문서 | `auth_type`: none, api_key, bearer_token, basic, authorization, token, oauth2(`oauth2_flow`: client_credentials/authorization_code), oauth2_token_exchange, oauth2_id_jag, true_passthrough, oauth_delegate, aws_sigv4. 서버별 사용자 변수와 클라이언트 헤더 |
| 1.106.6 | `MCPAuth` 열거(`litellm/types/mcp.py:41-53`) 12종이 문서와 같다. 서버 자격은 저장 시 암호화·응답에서 가림(`_redact_mcp_credentials`). 사용자별 자격 API: `POST/DELETE /v1/mcp/server/{id}/user-credential`, `.../oauth-user-credential`(+`/status`), `GET /v1/mcp/user-credentials`, `.../user-env-vars`(`ME` 2522~3060). OAuth 설정이 바뀌면 사용자별 토큰을 자동 삭제(`edit_mcp_server` 끝). 업스트림 OAuth 토큰·BYOK 캐시·DCR 브리지는 LiteLLM 안에 있다 |
| MINT 사용 | 등록은 `auth_type: none`만(`litellm_control.py:104`). 서버 폐기 때 사용자별 API 키·OAuth 토큰을 하나씩 지운다(`delete_user_credential` `litellm_write.py:341-345`, 호출 `sync_jobs.py:454`, 읽기 `litellm_admin.py:120-125`). 호출자 토큰 전달 서버(true_passthrough·oauth_delegate)는 승인 조건 allow_token_forward로만(`docs/설정.md` 124행) |
| 권장 | **재사용(유지)**. 자격 저장·갱신·삭제는 LiteLLM에 맡기고 MINT는 값을 보관하지 않는다. 인증이 필요한 서버를 직원 신청으로 받는 흐름(현재 `none`만 자동 등록)은 별도 설계가 필요하나 이번 REQ-24 범위 밖이다 |

## 7. MCP 호출 감사·기록

| 항목 | 내용 |
|---|---|
| 문서 | 해당 페이지에 서술 없음 |
| 1.106.6 | 일별 도구 지출 `LiteLLM_DailyToolSpend`/`mcp_namespaced_tool_name` 컬럼(`schema.prisma` 736·859·895행), 도구 정책 조회 `/v1/tool/list`, `/v1/tool/{name}/logs`. 가드레일 평가 기록은 호출 로그에 붙는다(`_record_mcp_guardrail_evaluations`). 관리 작업 감사(`LiteLLM_AuditLogs`)는 `store_audit_logs`가 켜져야 하며 **서버 생성·수정·삭제는 기록하지 않는다**(소스에 미구현 주석 3곳). 이 기기 설정에는 `store_audit_logs`가 없다 |
| MINT 사용 | 판정·호출·관리 작업은 MINT 원장·사건 테이블(MINT DB)에 쓴다. LiteLLM 기록은 읽지 않는다. 설정 조각이 `disable_spend_logs`·`store_prompts_in_spend_logs: false`를 둔다(`litellm_config.py:42,46`) |
| 권장 | **MINT 자체 유지**. LiteLLM은 서버 변경 감사를 남기지 않으므로 서버 등록·승인·거절·중지는 MINT 원장이 유일한 기록이다. LiteLLM 로그를 감사 근거로 삼지 않는다 |

## 8. 전역 정지(Kill Switch)에 가까운 수단

| 항목 | 내용 |
|---|---|
| 문서 | 전역 비활성 스위치 없음(문서도 `rpm: 0`·`no-mcp-servers`를 근접 수단으로만 언급) |
| 1.106.6 | `general_settings`의 `mcp_*` 설정은 `mcp_advertised_versions, mcp_allow_all_keys_respects_mcp_scope, mcp_client_side_auth_header_name, mcp_internal_ip_ranges, mcp_prefer_client_id_metadata_document, mcp_required_fields, mcp_session_token_signing, mcp_trusted_proxy_ranges, mcp_xff_num_trusted_hops`뿐이고 정지 스위치는 없다. 쓸 수 있는 조각: 키·팀 차단(`/key/block`, `/team/block`), 키 삭제, 서버 `reject`(4), 사용자·org 상한 `object_permission`, `no-mcp-servers` 표지, `DELETE /v1/mcp/sessions`(아래 9) |
| MINT 사용 | 운영 모드 `POST /settings/mode`(`src/mint_litellm/console/api.py:692`)와 플러그인 `MINT_MODE`(`plugin/config.py:99`); 키·팀 차단은 사람이 승인한 제안만 LiteLLM에 쓴다(`key_block.py:566` → `set_blocked`, `litellm_write.py:312-317`) |
| 권장 | **FM-55는 MINT 자체**로 구현한다(플러그인이 모든 MCP 호출을 판정에서 막음: MINT DB를 요청마다 읽으므로 캐시 지연 없음). LiteLLM 쪽에는 보조로 (a) 모든 활성 서버 `reject` 일괄(4), (b) 필요 시 대상 키·팀 차단을 쓸 수 있다. 전역 정지에 키 차단을 기본으로 묶지 않는다(사람 승인 없는 자동 차단 금지 원칙, `보장과-한계.md` 208행) |

## 9. 키·토큰 폐기와 세션 무효화 시점

| 항목 | 내용 |
|---|---|
| 1.106.6 캐시 | 키·팀·사용자 객체는 `user_api_key_cache`에 **기본 60초**(`litellm/proxy/proxy_server.py` `UserAPIKeyCacheTTLEnum.in_memory_cache_ttl=60`, 설정 `general_settings.user_api_key_cache_ttl`로 조정, 이 기기 설정에는 없음). 인증은 캐시 우선·신선도 확인 없음. 변경 API(`/key/block`·`/key/update`·`/key/delete`)는 로컬 캐시 삭제 후 **Redis가 있으면** 다른 워커에 삭제를 방송한다(`auth_cache_invalidation_pubsub.py` `publish_auth_cache_invalidation`, 최선 노력·실패하면 TTL까지 유지). 방송은 `redis_usage_cache`(환경 변수 `REDIS_*`)만 있으면 동작하고 `enable_redis_auth_cache`와 무관하며, 후자는 키 객체 자체를 Redis에 공유할 때만 필요하다(`proxy_server.py` `_attach_redis_usage_cache`). 권한 행(`object_permission`)도 같은 방송으로 삭제(`invalidate_cached_object_permissions`). 이 기기: `NUM_WORKERS=2`, `REDIS_HOST` 설정됨, `enable_redis_auth_cache`·`user_api_key_cache_ttl` 미설정 |
| 서버 변경 | 서버 승인·거절·삭제·수정은 요청마다 DB 개정 번호로 반영되어 지연 없음(1 참조) |
| 세션 | 게이트웨이가 낸 신원 봉투로 들어오는 요청은 매번 키 객체를 다시 읽어(캐시 경유) 차단·만료 키를 401로 거절하고 팀 차단·예산 등을 다시 검사한다(`AUTH._reload_admitted_key`·`_enforce_admitted_live_policy`·`_admitted_key_is_active`, 1281~1432행). 즉 세션 자체는 별도 TTL이 아니라 위 캐시 TTL을 따른다. `DELETE /v1/mcp/sessions?user_id=|session_id_prefix=`는 **요청을 받은 워커 하나의 세션만** 닫는다(`terminate_mcp_gateway_sessions` 주석 「Only sessions held by this worker」, 응답에 `worker_pid`). 이 기기는 워커가 둘이라 한 번 호출로 전부 닫히지 않는다 |
| MINT 사용 | 키 폐기·해제는 `/key/delete`(별칭 접두 한정)와 `/key/block`·`/key/unblock`(`litellm_write.py:407-415`, `:312`), 권한 갱신은 `/key/update`. 판정 쪽은 MINT DB를 직접 읽어 LiteLLM 캐시와 무관하다(`보장과-한계.md` 89행). 세션 종료 API는 쓰지 않는다 |
| 권장 | (a) 폐기·차단의 **즉시성은 MINT 판정이 담당**하고(플러그인은 폐기된 신원의 호출을 DB 기준으로 거부), LiteLLM 차단은 보강으로 본다. (b) FM-59 전파 확인: LiteLLM 쪽 반영 시각은 「쓰기 직후 `/key/info`·`/key/list`로 읽기」가 아니라 **최대 60초 + 방송 실패 가능성**을 전제로, 기본 상한 60초 안에 반영되지 않은 키는 미전파 경보로 표시한다. 읽기 확인이 같은 워커에서만 반영된 것을 볼 수 있어 확인을 여러 번 나눠 한다. (c) 폐기 지연을 줄이려면 `general_settings.user_api_key_cache_ttl`을 15~30으로 낮출 수 있으나 DB 부하가 늘어 MINT 설정 점검 항목으로 올릴지는 별도 결정이다. (d) `DELETE /v1/mcp/sessions`를 root 「세션 종료」에 쓰려면 워커 수만큼 반복해 `worker_pid` 합집합을 확인해야 하므로 지금은 쓰지 않고, 키 차단·삭제로 세션을 끊는다 |

## 확인하지 못한 것

- 실제 요청으로 재현한 항목은 없다(읽기 전용 조사). 특히 (가) 활성 서버 `reject`가 다른 워커의 열린 세션 도구 호출까지 즉시 막는지, (나) `rpm: 0`이 집행되는지, (다) 키 차단 직후 두 번째 워커가 방송으로 즉시 거절하는지는 시험 환경에서 확인이 필요하다.
- 접근 그룹·toolset(`mcp_toolsets`)의 세부 동작과 UI의 서버 제출 화면은 조사하지 않았다. 사용자 object_permission 상한(「모든 키의 상한」)과 org 상한을 전역 정지 보조로 쓸 수 있는지도 미확인이다.
- `blocked_tools`가 MCP에서 집행되지 않는다는 결론은 파이썬 소스 전체 검색(해당 컬럼을 읽는 MCP 코드 없음)에 근거한다. 다른 판본에서는 달라질 수 있어 판본 갱신 때 다시 확인해야 한다.

## 실행할 일 (제안, 코드는 이 조사에서 바꾸지 않음)

1. **서버 중지·이용 종료·root 즉시 비활성화에 `reject`를 더한다**: 활성 서버를 `reject_submission`으로 내리고 재개 때 `approve_submission`. 허용 경로 변경 없음. 대상 작업: `sync_jobs.py`의 서버 중지·재개 경로(FM-14·FM-45·FM-56).
2. **FM-55 전역 정지는 MINT 자체**로 만든다(플러그인 판정 차단 + 선택적으로 활성 서버 일괄 `reject`). LiteLLM에 전역 정지 설정이 없다는 사실을 DESIGN_SYSTEM·결정 기록에 적는다.
3. **도구 사후 차단·호출별 검토는 계속 플러그인이 맡는다**(LiteLLM은 허용 목록뿐). `blocked_tools`·서버 `disallowed_tools`·`/v1/tool/policy`는 MCP 호출에 쓰지 않는다.
4. **폐기 전파 확인(FM-59)을 60초 상한 기준으로 설계한다**: LiteLLM 반영은 캐시 TTL(기본 60초)·Redis 방송(최선 노력)에 달려 있다. MINT 판정이 즉시 막고, LiteLLM 키·권한 반영은 60초 안에 확인되지 않으면 경보한다.
5. **서버 `DELETE`·`DELETE /v1/mcp/sessions`를 쓰지 않는 현재 결정을 유지한다**: 전자는 키·팀 권한을 정리하지 않고, 후자는 워커 하나에만 적용된다.
6. **서버 변경의 감사 기록은 MINT 원장이 유일한 근거**임을 문서(보장과-한계.md)에 적는다. LiteLLM 서버 변경은 감사 로그를 남기지 않는다.
7. 판본이 오르면 이 문서의 「미재현」 항목과 `blocked_tools` 결론을 다시 확인한다(D-004).

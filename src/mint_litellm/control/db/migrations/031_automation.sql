-- 운영 자동화: 계약 변경 요약, 호출별 승인 요청의 자동 개설.

-- 관측 변경마다 사람이 읽는 변경 요약을 함께 둔다(재승인 화면에 보인다).
ALTER TABLE mint.contract_observations ADD COLUMN change_summary text
    CHECK (change_summary IS NULL OR length(change_summary) <= 1024);

-- 판정 프로세스는 막힌 호출의 승인 요청(대기 상태)을 열 수만 있다. 승인·거절·소비 전이는
-- 기존 열 권한과 상태 전이 규칙이 그대로 막는다.
GRANT INSERT (id, instance_id, org_id, principal_type, principal_id, server_id, tool, args_fp,
              fp_key_version, policy_version_id, status, requested_by, expires_at, contract_id,
              exec_contract_sha256)
    ON mint.call_approvals TO mint_plugin;

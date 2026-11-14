-- 호출별 승인 요청이 무엇을 승인받는지(마스킹·절단된 인자 표시), 언제 열렸고 언제 결정됐는지,
-- 거부 사유를 행에 남긴다. 거부된 행은 같은 호출의 재시도를 짧은 시간 거절하는 데 쓰이며
-- 새 상태나 누적 표는 만들지 않는다. 기존 행의 요청 시각은 알 수 없으므로 비워 둔다.
ALTER TABLE mint.call_approvals
    ADD COLUMN display jsonb CHECK (display IS NULL OR jsonb_typeof(display) = 'object'),
    ADD COLUMN requested_at timestamptz,
    ADD COLUMN decided_at timestamptz,
    ADD COLUMN decision_reason text CHECK (decision_reason IS NULL OR length(decision_reason) <= 500);

ALTER TABLE mint.call_approvals ALTER COLUMN requested_at SET DEFAULT clock_timestamp();

CREATE INDEX call_approvals_recent_outcome
    ON mint.call_approvals (instance_id, principal_id, server_id, tool, args_fp)
    WHERE status IN ('rejected', 'expired');
-- 판정 프로세스가 요청을 열 때 쓰는 나머지 열(대상·동작·실행 계약 해시)과 표시 값의 삽입 권한.
GRANT INSERT (target, action, exec_contract_sha256, display)
    ON mint.call_approvals TO mint_plugin;

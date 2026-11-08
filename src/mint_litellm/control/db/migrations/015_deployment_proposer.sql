-- 운영자가 제시한 배포 후보의 제시자(사용자 식별자). 재승인자는 제시자와 달라야 한다.
-- 레지스트리에서 읽은 후보와 신청 때 만든 후보는 비어 있다.
ALTER TABLE mint.deployment_contracts
    ADD COLUMN proposed_by text CHECK (proposed_by IS NULL OR length(proposed_by) > 0);

CREATE TRIGGER deployment_contracts_3_frozen_proposer BEFORE UPDATE ON mint.deployment_contracts
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns('proposed_by');

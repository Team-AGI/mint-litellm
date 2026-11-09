-- 제출 신청의 주소가 처음부터 거부 대상(사설 리터럴 IP)이면 운영자 입력을 기다리지 않고
-- received에서 바로 거절(decided)로 끝낸다. 필수 입력이 비어 있어도 되는 것은 이 거절 한 가지뿐이다.
ALTER TABLE mint.intakes DROP CONSTRAINT intakes_check3;
ALTER TABLE mint.intakes ADD CONSTRAINT intakes_inputs_required CHECK (
    status = 'received'
    OR (status = 'decided' AND decision = 'rejected')
    OR (purpose IS NOT NULL AND data_grade IS NOT NULL AND allowed_resources IS NOT NULL
        AND provider IS NOT NULL AND owner_user_id IS NOT NULL AND readiness IS NOT NULL
        AND data_return_terms IS NOT NULL AND requested_by IS NOT NULL));

DROP TRIGGER intakes_1_status ON mint.intakes;
CREATE TRIGGER intakes_1_status BEFORE INSERT OR UPDATE ON mint.intakes
    FOR EACH ROW EXECUTE FUNCTION mint.check_status(
        'received',
        'received>checking,received>decided,checking>passed,checking>failed,'
        'checking>indeterminate,passed>decided,failed>decided,indeterminate>decided,'
        'passed>checking,indeterminate>checking');

-- 판정 프로세스가 승인 조건의 기본값을 채우는 데 쓰는 값을 파생 열로 둔다.
-- 판정 프로세스는 도구 계약의 정본 문자열이나 수용 신청 행을 읽지 못하므로 값만 열로 내려 준다.

-- 도구 계약의 입력 정의에 있는 항목 이름(정렬). 정본 문자열을 읽지 못하면 NULL(알 수 없음)이다.
CREATE FUNCTION mint.contract_input_keys(canonical text) RETURNS text[]
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN coalesce((
        SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(CASE
            WHEN jsonb_typeof(canonical::jsonb -> 'input_schema' -> 'properties') = 'object'
            THEN canonical::jsonb -> 'input_schema' -> 'properties'
            ELSE '{}'::jsonb END) AS k), '{}'::text[]);
EXCEPTION WHEN others THEN
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION mint.contract_input_keys(text) FROM PUBLIC;
-- 생성 열은 삽입하는 쪽이 계산하므로 도구 계약을 등록하는 제어 평면에만 실행 권한을 준다(직원 로그인 제외).
GRANT EXECUTE ON FUNCTION mint.contract_input_keys(text) TO mint_control, mint_worker;

ALTER TABLE mint.tool_contracts
    ADD COLUMN input_keys text[] GENERATED ALWAYS AS (mint.contract_input_keys(canonical_text)) STORED;
GRANT SELECT (input_keys) ON mint.tool_contracts TO mint_plugin;

-- 서버의 마지막 승인된 수용 신청이 적은 자료 등급. 수용 신청 없이 등록된 서버는 NULL이다.
ALTER TABLE mint.servers
    ADD COLUMN data_grade text CHECK (data_grade IN ('public', 'internal', 'confidential', 'restricted'));
UPDATE mint.servers s SET data_grade = i.data_grade
FROM (
    SELECT DISTINCT ON (instance_id, server_id) instance_id, server_id, data_grade
    FROM mint.intakes WHERE decision IN ('approved', 'exception')
    ORDER BY instance_id, server_id, decided_at DESC
) i
WHERE s.instance_id = i.instance_id AND s.server_id = i.server_id;

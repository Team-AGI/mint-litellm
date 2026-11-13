-- 원장(mint.events)을 inserted_at 기준 월별 범위 분할 표로 바꾼다.
--
-- 이 파일은 사건 표를 새로 만들어 모든 행을 옮기고 옛 표를 지운다. 표 크기에 비례해 걸리므로
-- 적용 전에 백업한다. 행의 모든 열(봉인 열 포함)을 그대로 옮기며 옛 표와 새 표의 행 수가 다르면
-- 트랜잭션 전체가 취소된다.
--
-- 분할 표의 유일 제약은 분할 키(inserted_at)를 포함해야 하므로 사건 표의 유일 제약 세 가지
-- (event_id, (instance_id, source_key), (instance_id, seal_seq))는 같은 보장을 별도 표
-- mint.event_keys가 맡는다. 그 표는 분할을 지워도 남는다(지운 달의 사건이 다시 들어오지 않는다).

-- ---------------------------------------------------------------------------
-- 1. 옛 표 치우기
-- ---------------------------------------------------------------------------

ALTER TABLE mint.events RENAME TO events_unpartitioned;
ALTER TABLE mint.events_unpartitioned
    DROP CONSTRAINT events_pkey,
    DROP CONSTRAINT events_instance_id_source_key_key,
    DROP CONSTRAINT events_instance_id_seal_seq_key;
DROP INDEX mint.events_by_time, mint.events_by_invocation, mint.events_unsealed,
    mint.events_decisions_by_time;
DROP FUNCTION mint.staff_list_events(integer);

-- ---------------------------------------------------------------------------
-- 2. 중복 제거·봉인 순번 유일성을 맡는 키 표
-- ---------------------------------------------------------------------------

CREATE TABLE mint.event_keys (
    instance_id mint.ident NOT NULL,
    source_key  text NOT NULL,
    event_id    uuid NOT NULL UNIQUE,
    seal_seq    bigint,
    -- 사건 행이 실제로 들어왔는가. claim_event_key가 먼저 잡은 키는 false이고 삽입이 true로 바꾼다.
    landed      boolean NOT NULL DEFAULT false,
    PRIMARY KEY (instance_id, source_key)
);
CREATE UNIQUE INDEX event_keys_seal_seq ON mint.event_keys (instance_id, seal_seq)
    WHERE seal_seq IS NOT NULL;

INSERT INTO mint.event_keys (instance_id, source_key, event_id, seal_seq, landed)
    SELECT instance_id, source_key, event_id, seal_seq, true FROM mint.events_unpartitioned;

-- 키 행은 추가만 되고, 봉인 순번(비어 있을 때 한 번)과 landed(false에서 true로 한 번)만 채워진다.
CREATE FUNCTION mint.guard_event_keys() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND (to_jsonb(NEW) - 'seal_seq' - 'landed') = (to_jsonb(OLD) - 'seal_seq' - 'landed')
       AND (OLD.seal_seq IS NULL OR NEW.seal_seq IS NOT DISTINCT FROM OLD.seal_seq)
       AND (NOT OLD.landed OR NEW.landed) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'event keys are append-only' USING ERRCODE = 'check_violation';
END $$;

CREATE TRIGGER event_keys_guard BEFORE UPDATE OR DELETE ON mint.event_keys
    FOR EACH ROW EXECUTE FUNCTION mint.guard_event_keys();
CREATE TRIGGER event_keys_guard_truncate BEFORE TRUNCATE ON mint.event_keys
    FOR EACH STATEMENT EXECUTE FUNCTION mint.reject_mutation();

-- ON CONFLICT (instance_id, source_key) DO NOTHING을 대신한다. 키를 먼저 잡은 쪽만 사건을 넣는다.
--   INSERT INTO mint.events ... SELECT ... WHERE mint.claim_event_key(instance_id, source_key, event_id)
CREATE FUNCTION mint.claim_event_key(p_instance_id text, p_source_key text, p_event_id uuid)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = mint, pg_catalog AS $$
DECLARE
    claimed integer;
BEGIN
    INSERT INTO mint.event_keys (instance_id, source_key, event_id)
        VALUES (p_instance_id, p_source_key, p_event_id)
        ON CONFLICT (instance_id, source_key) DO NOTHING;
    GET DIAGNOSTICS claimed = ROW_COUNT;
    RETURN claimed = 1;
END $$;
REVOKE ALL ON FUNCTION mint.claim_event_key(text, text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.claim_event_key(text, text, uuid) TO mint_ledger_writer;

-- 사건 삽입마다 키를 등록한다(같은 키·같은 event_id를 먼저 잡았으면 그 키를 쓴다). 이미 있는 키면
-- 일반 삽입은 이전처럼 unique_violation으로 거부된다. 봉인 열이 채워질 때 봉인 순번 유일성도 지킨다.
CREATE FUNCTION mint.events_register_key() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = mint, pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE mint.event_keys SET landed = true
            WHERE instance_id = NEW.instance_id AND source_key = NEW.source_key
              AND event_id = NEW.event_id AND NOT landed;
        IF NOT FOUND THEN
            INSERT INTO mint.event_keys (instance_id, source_key, event_id, landed)
                VALUES (NEW.instance_id, NEW.source_key, NEW.event_id, true);
        END IF;
    ELSIF NEW.seal_seq IS NOT NULL AND OLD.seal_seq IS NULL THEN
        UPDATE mint.event_keys SET seal_seq = NEW.seal_seq WHERE event_id = NEW.event_id;
    END IF;
    RETURN NEW;
END $$;

-- ---------------------------------------------------------------------------
-- 3. 분할 사건 표
-- ---------------------------------------------------------------------------

CREATE TABLE mint.events (
    event_id      uuid NOT NULL,
    instance_id   mint.ident NOT NULL,
    inserted_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    kind          text NOT NULL CHECK (kind ~ '^[a-z][a-z_]*$'),
    source_key    text NOT NULL CHECK (length(source_key) BETWEEN 1 AND 512),
    invocation_id uuid,
    attempt_id    integer CHECK (attempt_id >= 1),
    actor         text,
    subject       jsonb,
    payload       jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    seal_seq      bigint,
    prev_hash     bytea CHECK (prev_hash IS NULL OR length(prev_hash) = 32),
    row_hash      bytea CHECK (row_hash IS NULL OR length(row_hash) = 32),
    sealed_at     timestamptz,
    CHECK (source_key NOT LIKE 'call:%' OR (invocation_id IS NOT NULL AND attempt_id IS NOT NULL)),
    CHECK ((seal_seq IS NULL) = (row_hash IS NULL) AND (seal_seq IS NULL) = (sealed_at IS NULL))
) PARTITION BY RANGE (inserted_at);

CREATE INDEX events_by_id ON mint.events (event_id);
CREATE INDEX events_by_time ON mint.events (instance_id, inserted_at);
CREATE INDEX events_by_seal ON mint.events (instance_id, seal_seq) WHERE seal_seq IS NOT NULL;
CREATE INDEX events_by_invocation ON mint.events (invocation_id) WHERE invocation_id IS NOT NULL;
CREATE INDEX events_unsealed ON mint.events (inserted_at, event_id) WHERE seal_seq IS NULL;
CREATE INDEX events_decisions_by_time ON mint.events (instance_id, inserted_at)
    WHERE kind = 'decision_evaluated';

-- 분할 만들기. 월 경계는 UTC다. 기본 분할이 이미 그 달의 행을 갖고 있으면 만들 수 없다(오류).
CREATE FUNCTION mint.ensure_event_partition(p_month date) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = mint, pg_catalog AS $$
DECLARE
    first_day date := date_trunc('month', p_month)::date;
    part text := 'events_' || to_char(first_day, 'YYYYMM');
BEGIN
    IF to_regclass('mint.' || part) IS NOT NULL THEN
        RETURN false;
    END IF;
    EXECUTE format(
        'CREATE TABLE mint.%I PARTITION OF mint.events FOR VALUES FROM (%L) TO (%L)',
        part, to_char(first_day, 'YYYY-MM-DD') || ' 00:00:00+00',
        to_char((first_day + interval '1 month')::date, 'YYYY-MM-DD') || ' 00:00:00+00');
    -- 문장 수준 트리거는 분할로 복제되지 않으므로 분할마다 직접 건다.
    EXECUTE format(
        'CREATE TRIGGER events_guard_truncate BEFORE TRUNCATE ON mint.%I '
        'FOR EACH STATEMENT EXECUTE FUNCTION mint.guard_events_truncate()', part);
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION mint.ensure_event_partition(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.ensure_event_partition(date) TO mint_worker;

CREATE TABLE mint.events_default PARTITION OF mint.events DEFAULT;
CREATE TRIGGER events_guard_truncate BEFORE TRUNCATE ON mint.events_default
    FOR EACH STATEMENT EXECUTE FUNCTION mint.guard_events_truncate();

-- 기존 행이 있는 달과 이번 달부터 석 달 뒤까지의 분할을 만든다.
DO $$
DECLARE
    m date;
BEGIN
    FOR m IN
        SELECT DISTINCT date_trunc('month', inserted_at AT TIME ZONE 'UTC')::date
            FROM mint.events_unpartitioned
        UNION
        SELECT (date_trunc('month', now() AT TIME ZONE 'UTC') + make_interval(months => n))::date
            FROM generate_series(0, 3) AS n
    LOOP
        PERFORM mint.ensure_event_partition(m);
    END LOOP;
END $$;

-- 행을 그대로 옮긴다. 삽입 트리거(봉인 열 지우기)는 아직 없으므로 봉인 열도 보존된다.
INSERT INTO mint.events SELECT * FROM mint.events_unpartitioned;

DO $$
BEGIN
    IF (SELECT count(*) FROM mint.events) <> (SELECT count(*) FROM mint.events_unpartitioned) THEN
        RAISE EXCEPTION 'events copy is incomplete' USING ERRCODE = 'data_exception';
    END IF;
END $$;

DROP TABLE mint.events_unpartitioned;

-- ---------------------------------------------------------------------------
-- 4. 트리거(옛 표와 같은 이름·같은 순서). 행 수준 트리거는 분할로 복제된다.
-- ---------------------------------------------------------------------------

CREATE TRIGGER events_0_plugin_kinds BEFORE INSERT ON mint.events
    FOR EACH ROW EXECUTE FUNCTION mint.restrict_plugin_events();
CREATE TRIGGER events_guard
    BEFORE INSERT OR UPDATE OR DELETE ON mint.events
    FOR EACH ROW EXECUTE FUNCTION mint.guard_events();
CREATE TRIGGER events_key BEFORE INSERT OR UPDATE ON mint.events
    FOR EACH ROW EXECUTE FUNCTION mint.events_register_key();
CREATE TRIGGER events_guard_truncate
    BEFORE TRUNCATE ON mint.events
    FOR EACH STATEMENT EXECUTE FUNCTION mint.guard_events_truncate();

-- ---------------------------------------------------------------------------
-- 5. 권한(옛 표와 같다)
-- ---------------------------------------------------------------------------

GRANT SELECT, INSERT ON mint.events TO mint_ledger_writer;
GRANT SELECT ON mint.events TO mint_sealer;
GRANT UPDATE (seal_seq, prev_hash, row_hash, sealed_at) ON mint.events TO mint_sealer;
GRANT SELECT ON mint.events TO mint_staff_owner;
GRANT INSERT (event_id, instance_id, kind, source_key, actor, payload)
    ON mint.events TO mint_staff_owner;

-- 옛 표의 행 형식을 쓰던 직원 조회 함수를 새 표로 다시 만든다.
CREATE FUNCTION mint.staff_list_events(p_limit integer DEFAULT 100)
RETURNS SETOF mint.events
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
    SELECT e.* FROM mint.events e
    WHERE e.instance_id = mint.staff_instance()
      AND (
        e.subject ->> 'principal_id' = mint.staff_user()
        OR (e.kind IN ('consent_granted', 'consent_revoked')
            AND EXISTS (SELECT 1 FROM mint.consents c
                        WHERE c.instance_id = e.instance_id
                          AND c.id::text = split_part(e.source_key, ':', 2)
                          AND c.human_user_id = mint.staff_user()))
        OR (e.kind IN ('call_approval_approved', 'call_approval_rejected',
                       'call_approval_cancelled')
            AND e.payload ->> 'kind' = 'confirmation'
            AND EXISTS (SELECT 1 FROM mint.self_confirmations s
                        WHERE s.instance_id = e.instance_id
                          AND s.id::text = split_part(e.source_key, ':', 2)
                          AND s.principal_id = mint.staff_user()))
        OR (e.kind IN ('console_session_started', 'console_session_ended')
            AND EXISTS (SELECT 1 FROM mint.console_sessions n
                        WHERE n.instance_id = e.instance_id AND n.subject = 'staff'
                          AND n.id_hash = split_part(e.source_key, ':', 2)
                          AND n.user_id = mint.staff_user())))
    ORDER BY e.inserted_at DESC, e.event_id DESC
    LIMIT least(greatest(p_limit, 1), 1000)
$$;
REVOKE ALL ON FUNCTION mint.staff_list_events(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.staff_list_events(integer) TO mint_staff;

-- 직원 사건 함수는 ON CONFLICT 대신 키를 먼저 잡는다.
CREATE OR REPLACE FUNCTION mint.staff_event(
    p_kind text, p_entity text, p_id text, p_version bigint, p_actor text, p_payload jsonb
) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = mint, pg_catalog AS $$
    INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, payload)
    SELECT s.e, mint.staff_instance(), p_kind, s.k, p_actor, p_payload
    FROM (SELECT gen_random_uuid() AS e,
                 p_entity || ':' || p_id || ':' || p_version || ':' || p_kind AS k) s
    WHERE mint.claim_event_key(mint.staff_instance(), s.k, s.e)
$$;

-- ---------------------------------------------------------------------------
-- 6. 닫힌 달의 내보내기 기록과 분할 지우기
-- ---------------------------------------------------------------------------

-- 달마다 한 행. 파일 해시는 gzip 파일 바이트의 SHA-256이다. seal_ranges는 인스턴스별
-- [처음, 끝] 봉인 순번으로, 지운 뒤의 봉인 검증이 빠진 구간을 설명하는 데 쓴다.
CREATE TABLE mint.event_exports (
    month        date PRIMARY KEY CHECK (month = date_trunc('month', month)::date),
    row_count    bigint NOT NULL CHECK (row_count >= 0),
    file_sha256  text NOT NULL CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
    path         text NOT NULL CHECK (length(path) > 0),
    seal_ranges  jsonb NOT NULL CHECK (jsonb_typeof(seal_ranges) = 'object'),
    revision     integer NOT NULL DEFAULT 1 CHECK (revision >= 1),
    written_at   timestamptz NOT NULL DEFAULT now(),
    dropped_at   timestamptz
);
GRANT SELECT, INSERT, UPDATE ON mint.event_exports TO mint_worker;
GRANT SELECT ON mint.event_exports TO mint_control, mint_sealer;

-- 분할을 지운다. 달이 끝났고, 분할의 사건이 모두 봉인되었고, 지금 행 수가 검증된 내보내기 기록의
-- 행 수와 같을 때만 지운다. 하나라도 어긋나면 지우지 않고 오류를 낸다. 기본 분할은 지울 수 없다.
CREATE FUNCTION mint.drop_event_partition(p_month date, p_row_count bigint, p_file_sha256 text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = mint, pg_catalog AS $$
DECLARE
    first_day date := date_trunc('month', p_month)::date;
    part text := 'events_' || to_char(first_day, 'YYYYMM');
    actual bigint;
BEGIN
    IF first_day <> p_month THEN
        RAISE EXCEPTION 'month must be the first day of a month'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits i WHERE i.inhparent = 'mint.events'::regclass
          AND i.inhrelid = to_regclass('mint.' || part)) THEN
        RAISE EXCEPTION 'no such event partition: %', part USING ERRCODE = 'undefined_table';
    END IF;
    IF (first_day + interval '1 month')::date::timestamp AT TIME ZONE 'UTC' > now() THEN
        RAISE EXCEPTION 'the month is not over yet' USING ERRCODE = 'check_violation';
    END IF;
    EXECUTE format('LOCK TABLE mint.%I IN ACCESS EXCLUSIVE MODE', part);
    EXECUTE format('SELECT count(*) FROM mint.%I', part) INTO actual;
    IF actual <> p_row_count THEN
        RAISE EXCEPTION 'row count differs from the verified export (% vs %)', actual, p_row_count
            USING ERRCODE = 'check_violation';
    END IF;
    EXECUTE format('SELECT count(*) FROM mint.%I WHERE seal_seq IS NULL', part) INTO actual;
    IF actual > 0 THEN
        RAISE EXCEPTION 'the partition still has unsealed events' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM mint.event_exports
                   WHERE month = first_day AND row_count = p_row_count
                     AND file_sha256 = p_file_sha256) THEN
        RAISE EXCEPTION 'no matching export record' USING ERRCODE = 'check_violation';
    END IF;
    EXECUTE format('DROP TABLE mint.%I', part);
    UPDATE mint.event_exports SET dropped_at = now() WHERE month = first_day;
END $$;
REVOKE ALL ON FUNCTION mint.drop_event_partition(date, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.drop_event_partition(date, bigint, text) TO mint_worker;

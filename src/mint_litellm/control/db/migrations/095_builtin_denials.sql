-- 하네스 기본 기능(가상 서버 builtin:claude·builtin:codex)도 화면에서 막을 수 있게 거부의 서버 참조를
-- 등록된 서버 또는 가상 서버로 넓힌다. 가상 서버에는 서버 행이 없어 외래 키 대신 트리거로 확인한다.
ALTER TABLE mint.denials DROP CONSTRAINT IF EXISTS denials_instance_id_server_id_fkey;

CREATE FUNCTION mint.denials_known_server() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, mint, pg_temp AS $$
BEGIN
    IF NEW.server_id IS NOT NULL
       AND NEW.server_id NOT IN ('builtin:claude', 'builtin:codex')
       AND NOT EXISTS (SELECT 1 FROM mint.servers s
                       WHERE s.instance_id = NEW.instance_id AND s.server_id = NEW.server_id) THEN
        RAISE EXCEPTION 'unknown server %', NEW.server_id USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER denials_known_server BEFORE INSERT OR UPDATE OF server_id, instance_id
    ON mint.denials FOR EACH ROW EXECUTE FUNCTION mint.denials_known_server();

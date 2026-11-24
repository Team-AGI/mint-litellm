-- 일반 가입 폼: 가입 때 받은 비밀번호를 승인 전까지 암호문으로만 두고(작업 실행기가 LiteLLM 초대
-- 확정으로 넘긴 뒤 지운다), 상태 주소 토큰은 더 이상 만들지 않는다.
ALTER TABLE mint.signup_requests ADD COLUMN password_sealed bytea
    CHECK (password_sealed IS NULL OR length(password_sealed) BETWEEN 29 AND 2048);
ALTER TABLE mint.signup_requests ALTER COLUMN status_token_hash DROP NOT NULL;
GRANT INSERT (instance_id, id, email, display_name, password_sealed)
    ON mint.signup_requests TO mint_staff_owner;

CREATE FUNCTION mint.staff_signup_request(p_instance text, p_id uuid, p_email text,
    p_name text, p_sealed bytea) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, mint, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM mint.directory_users WHERE instance_id = p_instance
               AND lower(email) = lower(p_email) AND gone_at IS NULL) THEN
        RETURN false;
    END IF;
    IF EXISTS (SELECT 1 FROM mint.signup_requests r WHERE r.instance_id = p_instance
               AND lower(r.email) = lower(p_email) AND r.status = 'approved'
               AND NOT EXISTS (SELECT 1 FROM mint.directory_users d
                   WHERE d.instance_id = r.instance_id AND d.user_id = r.litellm_user_id
                   AND d.gone_at IS NOT NULL)) THEN
        RETURN false;
    END IF;
    INSERT INTO mint.signup_requests(instance_id,id,email,display_name,password_sealed)
        VALUES(p_instance,p_id,p_email,p_name,p_sealed);
    RETURN true;
EXCEPTION WHEN unique_violation THEN
    RETURN false;
END $$;

GRANT CREATE ON SCHEMA mint TO mint_staff_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('GRANT mint_staff_owner TO %I WITH SET TRUE',current_user);
    END IF;
END $$;
ALTER FUNCTION mint.staff_signup_request(text,uuid,text,text,bytea) OWNER TO mint_staff_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_staff_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('REVOKE SET OPTION FOR mint_staff_owner FROM %I',current_user);
    END IF;
END $$;
REVOKE ALL ON FUNCTION mint.staff_signup_request(text,uuid,text,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.staff_signup_request(text,uuid,text,text,bytea) TO mint_staff;

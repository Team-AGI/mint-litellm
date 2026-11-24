CREATE TABLE mint.signup_requests (
    instance_id mint.ident NOT NULL,
    id uuid NOT NULL,
    email text NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'failed')),
    status_token_hash text NOT NULL CHECK (status_token_hash ~ '^[0-9a-f]{64}$'),
    requested_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz,
    decided_by text,
    reason text,
    litellm_user_id text,
    invitation_id text,
    last_error text,
    PRIMARY KEY (instance_id, id),
    UNIQUE (instance_id, status_token_hash)
);
CREATE UNIQUE INDEX signup_requests_pending_email ON mint.signup_requests (instance_id, lower(email))
    WHERE status = 'pending';
REVOKE ALL ON mint.signup_requests FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.signup_requests TO mint_control;
GRANT SELECT, UPDATE ON mint.signup_requests TO mint_worker;

GRANT SELECT (instance_id, user_id, email, gone_at) ON mint.directory_users TO mint_staff_owner;
GRANT SELECT (instance_id, email, status, status_token_hash, reason, invitation_id,
    litellm_user_id) ON mint.signup_requests TO mint_staff_owner;
GRANT INSERT (instance_id, id, email, display_name, status_token_hash)
    ON mint.signup_requests TO mint_staff_owner;
CREATE FUNCTION mint.staff_signup_submit(p_instance text, p_id uuid, p_email text,
    p_name text, p_hash text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
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
    INSERT INTO mint.signup_requests(instance_id,id,email,display_name,status_token_hash)
        VALUES(p_instance,p_id,p_email,p_name,p_hash);
    RETURN true;
EXCEPTION WHEN unique_violation THEN
    RETURN false;
END $$;
CREATE FUNCTION mint.staff_signup_status(p_instance text, p_hash text)
RETURNS TABLE(status text, reason text, invitation_id text) LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, mint, pg_temp AS $$
    SELECT r.status, r.reason, r.invitation_id FROM mint.signup_requests r
    WHERE r.instance_id = p_instance AND r.status_token_hash = p_hash
$$;
GRANT CREATE ON SCHEMA mint TO mint_staff_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('GRANT mint_staff_owner TO %I WITH SET TRUE',current_user);
    END IF;
END $$;
ALTER FUNCTION mint.staff_signup_submit(text,uuid,text,text,text) OWNER TO mint_staff_owner;
ALTER FUNCTION mint.staff_signup_status(text,text) OWNER TO mint_staff_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_staff_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('REVOKE SET OPTION FOR mint_staff_owner FROM %I',current_user);
    END IF;
END $$;
REVOKE ALL ON FUNCTION mint.staff_signup_submit(text,uuid,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.staff_signup_status(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.staff_signup_submit(text,uuid,text,text,text) TO mint_staff;
GRANT EXECUTE ON FUNCTION mint.staff_signup_status(text,text) TO mint_staff;

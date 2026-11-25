-- 사람의 팀 소속이 바뀌면 그 사람의 단말 설치·앱 자격의 팀도 따라 바뀐다.
GRANT UPDATE (team_id) ON mint.endpoint_apps TO mint_control;

DROP TRIGGER endpoint_installs_2_frozen ON mint.endpoint_installs;
CREATE TRIGGER endpoint_installs_2_frozen BEFORE UPDATE ON mint.endpoint_installs
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'key_token', 'user_id', 'key_alias', 'issued_by', 'issued_at');

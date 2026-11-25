-- 사람의 팀 소속이 바뀌면 그 사람의 단말 앱 자격의 팀도 따라 바뀐다.
GRANT UPDATE (team_id) ON mint.endpoint_apps TO mint_control;

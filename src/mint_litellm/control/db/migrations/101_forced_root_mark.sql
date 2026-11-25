-- Root 표지 지정·해제도 강제 조치 기록에 남긴다.
ALTER TABLE mint.forced_actions DROP CONSTRAINT forced_actions_action_check;
ALTER TABLE mint.forced_actions ADD CONSTRAINT forced_actions_action_check CHECK (action IN (
    'halt', 'halt_lift', 'intake_reject', 'server_suspend', 'server_resume',
    'server_terminate', 'person_lockout', 'person_unlock', 'sessions_end', 'root_set',
    'root_unset'));

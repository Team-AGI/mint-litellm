-- 콘솔의 「지금 백업」 요청 표시. 예약 백업 컨테이너가 1분마다 읽고 마지막 백업보다 새로우면 바로 백업한다.
ALTER TABLE mint.setup_marks DROP CONSTRAINT setup_marks_mark_check;
ALTER TABLE mint.setup_marks ADD CONSTRAINT setup_marks_mark_check
    CHECK (mark IN ('webhook_test', 'audit_report', 'backup_requested'));

-- 제어 역할의 논리 백업은 모든 mint 표를 읽어 일관된 복원본을 만든다.
GRANT SELECT ON ALL TABLES IN SCHEMA mint TO mint_control;

-- 증빙 첨부가 대기 중인 폐기 작업의 다음 실행만 앞당길 수 있다.
GRANT UPDATE (run_after) ON mint.jobs TO mint_control;

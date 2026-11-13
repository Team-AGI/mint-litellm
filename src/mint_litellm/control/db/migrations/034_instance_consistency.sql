-- 같은 서버를 계약 관리하는 다른 인스턴스와 승인 계약·보안 설정이 달라 호출을 막는 서버의 표지
-- (막기 시작한 시각). 판정은 서버 행을 읽는다. 예외 증빙이 있거나 차이가 사라지면 비운다.
ALTER TABLE mint.servers ADD COLUMN instance_mismatch_at timestamptz;

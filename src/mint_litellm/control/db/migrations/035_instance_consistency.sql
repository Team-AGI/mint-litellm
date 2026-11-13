-- 같은 서버를 계약 관리하는 다른 인스턴스와 승인 계약·보안 설정이 달라진 서버의 표지.
-- since는 차이를 처음 본 시각, at은 유예가 지나 호출을 막기 시작한 시각이다. 판정은 at만 읽는다.
-- 차이가 사라지면 둘 다 비운다.
ALTER TABLE mint.servers
    ADD COLUMN instance_mismatch_since timestamptz,
    ADD COLUMN instance_mismatch_at timestamptz;

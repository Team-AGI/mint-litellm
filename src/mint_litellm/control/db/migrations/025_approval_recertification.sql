-- 승인의 필요성 재확인 주기. 승인은 정해진 기간마다 운영자가 여전히 필요한지 다시 확인해야 하며,
-- 유예 안에 확인이 없으면 보류되어 판정이 그 승인을 쓰지 않는다.
--
-- 새 열은 모두 가변이다. 승인의 기간·범위·도구·조건을 고정하는 트리거(approvals_2_frozen)와
-- 상태 전이 트리거(approvals_1_status)는 건드리지 않는다. 보류는 상태를 바꾸지 않고
-- recert_held_at 표지로 표현한다(상태 전이표에 단계를 더하지 않는다).
--   recert_confirmed_at / _by  마지막 재확인 시각과 확인한 운영자(없으면 유효 시작 시각이 기준)
--   recert_requested_at        재확인 요청을 연 시각(확인하면 지운다)
--   recert_held_at             유예가 지나 보류된 시각(확인하면 지운다)
-- 표 단위 권한(mint_plugin 조회, mint_control 갱신)이 새 열에도 그대로 적용된다.
ALTER TABLE mint.approvals
    ADD COLUMN recert_confirmed_at  timestamptz,
    ADD COLUMN recert_confirmed_by  text,
    ADD COLUMN recert_requested_at  timestamptz,
    ADD COLUMN recert_held_at       timestamptz,
    ADD CONSTRAINT approvals_recert_confirm_pair
        CHECK ((recert_confirmed_at IS NULL) = (recert_confirmed_by IS NULL));

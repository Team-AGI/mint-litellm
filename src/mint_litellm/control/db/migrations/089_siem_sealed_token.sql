-- 화면에서 입력한 SIEM 토큰은 봉인(AES-GCM)해 대상 행에 둔다. 봉인 값이 있으면 읽을 곳은 'sealed:'다.
ALTER TABLE mint.siem_targets ADD COLUMN sealed_secret bytea;
ALTER TABLE mint.siem_targets ADD CONSTRAINT siem_targets_sealed_shape
    CHECK ((secret_ref = 'sealed:') = (sealed_secret IS NOT NULL));

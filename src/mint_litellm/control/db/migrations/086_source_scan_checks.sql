-- 로컬 신청의 공급망 검사: 구성요소 목록(SBOM)·코드·비밀 검사(SAST)·의존성 취약점(SCA).
ALTER TABLE mint.intake_checks DROP CONSTRAINT intake_checks_check_check;
ALTER TABLE mint.intake_checks ADD CONSTRAINT intake_checks_check_check CHECK ("check" IN (
    'url_guard', 'oauth_issuer_allowlist', 'connection', 'definitions',
    'description_scan', 'risk_grade', 'termination_readiness', 'supply_chain',
    'exec_shape', 'pack_build', 'inspection', 'sbom', 'code_scan', 'dependency_vulns'));

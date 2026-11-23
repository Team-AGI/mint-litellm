-- 로컬 서버가 레지스트리에 없다는 이유만으로 켜진 배포 변경 표지를 푼다.
UPDATE mint.servers
   SET deployment_drift = false, deployment_drift_fields = NULL
 WHERE identity_kind <> 'remote'
   AND deployment_drift
   AND deployment_drift_fields = ARRAY['registry_missing']::text[];

-- 플러그인은 호출 때 승인된 배포 계약의 OAuth 범위를 읽어 서버 정의의 범위와 대조한다(읽기만).
GRANT SELECT (oauth_scopes) ON mint.deployment_contracts TO mint_plugin;

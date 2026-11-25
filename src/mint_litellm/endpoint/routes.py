"""단말 훅이 부르는 경로 이름. 콘솔의 키 발급과 판정 쪽 경로 등록이 같은 목록을 쓴다."""

DECIDE_PATH = "/mint/v1/decide"
RESULT_PATH = "/mint/v1/result"
REPORT_PATH = "/mint/v1/endpoint/report"
OUTCOMES_PATH = "/mint/v1/endpoint/outcomes"
ME_PATH = "/mint/v1/endpoint/me"
INTAKES_PATH = "/mint/v1/endpoint/intakes"
APPS_PATH = "/mint/v1/endpoint/apps"
APP_PATH = APPS_PATH + "/{app_id}"
PACKS_PREFIX = "/mint/v1/endpoint/packs"
PACKS_PATH = PACKS_PREFIX + "/{server_id}/{pack_sha256}/{file}"
INSPECTIONS_PREFIX = "/mint/v1/endpoint/inspections"
INSPECTION_START_PATH = INSPECTIONS_PREFIX + "/{inspection_id}/start"
INSPECTION_RESULT_PATH = INSPECTIONS_PREFIX + "/{inspection_id}/result"
ACCESS_REQUESTS_PATH = "/mint/v1/endpoint/access-requests"
ACCESS_REQUEST_CANCEL_PATH = ACCESS_REQUESTS_PATH + "/{request_id}/cancel"

# 설치 묶음의 사용자 키가 부를 수 있는 경로의 전부이다(LiteLLM 키의 ``allowed_routes``).
KIT_KEY_ROUTES = (
    DECIDE_PATH, RESULT_PATH, REPORT_PATH, OUTCOMES_PATH, ME_PATH, INTAKES_PATH,
    PACKS_PREFIX + "/*", INSPECTIONS_PREFIX + "/*", APPS_PATH, APPS_PATH + "/*",
    ACCESS_REQUESTS_PATH, ACCESS_REQUESTS_PATH + "/*",
)

# 게이트웨이 MCP 전용 키가 부를 수 있는 LiteLLM의 MCP 경로(접두 일치·와일드카드).
# 모델 호출은 열지 않는다.
MCP_KEY_ROUTES = ("/mcp", "/mcp/*", "/mcp-rest/*")

# 직원이 직접 만든 AI 프로그램(앱) 키가 부를 수 있는 경로: 모델 호출과 MCP. 단말 경로는 열지 않는다.
APP_KEY_ROUTES = (
    "/chat/completions", "/v1/chat/completions", "/completions", "/v1/completions",
    "/embeddings", "/v1/embeddings", "/responses", "/v1/responses", "/v1/messages",
    "/models", "/v1/models", *MCP_KEY_ROUTES,
)

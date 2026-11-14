"""단말 훅이 부르는 경로 이름. 콘솔의 키 발급과 판정 쪽 경로 등록이 같은 목록을 쓴다."""

DECIDE_PATH = "/mint/v1/decide"
RESULT_PATH = "/mint/v1/result"
REPORT_PATH = "/mint/v1/endpoint/report"
OUTCOMES_PATH = "/mint/v1/endpoint/outcomes"

# 설치 묶음의 사용자 키가 부를 수 있는 경로의 전부이다(LiteLLM 키의 ``allowed_routes``).
KIT_KEY_ROUTES = (DECIDE_PATH, RESULT_PATH, REPORT_PATH, OUTCOMES_PATH)

# 게이트웨이 MCP 전용 키가 부를 수 있는 LiteLLM의 MCP 경로(접두 일치·와일드카드).
# 모델 호출은 열지 않는다.
MCP_KEY_ROUTES = ("/mcp", "/mcp/*", "/mcp-rest/*")

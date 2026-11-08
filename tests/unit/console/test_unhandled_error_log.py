"""처리하지 못한 예외는 500 응답과 함께 요청 식별자가 담긴 로그를 남기되 비밀은 담지 않는다."""

import logging

from fastapi.testclient import TestClient

from mint_litellm.console.app import create_app
from mint_litellm.console.core import ConsoleConfig

SECRET = "sk-secret-key-value"


def test_an_unhandled_error_is_logged_with_the_request_id_and_no_secret(caplog):
    # 이 시험은 데이터베이스를 쓰지 않으므로 주소만 채운 설정이면 된다.
    app = create_app(ConsoleConfig(None, None, "http://litellm.invalid", None, "", ""))

    @app.get("/boom")
    async def boom():
        raise RuntimeError("boom")

    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level(logging.ERROR, logger="mint_litellm.console.app"):
        response = client.get(
            "/boom", headers={"Authorization": f"Bearer {SECRET}"}, cookies={"c": SECRET}
        )
    assert response.status_code == 500
    assert response.json()["code"] == "MINT-ADMIN-UNAVAILABLE"
    request_id = response.headers["X-Request-Id"]
    assert request_id in caplog.text and "GET /boom" in caplog.text
    assert SECRET not in caplog.text

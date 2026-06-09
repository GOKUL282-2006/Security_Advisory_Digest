from fastapi.testclient import TestClient

import app


def test_health_endpoint():
    client = TestClient(app.app)

    assert client.get("/health").json() == {"status": "ok"}

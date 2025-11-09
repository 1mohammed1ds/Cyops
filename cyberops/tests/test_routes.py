import os

import pytest

from app import app


@pytest.fixture()
def client():
    app.config.update({"TESTING": True})
    with app.test_client() as client:
        yield client


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/logs",
        "/phishing",
        "/integrity",
        "/threatintel",
        "/ai",
        "/crypto",
    ],
)
def test_get_routes_respond(client, path):
    response = client.get(path)
    # pages that expect POST should still render on GET
    assert response.status_code in {200, 302}

"""Fixtures shared by the API tests. pytest finds this file by its name and makes its
fixtures available to every test file in this folder, without imports."""

import pytest
from fastapi.testclient import TestClient

from api import main
from model.tests.tiny_model import build_tiny_model

# TrustedHostMiddleware refuses TestClient's default host ("testserver").
BASE_URL = "http://127.0.0.1:8000"


@pytest.fixture(scope="session")
def tiny_model():
    return build_tiny_model()


@pytest.fixture
def open_client():
    """A function that makes a TestClient for the app, addressed to 127.0.0.1.

    Use it as `with open_client() as client:`. Entering the `with` runs the lifespan
    function, like uvicorn does at startup.
    """
    return lambda: TestClient(main.app, base_url=BASE_URL)


@pytest.fixture
def client(monkeypatch, tiny_model, open_client):
    """The app, with the tiny model loaded at startup instead of the real file."""
    monkeypatch.setattr(main, "load_model", lambda: tiny_model)
    with open_client() as client:
        yield client

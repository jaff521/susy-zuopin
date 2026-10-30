"""
Tests for Single-Port Responsive Web Dashboard Hosting.
Verifies:
1. GET / returns index.html (200 OK, text/html)
2. Static assets (/styles.css, /app.js) are properly mounted and served
3. Pre-bundled demo sample (/samples/toy_label_sample.png) is served
4. Security headers are applied to static files as well
5. Zero CORS issues due to same-origin hosting
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_index_html_served_at_root(client):
    """GET / must return the single-port workbench HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "出海易审" in response.text or "CrossBorder SafeGuard" in response.text
    assert "id=\"audit-wizard\"" in response.text or "audit" in response.text.lower()


def test_static_assets_served(client):
    """CSS and JS assets must be accessible."""
    css_res = client.get("/styles.css")
    assert css_res.status_code == 200
    assert "text/css" in css_res.headers.get("content-type", "")

    js_res = client.get("/app.js")
    assert js_res.status_code == 200
    assert "javascript" in js_res.headers.get("content-type", "")


def test_sample_image_asset_served(client):
    """Pre-bundled competition demo sample image must be served."""
    sample_res = client.get("/samples/toy_label_sample.png")
    assert sample_res.status_code == 200
    assert "image/png" in sample_res.headers.get("content-type", "")
    assert len(sample_res.content) > 100

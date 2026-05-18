"""Tests for GET /acme/terms (H4a)."""

from __future__ import annotations

from httpx import AsyncClient


async def test_terms_returns_200(test_client: AsyncClient) -> None:
    resp = await test_client.get("/acme/terms")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "Let's Encrypt" in resp.text

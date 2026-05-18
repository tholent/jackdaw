"""Unit tests for GET /directory."""

from __future__ import annotations

from httpx import AsyncClient


async def test_directory_returns_200(test_client: AsyncClient) -> None:
    resp = await test_client.get("/directory")
    assert resp.status_code == 200


async def test_directory_contains_required_keys(test_client: AsyncClient) -> None:
    resp = await test_client.get("/directory")
    body = resp.json()
    for key in ("newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"):
        assert key in body, f"Missing directory key: {key}"


async def test_directory_urls_use_relay_domain(test_client: AsyncClient) -> None:
    resp = await test_client.get("/directory")
    body = resp.json()
    # The relay domain comes from settings; in tests this is the base_url host.
    for key in ("newNonce", "newAccount", "newOrder"):
        assert "jackdaw" in body[key], f"URL for {key!r} does not reference relay domain"


async def test_directory_has_link_header(test_client: AsyncClient) -> None:
    resp = await test_client.get("/directory")
    assert "Link" in resp.headers

"""Unit tests for GET /version."""

from __future__ import annotations

from importlib.metadata import version

from httpx import AsyncClient


async def test_version_returns_200(test_client: AsyncClient) -> None:
    resp = await test_client.get("/version")
    assert resp.status_code == 200


async def test_version_matches_package_metadata(test_client: AsyncClient) -> None:
    resp = await test_client.get("/version")
    assert resp.json() == {"version": version("jackdaw")}

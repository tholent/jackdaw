"""GET /healthz — liveness probe for Docker and load-balancers; GET /version."""

from fastapi import APIRouter
from fastapi.responses import Response

from jackdaw import __version__

router = APIRouter()


@router.get("/healthz")
async def healthz() -> Response:
    return Response(status_code=200)


@router.get("/version")
async def version() -> dict[str, str]:
    return {"version": __version__}

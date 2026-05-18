"""GET /healthz — liveness probe for Docker and load-balancers."""

from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter()


@router.get("/healthz")
async def healthz() -> Response:
    return Response(status_code=200)

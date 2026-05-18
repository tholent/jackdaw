"""HEAD + POST /acme/new-nonce — the `Replay-Nonce` header is added by middleware."""

from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter()


@router.head("/acme/new-nonce")
async def new_nonce_head() -> Response:
    """Respond to HEAD /acme/new-nonce (RFC 8555 §7.2).

    The actual ``Replay-Nonce`` header value is appended by
    ``_AcmeHeaderMiddleware`` so that a single nonce is issued per response.
    """
    return Response(status_code=200)


@router.post("/acme/new-nonce")
async def new_nonce_post() -> Response:
    """Respond to POST /acme/new-nonce (RFC 8555 §7.2).

    Same as the HEAD variant — middleware attaches the nonce header.
    """
    return Response(status_code=204)

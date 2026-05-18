"""GET /directory — returns the ACME directory object (RFC 8555 §7.1.1)."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from jackdaw.config import get_settings
from jackdaw.schemas.acme import DirectoryMeta, DirectoryResponse

router = APIRouter()


@router.get("/directory", response_model=DirectoryResponse)
async def get_directory() -> JSONResponse:
    """Return the ACME directory listing all endpoint URLs.

    This endpoint requires no authentication and no nonce.
    """
    settings = get_settings()
    base = settings.relay_base_url
    body = DirectoryResponse(
        newNonce=f"{base}/acme/new-nonce",
        newAccount=f"{base}/acme/new-account",
        newOrder=f"{base}/acme/new-order",
        revokeCert=f"{base}/acme/revoke-cert",
        keyChange=f"{base}/acme/key-change",
        meta=DirectoryMeta(
            termsOfService=f"{base}/acme/terms",
        ),
    )
    return JSONResponse(content=body.model_dump(exclude_none=True))

"""POST /acme/cert/{id} — download an issued PEM certificate chain (POST-as-GET)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from jackdaw.db.engine import get_db
from jackdaw.services.jws import verify_jws
from jackdaw.services.ownership import require_cert_owner

router = APIRouter()

_DB = Annotated[AsyncSession, Depends(get_db)]


@router.post("/acme/cert/{cert_id}")
async def download_cert(cert_id: str, request: Request, db: _DB) -> Response:
    """Return the PEM certificate chain for *cert_id* (RFC 8555 §7.4.2).

    RFC 8555 §6.3 requires POST-as-GET (POST with empty JWS payload) for
    resource fetches.
    """
    _, account_id = await verify_jws(request, db)
    cert = await require_cert_owner(db, cert_id, account_id)
    return Response(
        content=cert.pem_chain,
        media_type="application/pem-certificate-chain",
    )

"""GET /acme/terms — terms of service page (RFC 8555 §7.1.1 meta.termsOfService)."""

from fastapi import APIRouter
from fastapi.responses import Response

router = APIRouter()

_TERMS_BODY = (
    "Jackdaw ACME Relay — Terms of Service\n"
    "\n"
    "This relay issues publicly trusted TLS certificates via Let's Encrypt on behalf\n"
    "of internal ACME clients.  By using this relay you agree to Let's Encrypt's\n"
    "Subscriber Agreement (https://letsencrypt.org/repository/) and Acceptable Use\n"
    "Policy.  The relay operator accepts no liability for misuse.\n"
    "\n"
    "Certificates are subject to Let's Encrypt rate limits.  The relay validates\n"
    "domain control via HTTP-01 before forwarding requests to Let's Encrypt.\n"
)


@router.get("/acme/terms")
async def terms_of_service() -> Response:
    """Return the relay terms of service document."""
    return Response(content=_TERMS_BODY, media_type="text/plain; charset=utf-8")

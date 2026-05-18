"""Dynamic DNS provider loader.

Adding a new provider requires only two changes:
1. Create ``src/jackdaw/dns/providers/<name>.py`` implementing ``DNSProvider``.
2. Add one entry to ``_REGISTRY`` below.
"""

import importlib

from jackdaw.dns.base import DNSProvider

# Maps the DNS_PROVIDER env-var value to a fully-qualified class path.
_REGISTRY: dict[str, str] = {
    "porkbun":    "jackdaw.dns.providers.porkbun.PorkbunDNSProvider",
    "cloudflare": "jackdaw.dns.providers.cloudflare.CloudflareDNSProvider",
    "null":       "jackdaw.dns.providers.null.NullDNSProvider",
}


def get_provider(name: str) -> DNSProvider:
    """Instantiate and return the DNS provider identified by *name*.

    Each provider reads its own credentials from the environment in
    ``__init__``, so only the selected provider ever loads its env vars.

    Args:
        name: Value of ``DNS_PROVIDER`` (e.g. ``"porkbun"``).

    Returns:
        An initialised ``DNSProvider`` instance.

    Raises:
        ValueError: The provider name is not registered.
    """
    if name not in _REGISTRY:
        raise ValueError(f"Unknown DNS provider: {name!r}. Available: {sorted(_REGISTRY)}")
    module_path, class_name = _REGISTRY[name].rsplit(".", 1)
    module = importlib.import_module(module_path)
    cls: type[DNSProvider] = getattr(module, class_name)
    return cls()

"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All runtime configuration; every field maps 1-to-1 to an env var."""

    # --- Required ---
    dns_provider: str
    relay_domain: str
    acme_email: str

    # --- Optional with defaults ---
    le_directory: str = "https://acme-v02.api.letsencrypt.org/directory"
    dns_propagation_wait: int = 30
    database_url: str = "sqlite+aiosqlite:///data/relay.db"
    le_account_key_path: str = "/data/le_account.key"
    ssl_dir: str = "/data/ssl"
    nonce_ttl: int = 600  # seconds; 10 minutes
    log_level: str = "INFO"
    # Comma-separated base domains; empty string means no extra restriction (proof is the gate).
    allowed_domains: str = ""
    # Set to False when pointing at Pebble (self-signed TLS) or other test CAs.
    le_verify_ssl: bool = True
    # HTTP-01 challenge validation settings.
    challenge_http_port: int = 80
    challenge_timeout: int = 5   # seconds per attempt
    challenge_retries: int = 3
    challenge_retry_delay: int = 2  # seconds between retries

    model_config = {"env_file": ".env", "case_sensitive": False, "extra": "ignore"}

    @property
    def relay_base_url(self) -> str:
        """Full base URL for building ACME endpoint URLs.

        If ``relay_domain`` already contains a scheme (e.g. for local dev:
        ``http://host.docker.internal:8000``) it is used as-is.  Otherwise
        ``https://`` is prepended (normal production / Docker use).
        """
        if self.relay_domain.startswith(("http://", "https://")):
            return self.relay_domain.rstrip("/")
        return f"https://{self.relay_domain}"

    @property
    def allowed_domain_list(self) -> list[str]:
        """Return *allowed_domains* parsed into a list (empty → no restriction)."""
        if not self.allowed_domains:
            return []
        return [d.strip() for d in self.allowed_domains.split(",") if d.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return the cached Settings singleton."""
    return Settings()

"""Application settings, read from environment variables.

Every variable uses the ``EXPENSES_`` prefix, for example ``EXPENSES_WEB_CLIENT_SECRET``.
Secrets have no default, so the app refuses to start when one is missing.
"""

from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configuration the application needs.

    Keycloak is reached through two addresses:

    * ``keycloak_public_url``: what the **browser** uses (login and logout pages).
      Tokens carry this address as their issuer.
    * ``keycloak_internal_url``: what the **app server** uses inside Docker
      (exchanging codes for tokens, downloading signing keys).
    """

    model_config = SettingsConfigDict(env_prefix="EXPENSES_", env_file=".env", extra="ignore")

    keycloak_public_url: str = "http://localhost:8080"
    keycloak_internal_url: str = "http://keycloak:8080"
    keycloak_realm: str = "greenfield"

    web_client_id: str = "expense-web"
    web_client_secret: SecretStr
    api_audience: str = "expense-api"

    app_base_url: str = "http://localhost:8000"
    session_secret_key: SecretStr
    session_cookie_name: str = "expenses_session"
    session_lifetime_seconds: int = 3600
    session_cookie_secure: bool = False

    @field_validator("keycloak_public_url", "keycloak_internal_url", "app_base_url")
    @classmethod
    def remove_trailing_slash(cls, url: str) -> str:
        """Store base URLs without a trailing slash so paths can be appended safely."""
        return url.rstrip("/")

    @property
    def issuer(self) -> str:
        """Expected ``iss`` claim of every Keycloak token for this realm."""
        return f"{self.keycloak_public_url}/realms/{self.keycloak_realm}"

    @property
    def _internal_oidc_base(self) -> str:
        return f"{self.keycloak_internal_url}/realms/{self.keycloak_realm}/protocol/openid-connect"

    @property
    def _public_oidc_base(self) -> str:
        return f"{self.issuer}/protocol/openid-connect"

    @property
    def authorization_endpoint(self) -> str:
        """Keycloak login page the browser is redirected to."""
        return f"{self._public_oidc_base}/auth"

    @property
    def end_session_endpoint(self) -> str:
        """Keycloak logout page the browser is redirected to."""
        return f"{self._public_oidc_base}/logout"

    @property
    def token_endpoint(self) -> str:
        """Server-to-server endpoint that exchanges a code for tokens."""
        return f"{self._internal_oidc_base}/token"

    @property
    def jwks_uri(self) -> str:
        """Server-to-server endpoint that publishes Keycloak's public signing keys."""
        return f"{self._internal_oidc_base}/certs"

    @property
    def redirect_uri(self) -> str:
        """Where Keycloak sends the browser back after login. Must match the Keycloak client."""
        return f"{self.app_base_url}/auth/callback"

    @property
    def post_logout_redirect_uri(self) -> str:
        """Where Keycloak sends the browser after logout. Must match the Keycloak client."""
        return f"{self.app_base_url}/"


@lru_cache
def get_settings() -> Settings:
    """Return the settings, loaded once and reused for the life of the process."""
    return Settings()

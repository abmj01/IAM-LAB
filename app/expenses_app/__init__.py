"""Greenfield expense claims application.

A FastAPI service with two parts:

* **Web**: employees log in through Keycloak (OIDC Authorization Code + PKCE).
  Tokens stay on the server; the browser only holds a session cookie.
* **API**: ``/api/...`` endpoints that accept Keycloak access tokens meant for
  the ``expense-api`` audience and authorize requests by role.
"""

__version__ = "0.1.0"

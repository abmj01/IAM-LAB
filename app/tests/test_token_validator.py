"""Tests for TokenValidator: one accepted token, and every way a token must be refused."""

import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import serialization
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from expenses_app.auth.token_validator import TokenClaims, TokenValidationError, TokenValidator
from tests.jwt_helpers import TEST_KEY_ID, encode_bytes, encode_segment


def test_valid_token_returns_claims(validator, make_token, valid_claims):
    claims = validator.validate(make_token(valid_claims))

    assert isinstance(claims, TokenClaims)
    assert claims.subject == valid_claims["sub"]
    assert claims.username == "ryan.landry"
    assert claims.has_role("employee")


def test_only_roles_for_this_api_are_returned(validator, make_token, valid_claims):
    claims = validator.validate(make_token(valid_claims))

    assert claims.roles == ("employee",)
    assert not claims.has_role("admin"), "Grafana's role must not leak into this API"


def test_token_without_roles_for_this_api_has_no_roles(validator, make_token, valid_claims):
    valid_claims["resource_access"] = {"grafana": {"roles": ["admin"]}}

    assert validator.validate(make_token(valid_claims)).roles == ()


def test_slightly_expired_token_is_accepted_within_leeway(validator, make_token, valid_claims):
    valid_claims["exp"] = valid_claims["iat"] - 10

    assert validator.validate(make_token(valid_claims)).username == "ryan.landry"


@pytest.mark.parametrize(
    ("description", "claim_changes"),
    [
        ("expired", {"exp": 1, "iat": 0}),
        ("audience of another app", {"aud": "grafana"}),
        ("issued by another realm", {"iss": "http://evil.example/realms/greenfield"}),
        ("missing subject", {"sub": None}),
        ("missing expiry", {"exp": None}),
    ],
)
def test_token_with_bad_claims_is_rejected(
    validator, make_token, valid_claims, description, claim_changes
):
    for claim_name, new_value in claim_changes.items():
        if new_value is None:
            valid_claims.pop(claim_name)
        else:
            valid_claims[claim_name] = new_value

    with pytest.raises(TokenValidationError):
        validator.validate(make_token(valid_claims))


def test_token_signed_by_untrusted_key_is_rejected(
    validator, make_token, valid_claims, attacker_key
):
    with pytest.raises(TokenValidationError):
        validator.validate(make_token(valid_claims, key=attacker_key))


def test_token_with_unknown_key_id_is_rejected(validator, make_token, valid_claims):
    with pytest.raises(TokenValidationError) as caught:
        validator.validate(make_token(valid_claims, key_id="attacker-key"))

    assert isinstance(caught.value.__cause__, PyJWKClientError)


def test_tampered_payload_is_rejected(validator, make_token, valid_claims):
    header, _, signature = make_token(valid_claims).split(".")
    valid_claims["resource_access"]["expense-api"]["roles"] = ["finance-approver"]
    forged_payload = encode_segment(valid_claims)

    with pytest.raises(TokenValidationError):
        validator.validate(f"{header}.{forged_payload}.{signature}")


def test_unsigned_alg_none_token_is_rejected(validator, valid_claims):
    unsigned_token = (
        f"{encode_segment({'alg': 'none', 'kid': TEST_KEY_ID})}.{encode_segment(valid_claims)}."
    )

    with pytest.raises(TokenValidationError):
        validator.validate(unsigned_token)


def test_hs256_token_signed_with_public_key_is_rejected(validator, valid_claims, signing_key):
    """Algorithm confusion: the attacker uses our *public* key as an HMAC secret."""
    public_key_pem = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signing_input = (
        f"{encode_segment({'alg': 'HS256', 'kid': TEST_KEY_ID})}.{encode_segment(valid_claims)}"
    )
    signature = hmac.new(public_key_pem, signing_input.encode(), hashlib.sha256).digest()
    forged_token = f"{signing_input}.{encode_bytes(signature)}"

    with pytest.raises(TokenValidationError):
        validator.validate(forged_token)


@pytest.mark.parametrize("raw_token", ["", "not-a-jwt", "a.b.c"])
def test_malformed_input_is_rejected(validator, raw_token):
    with pytest.raises(TokenValidationError):
        validator.validate(raw_token)


def test_rejection_keeps_original_error_for_logging(validator, make_token, valid_claims):
    valid_claims["aud"] = "grafana"

    with pytest.raises(TokenValidationError) as caught:
        validator.validate(make_token(valid_claims))

    assert isinstance(caught.value.__cause__, InvalidTokenError)


def test_production_validator_uses_keycloak_jwks_address(settings):
    validator = TokenValidator(settings)

    assert validator._signing_key_client.uri == settings.jwks_uri

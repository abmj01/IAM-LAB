"""Small helpers for building JWT pieces by hand, used to craft malicious test tokens."""

import base64
import json
from typing import Any

TEST_KEY_ID = "test-key"


def encode_bytes(raw_bytes: bytes) -> str:
    """Base64url-encode bytes without padding, as JWT segments are encoded."""
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode()


def encode_segment(data: dict[str, Any]) -> str:
    """Base64url-encode a JSON object as a JWT header or payload segment."""
    return encode_bytes(json.dumps(data).encode())

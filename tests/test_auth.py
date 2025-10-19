"""Tests for the authentication helpers."""
from __future__ import annotations

import base64
import json
import re

from app.auth import AuthService, EnvironmentConfig


def _decode_segment(segment: str) -> dict[str, object]:
    padding = "=" * (-len(segment) % 4)
    decoded = base64.urlsafe_b64decode(segment + padding)
    return json.loads(decoded.decode("utf-8"))


def test_obtain_jwt_generates_compact_token() -> None:
    env = EnvironmentConfig(
        name="demo",
        label="Démo",
        audience="demo",
        token_url="https://demo",
    )
    service = AuthService([env])

    token = service.obtain_jwt("client", "secret", "demo")

    assert re.fullmatch(r"^[^.]+\.[^.]+\.[^.]+$", token)


def test_obtain_jwt_includes_environment_data() -> None:
    env = EnvironmentConfig(
        name="demo",
        label="Démo",
        audience="demo",
        token_url="https://demo",
    )
    service = AuthService([env])

    token = service.obtain_jwt("client", "secret", "demo")

    header_segment, payload_segment, signature_segment = token.split(".")
    assert header_segment
    assert signature_segment

    payload = _decode_segment(payload_segment)
    assert payload["env"] == "demo"
    assert payload["token_url"] == "https://demo"

"""Authentication utilities for the desktop JWT client."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable
import base64
import hashlib
import hmac
import json


@dataclass(frozen=True)
class EnvironmentConfig:
    """Configuration describing a target authentication environment."""

    name: str
    label: str
    audience: str
    token_url: str


class AuthService:
    """Service responsible for issuing JWTs for configured environments.

    In a production scenario this class would make an HTTP call to the
    environment-specific token URL. For the sake of this example we simulate the
    token generation locally using HMAC-SHA256 so that the interface remains
    functional without external dependencies.
    """

    def __init__(self, environments: Iterable[EnvironmentConfig]):
        env_dict: Dict[str, EnvironmentConfig] = {
            env.name: env for env in environments
        }
        if not env_dict:
            raise ValueError("At least one environment must be provided")
        self._environments = env_dict

    @property
    def environments(self) -> Dict[str, EnvironmentConfig]:
        """Return the environments indexed by their internal name."""

        return dict(self._environments)

    def obtain_jwt(self, client_id: str, client_secret: str, env_name: str) -> str:
        """Return a signed JWT for the specified environment.

        Parameters
        ----------
        client_id:
            Identifier assigned to the OAuth client.
        client_secret:
            Secret associated with the OAuth client.
        env_name:
            Name of the target environment as defined in the configuration.

        Raises
        ------
        KeyError
            If the supplied environment is not registered.
        ValueError
            If any required field is empty.
        """

        if not client_id:
            raise ValueError("Le clientId est requis")
        if not client_secret:
            raise ValueError("Le clientSecret est requis")
        if env_name not in self._environments:
            raise KeyError(env_name)

        environment = self._environments[env_name]
        issued_at = datetime.now(timezone.utc)
        payload = {
            "iss": client_id,
            "aud": environment.audience,
            "iat": int(issued_at.timestamp()),
            "exp": int((issued_at + timedelta(minutes=5)).timestamp()),
            "env": environment.name,
            "token_url": environment.token_url,
        }
        header = {"alg": "HS256", "typ": "JWT"}
        return _encode_jwt(header, payload, client_secret)


def _encode_jwt(header: Dict[str, str], payload: Dict[str, object], secret: str) -> str:
    """Create a compact JWT string signed with HS256 using *secret*."""

    if not secret:
        raise ValueError("Le secret ne peut pas être vide")

    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_segment = _b64url(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256)
    signature_segment = _b64url(signature.digest())
    return f"{header_segment}.{payload_segment}.{signature_segment}"


def _b64url(data: bytes) -> str:
    """Return base64 url-safe encoding without padding."""

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


DEFAULT_ENVIRONMENTS = (
    EnvironmentConfig(
        name="dev",
        label="Développement",
        audience="https://api.dev.example.com",
        token_url="https://auth.dev.example.com/oauth/token",
    ),
    EnvironmentConfig(
        name="staging",
        label="Recette",
        audience="https://api.staging.example.com",
        token_url="https://auth.staging.example.com/oauth/token",
    ),
    EnvironmentConfig(
        name="prod",
        label="Production",
        audience="https://api.example.com",
        token_url="https://auth.example.com/oauth/token",
    ),
)

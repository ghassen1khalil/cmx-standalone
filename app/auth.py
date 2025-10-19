"""Authentication utilities for the desktop JWT client."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable
import base64
import hashlib
import hmac
import json
import requests


@dataclass(frozen=True)
class EnvironmentConfig:
    """Configuration describing a target authentication environment."""

    name: str
    label: str
    token_url: str
    cmxCoreApi: str


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
        
        # Préparation des données pour l'appel au webservice
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {base64.b64encode(f"{client_id}:{client_secret}".encode("ascii")).decode("ascii")}'
        }
        
        data = {
            'grant_type': 'client_credentials',
            'scope': 'cmx_business'
        }
        
        try:
            response = requests.post(
                environment.token_url,
                headers=headers,
                data=data
            )
            response.raise_for_status()
            return response.json()['access_token']
        except requests.RequestException as e:
            raise ValueError(f"Erreur lors de l'appel au service d'authentification: {str(e)}")


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


class CMXService:
    """Service pour interagir avec l'API CMX Core."""

    def __init__(self, environment: EnvironmentConfig):
        self._environment = environment

    def get_documents(self, jwt: str, profile: str, enduser: str, store_id: str) -> Dict:
        """Récupère les documents via l'API CMX Core.

        Parameters
        ----------
        jwt : str
            Le jeton JWT pour l'authentification
        profile : str
            Le profil CMX à utiliser
        enduser : str
            L'utilisateur CMX
        store_id : str
            L'ID du store CMX

        Returns
        -------
        Dict
            La réponse du service

        Raises
        ------
        requests.RequestException
            Si une erreur se produit lors de l'appel au service
        """
        headers = {
            'Authorization': f'Bearer {jwt}',
            'Accept': 'application/octet-stream, application/json',
            'cmx-enduser': enduser,
            'cmx-profile': profile,
            'cmx-store-id': store_id
        }

        url = f"{self._environment.cmxCoreApi}/v2/thor/core/documents"
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


def is_jwt_valid(token: str | None) -> bool:
    """Vérifie si le JWT est valide et non expiré.

    Parameters
    ----------
    token : str | None
        Le JWT à vérifier

    Returns
    -------
    bool
        True si le token est valide et non expiré, False sinon
    """
    if not token:
        return False
    try:
        # Décode la partie payload du JWT
        payload_part = token.split('.')[1]
        # Ajoute le padding nécessaire
        padding = '=' * (-len(payload_part) % 4)
        payload_bytes = base64.b64decode(payload_part + padding)
        payload = json.loads(payload_bytes)
        
        # Vérifie l'expiration
        exp_timestamp = payload.get('exp')
        if not exp_timestamp:
            return False
        
        current_timestamp = int(datetime.now(timezone.utc).timestamp())
        return current_timestamp < exp_timestamp
    except (IndexError, json.JSONDecodeError, TypeError):
        return False


DEFAULT_ENVIRONMENTS = (
    EnvironmentConfig(
        name="Staging",
        label="Recette",
        token_url="https://onelogin.stg.axa.com/as/token.oauth2",
        cmxCoreApi="https://cmx-eu.corp.intraxa",
    ),
    EnvironmentConfig(
        name="Production",
        label="Production",
        token_url="https://onelogin.axa.com/as/token.oauth2",
        cmxCoreApi="https://cmx-eu.corp.intraxa",
    ),
)

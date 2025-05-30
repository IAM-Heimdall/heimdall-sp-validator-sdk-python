# aif_sp_validator_sdk/validator.py
import jwt # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
import base64
import httpx
import logging
import time # For performance timing
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Any, Union
from urllib.parse import urljoin

from .models import ValidatedATKData, AIFValidatorConfig, JWKModel, RevocationStatus
from .cache import JWKSCache
from .exceptions import (
    AIFTokenValidationError, AIFRevokedTokenError, AIFSignatureError,
    AIFClaimError, AIFRegistryConnectionError, AIFConfigurationError,
    AIFNoMatchingKeyError, AIFTokenExpiredError, AIFTokenNotYetValidError,
    AIFMissingClaimError, AIFInvalidAudienceError, AIFInvalidIssuerError,
    AIFKeyConstructionError
)

logger = logging.getLogger(__name__)

class AIFTokenValidator:
    def __init__(self, config: AIFValidatorConfig):
        if not isinstance(config, AIFValidatorConfig):
            raise AIFConfigurationError("Invalid AIFValidatorConfig object provided.")
        self.config = config
        self.jwks_cache = JWKSCache(
            default_ttl_seconds=config.jwks_cache_ttl_seconds,
            fetch_timeout_seconds=config.jwks_fetch_timeout_seconds
        )
        logger.info(f"AIFTokenValidator initialized. Expected Audiences: {config.expected_sp_audiences}, Issuer: {config.expected_issuer_id}")

    def _construct_public_key_from_jwk(self, jwk_model: JWKModel) -> ed25519.Ed25519PublicKey:
        if jwk_model.kty == "OKP" and jwk_model.crv == "Ed25519" and jwk_model.x:
            try:
                # PyJWT needs padding for base64.urlsafe_b64decode if it's not standard length
                x_bytes = base64.urlsafe_b64decode(jwk_model.x + '=' * (-len(jwk_model.x) % 4))
                if len(x_bytes) != 32: # Ed25519 public key is 32 bytes
                    raise AIFKeyConstructionError(f"Invalid Ed25519 key length from JWK (kid: {jwk_model.kid}). Expected 32 bytes, got {len(x_bytes)}.")
                return ed25519.Ed25519PublicKey.from_public_bytes(x_bytes)
            except Exception as e:
                raise AIFKeyConstructionError(f"Error constructing Ed25519 public key from JWK (kid: {jwk_model.kid}): {e}", kid=jwk_model.kid) from e
        else: # Could add support for RSA/EC later if self.config.allowed_algorithms includes them
            raise AIFKeyConstructionError(f"JWK (kid: {jwk_model.kid}) is not a supported EdDSA key (kty: {jwk_model.kty}, crv: {jwk_model.crv}).", kid=jwk_model.kid, key_type=jwk_model.kty)


    async def _get_verification_key(self, atk_header: Dict[str, Any], atk_issuer: str) -> ed25519.Ed25519PublicKey:
        kid_from_atk = atk_header.get("kid")
        alg_from_atk = atk_header.get("alg")

        if alg_from_atk not in self.config.allowed_algorithms:
            raise AIFClaimError(f"Unsupported ATK algorithm: {alg_from_atk}. Allowed: {self.config.allowed_algorithms}", claim_name="alg", actual=alg_from_atk)
        
        # For now, assume issuer in token directly maps to the base URL for JWKS
        # In a multi-issuer scenario, this would be more complex (e.g. discovery from REG)
        if atk_issuer != self.config.expected_issuer_id: # Strict check for single trusted issuer
            raise AIFInvalidIssuerError(expected_issuer=self.config.expected_issuer_id, actual_issuer=atk_issuer)

        jwks_url = urljoin(str(self.config.aif_core_service_url).rstrip('/') + '/', ".well-known/jwks.json")
        
        jwks_model = await self.jwks_cache.get_jwks(jwks_url) # Raises AIFRegistryConnectionError or AIFJWKSError

        matching_key_model: Optional[JWKModel] = None
        if kid_from_atk:
            for key_jwk in jwks_model.keys:
                if key_jwk.kid == kid_from_atk:
                    matching_key_model = key_jwk
                    break
            if not matching_key_model:
                raise AIFNoMatchingKeyError(f"Key with kid '{kid_from_atk}' not found in JWKS.", requested_kid=kid_from_atk, available_kids=[k.kid for k in jwks_model.keys if k.kid])
        elif len(jwks_model.keys) == 1:
            logger.debug("ATK header missing 'kid', using the single key from JWKS.")
            matching_key_model = jwks_model.keys[0]
        else:
            raise AIFMissingClaimError(claim_name="kid", message="ATK header missing 'kid' and multiple keys in JWKS. Cannot select key.")

        if matching_key_model.alg and matching_key_model.alg != alg_from_atk: # Check if key's alg matches token's alg
            raise AIFClaimError(f"Algorithm mismatch: ATK alg '{alg_from_atk}', JWK alg '{matching_key_model.alg}'.", claim_name="alg")

        return self._construct_public_key_from_jwk(matching_key_model)

    async def _check_revocation(self, jti: str):
        if not self.config.revocation_check_enabled:
            logger.debug(f"Revocation check disabled by configuration. Skipping for JTI: {jti}")
            return

        # Construct revocation URL based on core service URL
        revocation_api_path = f"/reg/revocation-status?jti={jti}" # Matches your IE+REG routes
        revocation_url = urljoin(str(self.config.aif_core_service_url).rstrip('/') + '/', revocation_api_path.lstrip('/'))
        
        logger.debug(f"Checking revocation for JTI '{jti}' at {revocation_url}")
        async with httpx.AsyncClient(timeout=self.config.revocation_check_timeout_seconds) as client:
            try:
                response = await client.get(revocation_url)
                response.raise_for_status()
                status_data = response.json()
                rev_status_model = RevocationStatus(**status_data)
                if rev_status_model.is_revoked:
                    logger.warning(f"ATK JTI '{jti}' IS REVOKED.")
                    raise AIFRevokedTokenError(jti=jti)
                logger.debug(f"ATK JTI '{jti}' is NOT revoked.")
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error checking revocation for JTI '{jti}': {e.response.status_code} - {e.response.text[:200]}")
                raise AIFRegistryConnectionError(f"Failed to check revocation (HTTP {e.response.status_code})", endpoint=revocation_url, status_code=e.response.status_code) from e
            except httpx.RequestError as e:
                logger.error(f"Request error checking revocation for JTI '{jti}': {e}")
                raise AIFRegistryConnectionError(f"Network error checking revocation", endpoint=revocation_url) from e
            except (ValueError, TypeError) as e: # Pydantic or JSON error
                logger.error(f"Error parsing revocation status response for JTI '{jti}': {e}")
                raise AIFRegistryConnectionError(f"Invalid revocation status format for JTI {jti}", endpoint=revocation_url) from e

    def _extract_user_id_from_aid(self, aid: str) -> Optional[str]:
        if not aid or not isinstance(aid, str) or not aid.startswith("aif://"):
            return None
        try:
            parts = aid.split('/')
            # aif://issuer_id/llm_id/user_id_or_pseudo/agent_instance_id
            # parts[0]="aif:", parts[1]="", parts[2]="issuer", parts[3]="llm", parts[4]="user", parts[5]="instance"
            if len(parts) == 6:
                return parts[4]
        except Exception: pass # Simple split might fail if format is unexpected
        logger.warning(f"Could not parse user_id from AID format: {aid}")
        return None

    async def verify_atk(self, atk_string: str) -> ValidatedATKData:
        validation_start_time = time.perf_counter()
        if not atk_string or not isinstance(atk_string, str):
            raise AIFTokenValidationError("ATK must be a non-empty string.")
        atk_string = atk_string.strip()

        try:
            unverified_header = jwt.get_unverified_header(atk_string)
        except jwt.InvalidTokenError as e:
            raise AIFTokenValidationError(f"Malformed ATK (header parse failed): {e}") from e

        try:
            # Get issuer from unverified payload
            unverified_payload_for_iss = jwt.decode(atk_string, options={"verify_signature": False, "verify_exp": False, "verify_aud": False, "verify_iss": False})
            atk_issuer = unverified_payload_for_iss.get("iss")
            if not atk_issuer:
                raise AIFMissingClaimError(claim_name="iss", message="ATK 'iss' claim is missing.")

            public_key_obj = await self._get_verification_key(unverified_header, atk_issuer)
            
            # Convert key to PEM format for PyJWT compatibility
            key_pem = public_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            payload = jwt.decode(
                atk_string,
                key=key_pem,  # Use PEM format instead of cryptography object
                algorithms=self.config.allowed_algorithms,
                audience=self.config.expected_sp_audiences,
                issuer=self.config.expected_issuer_id,
                leeway=timedelta(seconds=self.config.clock_skew_seconds),
                options={
                    "verify_exp": True, "verify_nbf": True, "verify_iat": True,
                    "verify_aud": True, "verify_iss": True,
                    "require": ["exp", "iat", "iss", "aud", "sub"] + (["jti"] if self.config.require_jti else [])
                }
            )
        except jwt.ExpiredSignatureError as e: raise AIFTokenExpiredError(actual=getattr(e, 'expired', None)) from e
        except jwt.InvalidAudienceError as e: raise AIFInvalidAudienceError(expected_audiences=self.config.expected_sp_audiences, actual_audience=getattr(e, 'audience', None)) from e
        except jwt.InvalidIssuerError as e: raise AIFInvalidIssuerError(expected_issuer=self.config.expected_issuer_id, actual_issuer=getattr(e, 'issuer', None)) from e
        except jwt.InvalidSignatureError as e: raise AIFSignatureError(f"Invalid token signature: {e}") from e
        except jwt.MissingRequiredClaimError as e: raise AIFMissingClaimError(claim_name=str(e).split("'")[1] if "'" in str(e) else "unknown") from e
        except jwt.ImmatureSignatureError as e: raise AIFTokenNotYetValidError(actual=getattr(e, 'actual', None)) from e
        except jwt.InvalidTokenError as e: raise AIFTokenValidationError(f"Invalid ATK: {e}") from e
        
        jti = payload.get("jti")
        if self.config.require_jti and not jti:
            raise AIFMissingClaimError(claim_name="jti")
        if jti: 
            await self._check_revocation(jti)

        aid_subject = payload.get("sub", "")
        user_id_from_aid = self._extract_user_id_from_aid(aid_subject)

        validation_duration_ms = (time.perf_counter() - validation_start_time) * 1000
        logger.info(f"ATK validated successfully for AID: {aid_subject} in {validation_duration_ms:.2f} ms")

        return ValidatedATKData(
            aid=aid_subject, user_id_from_aid=user_id_from_aid,
            issuer=payload["iss"], audience=payload["aud"], jti=jti,
            permissions=payload.get("permissions", []), purpose=payload.get("purpose"),
            aif_trust_tags=payload.get("aif_trust_tags"),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            issued_at=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
            not_before=datetime.fromtimestamp(payload["nbf"], tz=timezone.utc) if "nbf" in payload else None,
            raw_payload=payload,
            validation_duration_ms=validation_duration_ms
        )
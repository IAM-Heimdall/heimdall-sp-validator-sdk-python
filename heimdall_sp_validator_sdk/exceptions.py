# aif_sp_validator_sdk/exceptions.py
from typing import Optional, Any, Dict, List, Union
from datetime import datetime

class AIFSDKBaseException(Exception):
    """Base exception for all AIF SDK errors."""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.context = context or {}
    def __str__(self) -> str:
        base = super().__str__()
        if self.context: return f"{base} (Context: {self.context})"
        return base

class AIFConfigurationError(AIFSDKBaseException):
    """Raised when SDK configuration is invalid or incomplete."""
    pass

class AIFTokenValidationError(AIFSDKBaseException):
    """Base class for token validation failures."""
    def __init__(self, message: str, claim_name: Optional[str] = None, 
                 expected: Any = None, actual: Any = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, context)
        self.claim_name = claim_name
        self.expected = expected
        self.actual = actual

class AIFSignatureError(AIFTokenValidationError):
    """Raised when token signature verification fails."""
    def __init__(self, message: str = "Token signature is invalid.", **kwargs):
        super().__init__(message, **kwargs)

class AIFTokenExpiredError(AIFTokenValidationError):
    """Raised when token has expired."""
    def __init__(self, message: str = "Token has expired.", claim_name: str = "exp", actual: Optional[datetime] = None, **kwargs):
        super().__init__(message, claim_name=claim_name, actual=actual, **kwargs)

class AIFTokenNotYetValidError(AIFTokenValidationError):
    """Raised when token is not yet valid (nbf claim)."""
    def __init__(self, message: str = "Token is not yet valid.", claim_name: str = "nbf", actual: Optional[datetime] = None, **kwargs):
        super().__init__(message, claim_name=claim_name, actual=actual, **kwargs)

class AIFClaimError(AIFTokenValidationError):
    """Raised when a specific claim validation fails (e.g., wrong format, value)."""
    pass

class AIFMissingClaimError(AIFClaimError):
    """Raised when a required claim is missing from the token."""
    def __init__(self, claim_name: str, message: Optional[str] = None, **kwargs):
        super().__init__(message or f"Required claim '{claim_name}' is missing.", claim_name=claim_name, **kwargs)

class AIFInvalidAudienceError(AIFClaimError):
    """Raised when token audience doesn't match expected values."""
    def __init__(self, expected_audiences: Union[str, List[str]], actual_audience: Any, **kwargs):
        super().__init__("Invalid token audience.", claim_name="aud", expected=expected_audiences, actual=actual_audience, **kwargs)

class AIFInvalidIssuerError(AIFClaimError):
    """Raised when token issuer is not trusted or doesn't match expected."""
    def __init__(self, expected_issuer: str, actual_issuer: Any, **kwargs):
        super().__init__("Invalid token issuer.", claim_name="iss", expected=expected_issuer, actual=actual_issuer, **kwargs)

class AIFRevokedTokenError(AIFTokenValidationError):
    """Raised when token has been revoked."""
    def __init__(self, message: str = "Token has been revoked.", jti: Optional[str] = None, **kwargs):
        super().__init__(message, claim_name="jti", actual=jti, **kwargs)
        self.jti = jti

class AIFRegistryConnectionError(AIFSDKBaseException):
    """Raised when unable to connect to or get valid data from AIF registry services."""
    def __init__(self, message: str, endpoint: Optional[str] = None, status_code: Optional[int] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.endpoint = endpoint
        self.status_code = status_code

class AIFNoMatchingKeyError(AIFSDKBaseException):
    """Raised when no matching key found in JWKS for token verification."""
    def __init__(self, message: str, requested_kid: Optional[str] = None, available_kids: Optional[List[Optional[str]]] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.requested_kid = requested_kid
        self.available_kids = available_kids or []

class AIFKeyConstructionError(AIFSDKBaseException):
    """Raised when unable to construct a cryptographic key from JWK data."""
    def __init__(self, message: str, kid: Optional[str] = None, key_type: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.kid = kid
        self.key_type = key_type

class AIFJWKSError(AIFSDKBaseException):
    """Raised when JWKS format is invalid or cannot be parsed."""
    def __init__(self, message: str, jwks_url: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.jwks_url = jwks_url

class AIFTimeoutError(AIFRegistryConnectionError): # Inherits from ConnectionError
    """Raised when HTTP operations timeout."""
    def __init__(self, message: str, operation: Optional[str] = None, timeout_seconds: Optional[float] = None, **kwargs):
        super().__init__(message, **kwargs) # Pass message to base
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        # Update context if needed
        self.context.update({"operation": operation, "timeout_seconds": timeout_seconds})


# This exception might be raised by the SP application using the SDK, not the SDK itself directly,
# but it's good to have it defined as part of the AIF ecosystem.
class AIFPermissionError(AIFTokenValidationError):
    """Raised when validated token permissions are insufficient for the requested operation."""
    def __init__(self, message: str, required_permissions: Optional[List[str]] = None, token_permissions: Optional[List[str]] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.required_permissions = required_permissions or []
        self.token_permissions = token_permissions or []
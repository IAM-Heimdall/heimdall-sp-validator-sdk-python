# aif_sp_validator_sdk/__init__.py
"""
AIF Service Provider Validator SDK
Provides tools for Service Providers to validate Agent Tokens (ATKs)
issued by a NeuProtocol AIF compliant Issuing Entity.
"""

from .validator import AIFTokenValidator
from .models import ValidatedATKData, AIFValidatorConfig, AudienceType, PermissionsList, TrustTagsDict
from .exceptions import (
    AIFSDKBaseException, # Base for users to catch all SDK errors
    AIFConfigurationError,
    AIFTokenValidationError, # General token validation error
    AIFTokenExpiredError,
    AIFTokenNotYetValidError,
    AIFSignatureError,
    AIFClaimError,
    AIFMissingClaimError,
    AIFInvalidAudienceError,
    AIFInvalidIssuerError,
    AIFRevokedTokenError,
    AIFRegistryConnectionError,
    AIFNoMatchingKeyError,
    AIFKeyConstructionError,
    AIFJWKSError,
    AIFTimeoutError,
    AIFPermissionError # If SDK does permission checking in future
)

__version__ = "0.1.0" # Start with a realistic initial version

__all__ = [
    "AIFTokenValidator",
    "ValidatedATKData",
    "AIFValidatorConfig",
    "AudienceType", 
    "PermissionsList", 
    "TrustTagsDict",
    "AIFSDKBaseException",
    "AIFConfigurationError",
    "AIFTokenValidationError",
    "AIFTokenExpiredError",
    "AIFTokenNotYetValidError",
    "AIFSignatureError",
    "AIFClaimError",
    "AIFMissingClaimError",
    "AIFInvalidAudienceError",
    "AIFInvalidIssuerError",
    "AIFRevokedTokenError",
    "AIFRegistryConnectionError",
    "AIFNoMatchingKeyError",
    "AIFKeyConstructionError",
    "AIFJWKSError",
    "AIFTimeoutError",
    "AIFPermissionError",
    "__version__"
]
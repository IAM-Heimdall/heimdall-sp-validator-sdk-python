# aif_sp_validator_sdk/models.py
from pydantic import BaseModel, Field, HttpUrl, field_validator, ConfigDict
from typing import List, Dict, Optional, Union, Any
from datetime import datetime, timezone
import os

# Type aliases for convenience and clarity
AudienceType = Union[str, List[str]]
PermissionsList = List[str]
TrustTagsDict = Dict[str, str]

class AIFValidatorConfig(BaseModel):
    """Configuration for the AIFTokenValidator."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")
    
    aif_core_service_url: HttpUrl = Field(..., description="Base URL of the AIF Core Service (IE+REG).")
    expected_sp_audiences: AudienceType = Field(..., min_length=1, description="Audience ID or list of Audience IDs this SP accepts.")
    expected_issuer_id: str = Field(..., min_length=1, description="The 'iss' claim value of the trusted AIF Issuing Entity.")
    
    jwks_cache_ttl_seconds: int = Field(default=24 * 60 * 60, gt=0, description="Cache TTL for JWKS in seconds.")
    jwks_fetch_timeout_seconds: int = Field(default=10, gt=0, le=60, description="Timeout for fetching JWKS.")
    
    revocation_check_enabled: bool = Field(default=True, description="Enable/disable revocation status checking.")
    revocation_check_timeout_seconds: int = Field(default=5, gt=0, le=30, description="Timeout for revocation status check.")
    # Retries are good but might be a v0.2 feature for simplicity if not strictly needed by users yet
    # revocation_check_retries: int = Field(default=1, ge=0, le=3, description="Number of retries for revocation check.")

    allowed_algorithms: List[str] = Field(default=["EdDSA"], min_length=1, description="List of accepted JWT signature algorithms.")
    clock_skew_seconds: int = Field(default=60, ge=0, le=600, description="Allowed clock skew in seconds for 'exp' and 'nbf' validation.")
    require_jti: bool = Field(default=True, description="If True, ATK must contain a 'jti' claim for revocation checking.")

    @field_validator('aif_core_service_url', mode='before')
    @classmethod
    def _validate_url_str(cls, v): return str(v)

    @field_validator('expected_sp_audiences', mode='before')
    @classmethod
    def _ensure_audience_list(cls, v):
        if isinstance(v, str):
            v_stripped = v.strip()
            if not v_stripped: raise ValueError("Audience string cannot be empty.")
            return [v_stripped]
        if isinstance(v, list):
            cleaned = [str(aud).strip() for aud in v if str(aud).strip()]
            if not cleaned: raise ValueError("Expected SP audiences list cannot be empty or contain only empty strings.")
            return cleaned
        raise TypeError("Expected SP audiences must be a string or a list of strings.")

    @classmethod
    def from_env(cls, **overrides: Any) -> 'AIFValidatorConfig':
        """Creates configuration from environment variables, with overrides."""
        env_audiences = os.getenv('AIF_SP_EXPECTED_AUDIENCES', '')
        
        config_data = {
            'aif_core_service_url': os.getenv('AIF_CORE_SERVICE_URL'),
            'expected_sp_audiences': [aud.strip() for aud in env_audiences.split(',') if aud.strip()] if env_audiences else None,
            'expected_issuer_id': os.getenv('AIF_EXPECTED_ISSUER_ID'),
            'jwks_cache_ttl_seconds': int(os.getenv('AIF_JWKS_CACHE_TTL_SECONDS', str(24 * 60 * 60))),
            'jwks_fetch_timeout_seconds': int(os.getenv('AIF_JWKS_FETCH_TIMEOUT_SECONDS', '10')),
            'revocation_check_enabled': os.getenv('AIF_REVOCATION_CHECK_ENABLED', 'true').lower() == 'true',
            'revocation_check_timeout_seconds': int(os.getenv('AIF_REVOCATION_TIMEOUT_SECONDS', '5')),
            # 'revocation_check_retries': int(os.getenv('AIF_REVOCATION_CHECK_RETRIES', '1')),
            'allowed_algorithms': [alg.strip() for alg in os.getenv('AIF_ALLOWED_ALGORITHMS', 'EdDSA').split(',')],
            'clock_skew_seconds': int(os.getenv('AIF_CLOCK_SKEW_SECONDS', '60')),
            'require_jti': os.getenv('AIF_REQUIRE_JTI', 'true').lower() == 'true',
        }
        # Filter out None values from env defaults if they are not required or have model defaults
        filtered_config_data = {k: v for k, v in config_data.items() if v is not None}
        filtered_config_data.update(overrides) # Apply overrides last
        
        # Pydantic will raise validation error if required fields are still missing
        return cls(**filtered_config_data)


class JWKModel(BaseModel):
    model_config = ConfigDict(extra="allow") # Allow other standard JWK fields
    kty: str
    kid: Optional[str] = None
    use: Optional[str] = None
    alg: Optional[str] = None # Algorithm intended for use with this key
    crv: Optional[str] = None # For OKP (EdDSA) and EC
    x: Optional[str] = None   # For OKP (EdDSA) and EC (x-coordinate)
    y: Optional[str] = None   # For EC (y-coordinate)
    n: Optional[str] = None   # For RSA (modulus)
    e: Optional[str] = None   # For RSA (exponent)

class JWKSModel(BaseModel):
    keys: List[JWKModel] = Field(..., min_length=1)

class RevocationStatus(BaseModel): # As received from REG
    jti: str
    is_revoked: bool
    checked_at: datetime # Should be provided by REG, or SDK sets its own check time

class ValidatedATKData(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    is_valid: bool = True # Always true if this object is returned
    aid: str
    user_id_from_aid: Optional[str] = None
    issuer: str
    audience: AudienceType # Store what was matched from the token
    jti: str
    permissions: PermissionsList = Field(default_factory=list)
    purpose: Optional[str] = None
    aif_trust_tags: Optional[TrustTagsDict] = None
    expires_at: datetime
    issued_at: datetime
    not_before: Optional[datetime] = None
    raw_payload: Dict[str, Any] # The full decoded payload
    validation_duration_ms: Optional[float] = None
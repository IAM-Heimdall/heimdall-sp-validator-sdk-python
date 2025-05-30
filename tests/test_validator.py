import pytest
import asyncio
import jwt
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

from heimdall_sp_validator_sdk import (
    AIFTokenValidator,
    AIFValidatorConfig,
    ValidatedATKData,
    AIFTokenExpiredError,
    AIFRevokedTokenError,
    AIFInvalidAudienceError,
    AIFSignatureError,
    AIFRegistryConnectionError,
    AIFConfigurationError,
    AIFTokenValidationError
)


@pytest.fixture
def validator_config():
    """Basic validator configuration for testing."""
    return AIFValidatorConfig(
        aif_core_service_url="https://test.example.com",
        expected_sp_audiences=["test-audience"],
        expected_issuer_id="aif://test-issuer.example.com"
    )


@pytest.fixture
def ed25519_keypair():
    """Generate Ed25519 key pair for testing."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Get public key x coordinate for JWK
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    x_coordinate = base64.urlsafe_b64encode(public_bytes).decode().rstrip('=')
    
    return {
        "private_key": private_key,
        "public_key": public_key,
        "x_coordinate": x_coordinate
    }


@pytest.fixture
def mock_jwks(ed25519_keypair):
    """Mock JWKS response."""
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key-1",
                "alg": "EdDSA",
                "use": "sig",
                "x": ed25519_keypair["x_coordinate"]
            }
        ]
    }


@pytest.fixture
def valid_token_payload():
    """Valid token payload for testing."""
    now = datetime.now(timezone.utc)
    return {
        "iss": "aif://test-issuer.example.com",
        "sub": "aif://test-issuer.example.com/gpt-4/user-123/instance-456",
        "aud": ["test-audience"],
        "exp": now + timedelta(hours=1),
        "iat": now,
        "jti": "test-jti-123",
        "permissions": ["read:articles", "write:comments"],
        "purpose": "Test token validation",
        "aif_trust_tags": {"user_verification_level": "verified"}
    }


def create_test_token(payload, keypair, kid="test-key-1"):
    """Create a test JWT token."""
    headers = {
        "alg": "EdDSA",
        "kid": kid,
        "typ": "JWT"
    }
    
    # Convert datetime objects to timestamps
    if "exp" in payload and isinstance(payload["exp"], datetime):
        payload["exp"] = int(payload["exp"].timestamp())
    if "iat" in payload and isinstance(payload["iat"], datetime):
        payload["iat"] = int(payload["iat"].timestamp())
    if "nbf" in payload and isinstance(payload["nbf"], datetime):
        payload["nbf"] = int(payload["nbf"].timestamp())
    
    # Convert private key to PEM for PyJWT
    private_key_pem = keypair["private_key"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return jwt.encode(payload, private_key_pem, algorithm="EdDSA", headers=headers)


class TestAIFValidatorConfig:
    """Test configuration validation."""
    
    def test_valid_config(self):
        config = AIFValidatorConfig(
            aif_core_service_url="https://test.example.com",
            expected_sp_audiences=["test-audience"],
            expected_issuer_id="aif://test-issuer.example.com"
        )
        assert str(config.aif_core_service_url) == "https://test.example.com/"  # Add trailing slash
        assert config.expected_sp_audiences == ["test-audience"]
        assert config.expected_issuer_id == "aif://test-issuer.example.com"

    def test_config_from_env(self, monkeypatch):
        monkeypatch.setenv("AIF_CORE_SERVICE_URL", "https://env.example.com")
        monkeypatch.setenv("AIF_SP_EXPECTED_AUDIENCES", "env-audience1,env-audience2")
        monkeypatch.setenv("AIF_EXPECTED_ISSUER_ID", "aif://env-issuer.example.com")
        
        config = AIFValidatorConfig.from_env()
        assert str(config.aif_core_service_url) == "https://env.example.com/"  # Add trailing slash
        assert config.expected_sp_audiences == ["env-audience1", "env-audience2"]
        assert config.expected_issuer_id == "aif://env-issuer.example.com"
    
    def test_invalid_config(self):
        with pytest.raises(Exception):  # Pydantic validation error
            AIFValidatorConfig(
                aif_core_service_url="",
                expected_sp_audiences=[],
                expected_issuer_id=""
            )


class TestAIFTokenValidator:
    """Test the main validator class."""
    
    def test_validator_initialization(self, validator_config):
        validator = AIFTokenValidator(validator_config)
        assert validator.config == validator_config
        assert validator.jwks_cache is not None
    
    def test_invalid_config_type(self):
        with pytest.raises(AIFConfigurationError):
            AIFTokenValidator("invalid_config")
    
    @pytest.mark.asyncio
    async def test_valid_token_validation(self, validator_config, ed25519_keypair, mock_jwks, valid_token_payload):
        """Test successful token validation."""
        validator = AIFTokenValidator(validator_config)
        
        # Create valid token
        token = create_test_token(valid_token_payload, ed25519_keypair)
        
        # Mock JWKS fetch
        with patch.object(validator.jwks_cache, 'get_jwks', new_callable=AsyncMock) as mock_get_jwks:
            from heimdall_sp_validator_sdk.models import JWKSModel, JWKModel
            mock_jwks_model = JWKSModel(keys=[JWKModel(**mock_jwks["keys"][0])])
            mock_get_jwks.return_value = mock_jwks_model
            
            # Mock revocation check
            with patch.object(validator, '_check_revocation', new_callable=AsyncMock) as mock_revocation:
                mock_revocation.return_value = None
                
                result = await validator.verify_atk(token)
                
                assert isinstance(result, ValidatedATKData)
                assert result.aid == "aif://test-issuer.example.com/gpt-4/user-123/instance-456"
                assert result.user_id_from_aid == "user-123"
                assert result.issuer == "aif://test-issuer.example.com"
                assert result.audience == ["test-audience"]
                assert result.jti == "test-jti-123"
                assert result.permissions == ["read:articles", "write:comments"]
                assert result.purpose == "Test token validation"
    
    @pytest.mark.asyncio
    async def test_expired_token(self, validator_config, ed25519_keypair, mock_jwks, valid_token_payload):
        """Test handling of expired tokens."""
        validator = AIFTokenValidator(validator_config)
        
        # Create expired token
        expired_payload = valid_token_payload.copy()
        expired_payload["exp"] = datetime.now(timezone.utc) - timedelta(hours=1)
        token = create_test_token(expired_payload, ed25519_keypair)
        
        with patch.object(validator.jwks_cache, 'get_jwks', new_callable=AsyncMock) as mock_get_jwks:
            from heimdall_sp_validator_sdk.models import JWKSModel, JWKModel
            mock_jwks_model = JWKSModel(keys=[JWKModel(**mock_jwks["keys"][0])])
            mock_get_jwks.return_value = mock_jwks_model
            
            with pytest.raises(AIFTokenExpiredError):
                await validator.verify_atk(token)
    
    @pytest.mark.asyncio
    async def test_invalid_audience(self, validator_config, ed25519_keypair, mock_jwks, valid_token_payload):
        """Test handling of invalid audience."""
        validator = AIFTokenValidator(validator_config)
        
        # Create token with wrong audience
        wrong_audience_payload = valid_token_payload.copy()
        wrong_audience_payload["aud"] = ["wrong-audience"]
        token = create_test_token(wrong_audience_payload, ed25519_keypair)
        
        with patch.object(validator.jwks_cache, 'get_jwks', new_callable=AsyncMock) as mock_get_jwks:
            from heimdall_sp_validator_sdk.models import JWKSModel, JWKModel
            mock_jwks_model = JWKSModel(keys=[JWKModel(**mock_jwks["keys"][0])])
            mock_get_jwks.return_value = mock_jwks_model
            
            with pytest.raises(AIFInvalidAudienceError):
                await validator.verify_atk(token)
    
    @pytest.mark.asyncio
    async def test_revoked_token(self, validator_config, ed25519_keypair, mock_jwks, valid_token_payload):
        """Test handling of revoked tokens."""
        validator = AIFTokenValidator(validator_config)
        
        token = create_test_token(valid_token_payload, ed25519_keypair)
        
        with patch.object(validator.jwks_cache, 'get_jwks', new_callable=AsyncMock) as mock_get_jwks:
            from heimdall_sp_validator_sdk.models import JWKSModel, JWKModel
            mock_jwks_model = JWKSModel(keys=[JWKModel(**mock_jwks["keys"][0])])
            mock_get_jwks.return_value = mock_jwks_model
            
            # Mock revocation check to raise revoked error
            with patch.object(validator, '_check_revocation', new_callable=AsyncMock) as mock_revocation:
                mock_revocation.side_effect = AIFRevokedTokenError(jti="test-jti-123")
                
                with pytest.raises(AIFRevokedTokenError):
                    await validator.verify_atk(token)
    
    @pytest.mark.asyncio
    async def test_invalid_token_format(self, validator_config):
        """Test handling of malformed tokens."""
        validator = AIFTokenValidator(validator_config)
        
        # Test empty token
        with pytest.raises(AIFTokenValidationError, match="ATK must be a non-empty string"):
            await validator.verify_atk("")
        
        # Test non-string token
        with pytest.raises(AIFTokenValidationError, match="ATK must be a non-empty string"):
            await validator.verify_atk(None)
        
        # Test malformed JWT
        with pytest.raises(AIFTokenValidationError, match="Malformed ATK"):
            await validator.verify_atk("invalid.jwt.token")
    
    @pytest.mark.asyncio
    async def test_jwks_fetch_failure(self, validator_config, ed25519_keypair, valid_token_payload):
        """Test handling of JWKS fetch failures."""
        validator = AIFTokenValidator(validator_config)
        
        token = create_test_token(valid_token_payload, ed25519_keypair)
        
        # Mock JWKS fetch failure
        with patch.object(validator.jwks_cache, 'get_jwks', new_callable=AsyncMock) as mock_get_jwks:
            mock_get_jwks.side_effect = AIFRegistryConnectionError("Failed to fetch JWKS")
            
            with pytest.raises(AIFRegistryConnectionError):
                await validator.verify_atk(token)
    
    def test_extract_user_id_from_aid(self, validator_config):
        """Test AID parsing functionality."""
        validator = AIFTokenValidator(validator_config)
        
        # Valid AID
        aid = "aif://issuer.example.com/gpt-4/user-123/instance-456"
        user_id = validator._extract_user_id_from_aid(aid)
        assert user_id == "user-123"
        
        # Invalid AID
        invalid_aid = "invalid-aid-format"
        user_id = validator._extract_user_id_from_aid(invalid_aid)
        assert user_id is None
        
        # Empty AID
        user_id = validator._extract_user_id_from_aid("")
        assert user_id is None


class TestRevocationChecking:
    """Test revocation checking functionality."""
    
    @pytest.mark.asyncio
    async def test_revocation_check_disabled(self, validator_config):
        """Test when revocation checking is disabled."""
        config = validator_config
        config.revocation_check_enabled = False
        
        validator = AIFTokenValidator(config)
        
        # Should not raise any errors
        await validator._check_revocation("test-jti")
    
    @pytest.mark.asyncio
    async def test_revocation_check_success(self, validator_config):
        """Test successful revocation check (token not revoked)."""
        validator = AIFTokenValidator(validator_config)
        
        # Mock httpx client
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = {
                "jti": "test-jti",
                "is_revoked": False,
                "checked_at": datetime.now(timezone.utc).isoformat()
            }
            
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response
            
            # Should not raise any errors
            await validator._check_revocation("test-jti")
    
    @pytest.mark.asyncio
    async def test_revocation_check_revoked(self, validator_config):
        """Test revocation check when token is revoked."""
        validator = AIFTokenValidator(validator_config)
        
        # Mock httpx client
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = {
                "jti": "test-jti",
                "is_revoked": True,
                "checked_at": datetime.now(timezone.utc).isoformat()
            }
            
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response
            
            with pytest.raises(AIFRevokedTokenError):
                await validator._check_revocation("test-jti")


class TestIntegrationScenarios:
    """Test real-world integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_full_validation_workflow(self, validator_config, ed25519_keypair, mock_jwks, valid_token_payload):
        """Test complete validation workflow."""
        validator = AIFTokenValidator(validator_config)
        
        # Create token with all claims
        complete_payload = valid_token_payload.copy()
        complete_payload.update({
            "nbf": datetime.now(timezone.utc) - timedelta(minutes=5),
            "aif_trust_tags": {
                "user_verification_level": "verified",
                "issuer_assurance": "production_level"
            }
        })
        
        token = create_test_token(complete_payload, ed25519_keypair)
        
        # Mock external calls
        with patch.object(validator.jwks_cache, 'get_jwks', new_callable=AsyncMock) as mock_get_jwks:
            from heimdall_sp_validator_sdk.models import JWKSModel, JWKModel
            mock_jwks_model = JWKSModel(keys=[JWKModel(**mock_jwks["keys"][0])])
            mock_get_jwks.return_value = mock_jwks_model
            
            with patch.object(validator, '_check_revocation', new_callable=AsyncMock) as mock_revocation:
                mock_revocation.return_value = None
                
                result = await validator.verify_atk(token)
                
                # Verify all fields are properly populated
                assert result.aid
                assert result.user_id_from_aid == "user-123"
                assert result.issuer == complete_payload["iss"]
                assert result.jti == complete_payload["jti"]
                assert result.aif_trust_tags == complete_payload["aif_trust_tags"]
                assert result.validation_duration_ms is not None
                assert result.validation_duration_ms > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
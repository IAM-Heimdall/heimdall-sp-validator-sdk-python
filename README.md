# Heimdall SP Validator SDK

Python SDK for Service Providers to validate Agent Identity Framework (AIF) tokens issued by Heimdall-compliant Issuing Entities.

## Installation

```bash
pip install heimdall-sp-validator-sdk
```

## Quick Start

```python
from heimdall_sp_validator_sdk import AIFTokenValidator, AIFValidatorConfig

# Configure validator
config = AIFValidatorConfig(
    aif_core_service_url="https://poc.iamheimdall.com",
    expected_sp_audiences=["my-service-api"],
    expected_issuer_id="aif://poc-heimdall.example.com"
)

validator = AIFTokenValidator(config)

# Validate token
try:
    result = await validator.verify_atk(token_string)
    print(f"✅ Valid token for user: {result.user_id_from_aid}")
    print(f"Permissions: {result.permissions}")
except Exception as e:
    print(f"❌ Invalid token: {e}")
```

## Configuration

### Environment Variables (Recommended)

Copy `.env.example` to `.env` and configure:

```bash
AIF_CORE_SERVICE_URL=https://poc.iamheimdall.com
AIF_EXPECTED_ISSUER_ID=aif://poc-heimdall.example.com
AIF_SP_EXPECTED_AUDIENCES=my-service-api,another-service
```

Use environment-based configuration:

```python
config = AIFValidatorConfig.from_env()
validator = AIFTokenValidator(config)
```

### Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `aif_core_service_url` | Required | Base URL of AIF core service |
| `expected_sp_audiences` | Required | Your service audience ID(s) |
| `expected_issuer_id` | Required | Trusted issuer identifier |
| `jwks_cache_ttl_seconds` | 86400 | JWKS cache duration (24 hours) |
| `revocation_check_enabled` | true | Enable revocation checking |
| `revocation_check_timeout_seconds` | 5 | Revocation check timeout |
| `clock_skew_seconds` | 60 | Allowed time skew for validation |

## Usage Examples

### Basic Validation

```python
import asyncio
from heimdall_sp_validator_sdk import AIFTokenValidator, AIFValidatorConfig

async def validate_token(token):
    config = AIFValidatorConfig(
        aif_core_service_url="https://poc.iamheimdall.com",
        expected_sp_audiences=["my-api"],
        expected_issuer_id="aif://poc-heimdall.example.com"
    )
    
    validator = AIFTokenValidator(config)
    result = await validator.verify_atk(token)
    
    return {
        "user_id": result.user_id_from_aid,
        "permissions": result.permissions,
        "expires_at": result.expires_at,
        "purpose": result.purpose
    }

# Run validation
token_data = asyncio.run(validate_token(your_token))
```

### Permission Checking

```python
async def check_permissions(token, required_permissions):
    try:
        result = await validator.verify_atk(token)
        
        # Check if token has required permissions
        has_permissions = all(
            perm in result.permissions 
            for perm in required_permissions
        )
        
        if not has_permissions:
            return {"error": "Insufficient permissions"}
            
        return {"success": True, "user_id": result.user_id_from_aid}
        
    except Exception as e:
        return {"error": str(e)}

# Usage
result = await check_permissions(token, ["read:articles", "write:comments"])
```

### FastAPI Integration

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer
from heimdall_sp_validator_sdk import AIFTokenValidator, AIFValidatorConfig

app = FastAPI()
security = HTTPBearer()

# Initialize validator
config = AIFValidatorConfig.from_env()
validator = AIFTokenValidator(config)

async def validate_token(token: str = Depends(security)):
    try:
        result = await validator.verify_atk(token.credentials)
        return result
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/protected")
async def protected_endpoint(token_data = Depends(validate_token)):
    return {
        "message": "Access granted",
        "user_id": token_data.user_id_from_aid,
        "permissions": token_data.permissions
    }
```

### Flask Integration

```python
from flask import Flask, request, jsonify
from functools import wraps
import asyncio

app = Flask(__name__)

# Initialize validator
config = AIFValidatorConfig.from_env()
validator = AIFTokenValidator(config)

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid token"}), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            result = asyncio.run(validator.verify_atk(token))
            return f(result, *args, **kwargs)
        except Exception as e:
            return jsonify({"error": str(e)}), 401
    
    return decorated

@app.route('/protected')
@require_token
def protected_route(token_data):
    return jsonify({
        "user_id": token_data.user_id_from_aid,
        "permissions": token_data.permissions
    })
```

## Error Handling

The SDK provides specific exceptions for different failure scenarios:

```python
from heimdall_sp_validator_sdk import (
    AIFTokenExpiredError,
    AIFRevokedTokenError,
    AIFInvalidAudienceError,
    AIFSignatureError,
    AIFRegistryConnectionError
)

try:
    result = await validator.verify_atk(token)
except AIFTokenExpiredError:
    # Token has expired
    return {"error": "Token expired", "code": "TOKEN_EXPIRED"}
except AIFRevokedTokenError:
    # Token was revoked
    return {"error": "Token revoked", "code": "TOKEN_REVOKED"}
except AIFInvalidAudienceError:
    # Token not intended for this service
    return {"error": "Invalid audience", "code": "WRONG_AUDIENCE"}
except AIFSignatureError:
    # Invalid signature
    return {"error": "Invalid signature", "code": "BAD_SIGNATURE"}
except AIFRegistryConnectionError:
    # Cannot connect to AIF registry
    return {"error": "Registry unavailable", "code": "REGISTRY_ERROR"}
except Exception as e:
    # Generic validation error
    return {"error": str(e), "code": "VALIDATION_ERROR"}
```

## Response Structure

Successful validation returns a `ValidatedATKData` object:

```python
{
    "aid": "aif://issuer/model/user/instance-id",
    "user_id_from_aid": "user-123",
    "issuer": "aif://poc-heimdall.example.com",
    "audience": ["my-service-api"],
    "jti": "unique-token-id",
    "permissions": ["read:articles", "write:comments"],
    "purpose": "User content management",
    "aif_trust_tags": {"user_verification_level": "verified"},
    "expires_at": "2025-01-15T10:30:00Z",
    "issued_at": "2025-01-14T10:30:00Z",
    "not_before": null,
    "raw_payload": {...},
    "validation_duration_ms": 45.2
}
```

## Requirements

- Python 3.8+
- Active AIF Core Service for JWKS and revocation checking
- Network access to the AIF service

## Dependencies

- `pydantic>=2.0.0` - Data validation
- `PyJWT[cryptography]>=2.8.0` - JWT handling with EdDSA support
- `httpx>=0.20.0` - Async HTTP client
- `cryptography>=3.4.0` - Cryptographic operations

## Security Considerations

- **Validate on every request** - Don't cache validation results
- **Use HTTPS** - Ensure secure communication with AIF service
- **Monitor revocation** - Keep revocation checking enabled
- **Handle errors gracefully** - Don't expose internal errors to clients
- **Update regularly** - Keep the SDK updated for security patches

## Troubleshooting

### Common Issues

**"Failed to fetch JWKS"**
- Check `aif_core_service_url` is correct and accessible
- Verify network connectivity to AIF service
- Ensure the service is running and healthy

**"Invalid audience"**
- Verify `expected_sp_audiences` matches token's `aud` claim
- Check if token was issued for your service

**"No matching key found"**
- Token might be from different issuer
- JWKS cache might be stale (will auto-refresh)

**"Token signature verification failed"**
- Token might be corrupted or tampered with
- Wrong algorithm or key being used

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Validator will now log detailed information
result = await validator.verify_atk(token)
```

## Support

- **Documentation**: [GitHub Repository](https://github.com/your-org/heimdall-sp-validator-sdk)
- **Issues**: [GitHub Issues](https://github.com/your-org/heimdall-sp-validator-sdk/issues)
- **AIF Specification**: [IAM Heimdall](https://poc.iamheimdall.com)

## License

MIT License - see [LICENSE](LICENSE) file for details.
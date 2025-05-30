# Heimdall SP Validator SDK - Documentation

Additional examples and usage patterns for the SDK.

## Framework Integrations

### FastAPI

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer
from heimdall_sp_validator_sdk import AIFTokenValidator, AIFValidatorConfig

app = FastAPI()
security = HTTPBearer()

config = AIFValidatorConfig.from_env()
validator = AIFTokenValidator(config)

async def validate_token(token = Depends(security)):
    try:
        result = await validator.verify_atk(token.credentials)
        return result
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/protected")
async def protected_endpoint(token_data = Depends(validate_token)):
    return {
        "user_id": token_data.user_id_from_aid,
        "permissions": token_data.permissions
    }
```

### Flask

```python
from flask import Flask, request, jsonify
from functools import wraps
import asyncio

app = Flask(__name__)
config = AIFValidatorConfig.from_env()
validator = AIFTokenValidator(config)

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing token"}), 401
        
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

```python
from heimdall_sp_validator_sdk import (
    AIFTokenExpiredError,
    AIFRevokedTokenError,
    AIFInvalidAudienceError,
    AIFSignatureError
)

try:
    result = await validator.verify_atk(token)
except AIFTokenExpiredError:
    return {"error": "Token expired"}
except AIFRevokedTokenError:
    return {"error": "Token revoked"}
except AIFInvalidAudienceError:
    return {"error": "Invalid audience"}
except AIFSignatureError:
    return {"error": "Invalid signature"}
except Exception as e:
    return {"error": "Validation failed"}
```

## Permission Checking

```python
async def check_permissions(token, required_permissions):
    result = await validator.verify_atk(token)
    
    has_permissions = all(
        perm in result.permissions 
        for perm in required_permissions
    )
    
    if not has_permissions:
        raise Exception("Insufficient permissions")
    
    return result

# Usage
result = await check_permissions(token, ["read:articles", "write:comments"])
```

## Complete Configuration

```python
config = AIFValidatorConfig(
    aif_core_service_url="https://poc.iamheimdall.com",
    expected_sp_audiences=["my-service"],
    expected_issuer_id="aif://poc-heimdall.example.com",
    
    # Optional settings
    jwks_cache_ttl_seconds=86400,  # 24 hours
    revocation_check_enabled=True,
    revocation_check_timeout_seconds=5,
    clock_skew_seconds=60
)
```

## Troubleshooting

### Common Issues

**"Failed to fetch JWKS"**
- Check `aif_core_service_url` is correct
- Verify network connectivity to AIF service

**"Invalid audience"** 
- Verify `expected_sp_audiences` matches token's `aud` claim

**"Token signature verification failed"**
- Token might be corrupted or from wrong issuer

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

result = await validator.verify_atk(token)
```

## Response Structure

```json
{
    "aid": "aif://issuer/model/user/instance-id",
    "user_id_from_aid": "user-123", 
    "issuer": "aif://poc-heimdall.example.com",
    "audience": ["my-service"],
    "jti": "unique-token-id",
    "permissions": ["read:articles", "write:comments"],
    "purpose": "Token purpose",
    "aif_trust_tags": {"user_verification_level": "verified"},
    "expires_at": "2025-01-15T10:30:00Z",
    "issued_at": "2025-01-14T10:30:00Z"
}
```
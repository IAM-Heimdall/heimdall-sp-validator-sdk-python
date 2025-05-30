# aif_sp_validator_sdk/cache.py
import time
from typing import Dict, Any, Optional, Tuple
import httpx
import logging
from urllib.parse import urljoin # For constructing URLs

from .models import JWKSModel
from .exceptions import AIFRegistryConnectionError, AIFJWKSError

logger = logging.getLogger(__name__)

class JWKSCache:
    def __init__(self, default_ttl_seconds: int, fetch_timeout_seconds: int):
        self._cache: Dict[str, Tuple[JWKSModel, float]] = {} # jwks_url -> (JWKSModel, expiry_timestamp)
        self.default_ttl_seconds = default_ttl_seconds
        self.fetch_timeout_seconds = fetch_timeout_seconds

    async def get_jwks(self, jwks_url: str) -> JWKSModel:
        """Retrieves JWKS, using cache if valid, otherwise fetching."""
        cached_jwks, expiry_ts = self._cache.get(jwks_url, (None, 0.0))

        if cached_jwks and time.time() < expiry_ts:
            logger.debug(f"Using cached JWKS for {jwks_url}")
            return cached_jwks

        logger.info(f"Fetching JWKS from {jwks_url} (cache miss or expired)")
        async with httpx.AsyncClient(timeout=self.fetch_timeout_seconds) as client:
            try:
                response = await client.get(jwks_url)
                response.raise_for_status()
                jwks_data = response.json()
                
                jwks_model = JWKSModel(**jwks_data) # Validate response against Pydantic model
                
                self._cache[jwks_url] = (jwks_model, time.time() + self.default_ttl_seconds)
                logger.info(f"Successfully fetched and cached JWKS for {jwks_url}")
                return jwks_model
            except httpx.HTTPStatusError as e:
                err_msg = f"Failed to fetch JWKS (HTTP {e.response.status_code}) from {jwks_url}"
                logger.error(f"{err_msg} - Response: {e.response.text[:200]}")
                raise AIFRegistryConnectionError(err_msg, endpoint=jwks_url, status_code=e.response.status_code) from e
            except httpx.RequestError as e: # Covers network errors, timeouts
                logger.error(f"Request error fetching JWKS from {jwks_url}: {e}")
                raise AIFRegistryConnectionError(f"Network error fetching JWKS from {jwks_url}", endpoint=jwks_url) from e
            except (ValueError, TypeError) as e: # Pydantic validation or JSONDecodeError
                logger.error(f"Error parsing JWKS JSON from {jwks_url}: {e}")
                raise AIFJWKSError(f"Invalid JWKS format from {jwks_url}", jwks_url=jwks_url) from e
    
    def clear_cache(self, jwks_url: Optional[str] = None):
        if jwks_url:
            if jwks_url in self._cache: del self._cache[jwks_url]
            logger.info(f"Cleared JWKS cache for {jwks_url}")
        else:
            self._cache.clear()
            logger.info("Cleared all JWKS cache.")
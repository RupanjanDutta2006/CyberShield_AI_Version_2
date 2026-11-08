"""CyberShield AI — API Authentication and Security Dependencies (B5-F01)

Provides header-based (X-API-Key) and Bearer-token (Authorization) authentication
for sensitive endpoints protecting report persistence, history, and on-chain registration.
"""

from typing import Optional
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from app.core.config import get_settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
http_bearer = HTTPBearer(auto_error=False)


def require_api_auth(
    api_key_from_header: Optional[str] = Security(api_key_header),
    bearer_credentials: Optional[HTTPAuthorizationCredentials] = Security(http_bearer),
) -> str:
    """Validate that incoming request carries valid API credentials.
    
    Protects sensitive routes:
    - History queries (/api/v1/history)
    - Sensitive scan report retrieval (/api/v1/scans/{scan_id})
    - Report persistence (/api/v1/reports)
    - Full investigation execution (/api/v1/reports/investigate)
    - Blockchain on-chain registration (/api/v1/reports/register)
    
    Returns:
        The validated token string if authorized.
        
    Raises:
        HTTPException 401: If no credentials provided.
        HTTPException 403: If credentials provided but invalid.
    """
    settings = get_settings()
    configured_key = settings.api_auth_key

    # Fail-closed if server authentication secret is unconfigured or empty
    if not configured_key or not configured_key.strip():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server authentication configuration is missing or invalid.",
        )

    # In production environments, reject insecure default development keys
    if settings.environment.lower() == "production" and configured_key == "cybershield-auth-key-2026":
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Insecure default authentication key disallowed in production environment.",
        )

    provided_token: Optional[str] = None
    if api_key_from_header:
        provided_token = api_key_from_header.strip()
    elif bearer_credentials and bearer_credentials.credentials:
        provided_token = bearer_credentials.credentials.strip()

    if not provided_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide valid API credentials via X-API-Key or Bearer authorization.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if provided_token != configured_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid or unauthorized API credentials.",
        )

    return provided_token

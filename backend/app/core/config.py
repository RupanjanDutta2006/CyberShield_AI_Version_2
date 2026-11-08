"""CyberShield AI — Unified Application Configuration

Loads settings from environment variables and provides a centralized,
strongly-typed configuration object for all backend services, supporting
Member 1, Member 2, Member 3, and Member 4 requirements.
"""

from functools import lru_cache
import os
from typing import List, Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load optional .env file from project root or backend directory
load_dotenv()


class Settings(BaseModel):
    """Application settings and configuration parameters for all 4 members."""

    app_name: str = Field(default_factory=lambda: os.getenv("APP_NAME", "CyberShield AI API"))
    app_version: str = Field(default_factory=lambda: os.getenv("APP_VERSION", "1.0.0"))
    api_v1_prefix: str = "/api/v1"
    environment: str = Field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    debug: bool = Field(default_factory=lambda: os.getenv("DEBUG", "true").lower() in ("true", "1", "yes"))
    host: str = Field(default_factory=lambda: os.getenv("HOST", "127.0.0.1"))
    port: int = Field(default_factory=lambda: int(os.getenv("PORT", "8000")))
    log_level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    # CORS configuration
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            origin.strip()
            for origin in os.getenv(
                "CORS_ORIGINS",
                os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000")
            ).split(",")
            if origin.strip()
        ]
    )

    # Scanner & Safety Limits (Member 1)
    scan_timeout_seconds: int = Field(
        default_factory=lambda: int(os.getenv("SCAN_TIMEOUT_SECONDS", "10"))
    )
    max_redirect_hops: int = Field(
        default_factory=lambda: int(os.getenv("MAX_REDIRECT_HOPS", "5"))
    )
    max_response_bytes: int = Field(
        default_factory=lambda: int(os.getenv("MAX_RESPONSE_BYTES", "1048576"))
    )

    # Threat Intelligence (Member 1 & Member 4)
    urlhaus_api_key: str = Field(
        default_factory=lambda: os.getenv("URLHAUS_API_KEY", os.getenv("URLHAUS_AUTH_KEY", ""))
    )
    urlhaus_auth_key: str = Field(
        default_factory=lambda: os.getenv("URLHAUS_AUTH_KEY", os.getenv("URLHAUS_API_KEY", ""))
    )
    urlhaus_api_url: str = Field(
        default_factory=lambda: os.getenv("URLHAUS_API_URL", "https://urlhaus-api.abuse.ch/v1")
    )
    phishtank_app_key: str = Field(
        default_factory=lambda: os.getenv("PHISHTANK_APP_KEY", "")
    )
    phishtank_api_url: str = Field(
        default_factory=lambda: os.getenv("PHISHTANK_API_URL", "https://checkurl.phishtank.com/checkurl/")
    )
    safe_browsing_api_key: str = Field(
        default_factory=lambda: os.getenv("SAFE_BROWSING_API_KEY", "")
    )

    # AI Scam Analysis — Multi-Provider Failover (Member 2)
    ai_provider: str = Field(default_factory=lambda: os.getenv("AI_PROVIDER", "groq"))
    ai_api_key: str = Field(default_factory=lambda: os.getenv("AI_API_KEY", ""))
    ai_model_name: str = Field(default_factory=lambda: os.getenv("AI_MODEL_NAME", "gemini-1.5-flash"))

    groq_api_key: str = Field(default_factory=lambda: os.getenv("GROQ_API_KEY", ""))
    groq_model: str = Field(default_factory=lambda: os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"))

    gemini_api_key: str = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY", os.getenv("AI_API_KEY", "")))
    gemini_model: str = Field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-1.5-flash"))

    openai_api_key: str = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openai_model: str = Field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini"))

    llm_timeout_seconds: float = Field(default_factory=lambda: float(os.getenv("LLM_TIMEOUT_SECONDS", "12.0")))
    llm_max_retries: int = Field(default_factory=lambda: int(os.getenv("LLM_MAX_RETRIES", "3")))
    llm_base_retry_delay: float = Field(default_factory=lambda: float(os.getenv("LLM_BASE_RETRY_DELAY", "1.0")))

    # Blockchain Registry (Member 3)
    blockchain_rpc_url: str = Field(
        default_factory=lambda: os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545")
    )
    registry_contract_address: str = Field(
        default_factory=lambda: os.getenv("REGISTRY_CONTRACT_ADDRESS", os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS", ""))
    )
    blockchain_contract_address: str = Field(
        default_factory=lambda: os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS", os.getenv("REGISTRY_CONTRACT_ADDRESS", ""))
    )
    blockchain_private_key: str = Field(
        default_factory=lambda: os.getenv("BLOCKCHAIN_PRIVATE_KEY", os.getenv("DEPLOYER_PRIVATE_KEY", ""))
    )
    deployer_private_key: str = Field(
        default_factory=lambda: os.getenv("DEPLOYER_PRIVATE_KEY", os.getenv("BLOCKCHAIN_PRIVATE_KEY", ""))
    )
    blockchain_network: str = Field(
        default_factory=lambda: os.getenv("BLOCKCHAIN_NETWORK", "Hardhat Local (EVM 31337)")
    )

    # Persistence (Member 4 & Member 1)
    database_url: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./cybershield.db")
    )

    # API Security & Authentication (Member 1 / Member 4)
    api_auth_key: str = Field(
        default_factory=lambda: os.getenv("API_AUTH_KEY", "cybershield-auth-key-2026")
    )

    # Uppercase aliases for compatibility with Member 2 / Member 4 modules
    def __getattr__(self, name: str):
        lower_name = name.lower()
        if lower_name in self.__dict__:
            return self.__dict__[lower_name]
        return super().__getattribute__(name)


@lru_cache()
def get_settings() -> Settings:
    """Return cached instance of application settings."""
    return Settings()


# Singleton instance for direct imports (e.g. `from app.core.config import settings`)
settings = get_settings()

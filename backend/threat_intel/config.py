from backend.config import settings

class ThreatIntelConfig:
    URLHAUS_AUTH_KEY = settings.URLHAUS_AUTH_KEY
    URLHAUS_API_URL = settings.URLHAUS_API_URL
    PHISHTANK_APP_KEY = settings.PHISHTANK_APP_KEY
    PHISHTANK_API_URL = settings.PHISHTANK_API_URL
    REQUEST_TIMEOUT_SECONDS = 3.5  # Strict timeout to prevent hanging

threat_config = ThreatIntelConfig()

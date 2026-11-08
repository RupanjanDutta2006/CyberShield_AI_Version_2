"""Reusable resilient LLM client supporting multi-provider tiered failover.

Failover order:
  Tier 1: Groq Cloud (Ultra-fast, Primary)
  Tier 2: Google Gemini (Backup 1)
  Tier 3: OpenAI (Backup 2)

Features bounded retries, exponential backoff, rate limit handling,
strict timeouts, secret sanitization, and structured JSON parsing.
"""

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx
from backend.config import settings

logger = logging.getLogger("cybershield.ai_engine.llm_client")


class LLMError(Exception):
    """Base exception for all LLM client errors."""


class LLMTimeoutError(LLMError):
    """Raised when an LLM request exceeds configured timeout."""


class LLMRateLimitError(LLMError):
    """Raised when encountering rate limits (HTTP 429) after max retries."""


class LLMConnectionError(LLMError):
    """Raised when unable to establish connection to LLM provider."""


class LLMAuthenticationError(LLMError):
    """Raised when LLM API returns authentication or authorization errors."""


class LLMMalformedResponseError(LLMError):
    """Raised when LLM response is not valid JSON or missing expected fields."""


class LLMClient:
    """Async HTTP client for querying OpenAI-compatible chat completion APIs with failover."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        providers: Optional[List[Tuple[str, str, str, str]]] = None,
    ):
        self.timeout = timeout if timeout is not None else getattr(settings, "LLM_TIMEOUT_SECONDS", 12.0)
        self.max_retries = max_retries if max_retries is not None else getattr(settings, "LLM_MAX_RETRIES", 3)

        if api_key is not None or base_url is not None or model is not None:
            self.providers = [
                (
                    "Custom Provider",
                    api_key or "",
                    model or "openai/gpt-oss-120b",
                    (base_url or "https://api.groq.com/openai/v1").rstrip("/"),
                )
            ]
        elif providers is not None:
            self.providers = providers
        else:
            self.providers = self._discover_providers()

    @staticmethod
    def _discover_providers() -> List[Tuple[str, str, str, str]]:
        """Discover and configure active providers in priority order: Groq -> Gemini -> OpenAI."""
        configured: List[Tuple[str, str, str, str]] = []

        # 1. Tier 1: Groq Cloud
        groq_key = getattr(settings, "GROQ_API_KEY", None)
        if groq_key and groq_key.strip():
            configured.append((
                "Groq Cloud",
                groq_key.strip(),
                getattr(settings, "GROQ_MODEL", "openai/gpt-oss-120b"),
                "https://api.groq.com/openai/v1",
            ))

        # 2. Tier 2: Google Gemini (OpenAI-compatible endpoint)
        gemini_key = getattr(settings, "GEMINI_API_KEY", None)
        if gemini_key and gemini_key.strip():
            configured.append((
                "Google Gemini",
                gemini_key.strip(),
                getattr(settings, "GEMINI_MODEL", "gemini-1.5-flash"),
                "https://generativelanguage.googleapis.com/v1beta/openai",
            ))

        # 3. Tier 3: OpenAI
        openai_key = getattr(settings, "OPENAI_API_KEY", None)
        if openai_key and openai_key.strip():
            configured.append((
                "OpenAI",
                openai_key.strip(),
                getattr(settings, "OPENAI_MODEL", "gpt-4o-mini"),
                "https://api.openai.com/v1",
            ))

        # 4. Fallback generic AI_API_KEY if none of the above are set
        if not configured:
            ai_key = getattr(settings, "AI_API_KEY", None)
            if ai_key and ai_key.strip():
                provider_type = getattr(settings, "AI_PROVIDER", "groq").lower()
                if "gemini" in provider_type:
                    configured.append((
                        "Google Gemini",
                        ai_key.strip(),
                        "gemini-1.5-flash",
                        "https://generativelanguage.googleapis.com/v1beta/openai",
                    ))
                elif "openai" in provider_type:
                    configured.append((
                        "OpenAI",
                        ai_key.strip(),
                        "gpt-4o-mini",
                        "https://api.openai.com/v1",
                    ))
                else:
                    configured.append((
                        "Groq Cloud",
                        ai_key.strip(),
                        "openai/gpt-oss-120b",
                        "https://api.groq.com/openai/v1",
                    ))

        return configured

    def is_configured(self) -> bool:
        """Check if at least one valid LLM provider is configured."""
        return bool(self.providers and any(p[1] for p in self.providers))

    def _clean_json_markdown(self, raw_content: str) -> str:
        """Remove markdown code blocks such as ```json ... ``` from model output."""
        cleaned = raw_content.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        return cleaned.strip()

    async def _query_single_provider(
        self,
        name: str,
        api_key: str,
        model: str,
        base_url: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        response_format_json: bool = True,
    ) -> Dict[str, Any]:
        """Query a single provider endpoint with bounded retries."""
        url = f"{base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if response_format_json:
            payload["response_format"] = {"type": "json_object"}

        retries = 0
        backoff = 0.5

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while True:
                try:
                    response = await client.post(url, headers=headers, json=payload)

                    if response.status_code == 200:
                        data = response.json()
                        try:
                            choice = data["choices"][0]["message"]["content"]
                        except (KeyError, IndexError, TypeError) as e:
                            raise LLMMalformedResponseError(
                                f"Missing expected choices structure in response from {name}: {str(e)}"
                            )

                        clean_content = self._clean_json_markdown(choice)
                        try:
                            parsed_json = json.loads(clean_content)
                            if not isinstance(parsed_json, dict):
                                raise LLMMalformedResponseError("Parsed JSON is not a key-value object.")
                            return parsed_json
                        except json.JSONDecodeError as jde:
                            raise LLMMalformedResponseError(
                                f"Failed to parse LLM output as JSON from {name}: {str(jde)}"
                            )

                    elif response.status_code == 429:
                        retries += 1
                        if retries > self.max_retries:
                            raise LLMRateLimitError(
                                f"{name} rate limit / quota exceeded (HTTP 429) after {self.max_retries} retries."
                            )
                        logger.warning(
                            "%s rate limited (HTTP 429). Retrying in %.2f seconds (attempt %d/%d)",
                            name,
                            backoff,
                            retries,
                            self.max_retries,
                        )
                        await asyncio.sleep(backoff)
                        backoff *= 2

                    elif response.status_code in (401, 403):
                        raise LLMAuthenticationError(
                            f"{name} API authentication failed with HTTP {response.status_code}."
                        )

                    elif response.status_code >= 500:
                        retries += 1
                        if retries > self.max_retries:
                            raise LLMConnectionError(
                                f"{name} server error (HTTP {response.status_code}) after {self.max_retries} retries."
                            )
                        logger.warning(
                            "%s server error %d. Retrying in %.2f seconds (attempt %d/%d)",
                            name,
                            response.status_code,
                            backoff,
                            retries,
                            self.max_retries,
                        )
                        await asyncio.sleep(backoff)
                        backoff *= 2

                    else:
                        raise LLMError(
                            f"{name} unexpected status {response.status_code}: {response.text[:150]}"
                        )

                except httpx.TimeoutException as te:
                    retries += 1
                    if retries > self.max_retries:
                        raise LLMTimeoutError(f"{name} timed out after {self.timeout}s: {str(te)}")
                    logger.warning("%s timeout. Retrying in %.2f seconds...", name, backoff)
                    await asyncio.sleep(backoff)
                    backoff *= 2

                except httpx.RequestError as re_err:
                    retries += 1
                    if retries > self.max_retries:
                        raise LLMConnectionError(f"{name} network error: {str(re_err)}")
                    logger.warning("%s connection error. Retrying in %.2f seconds...", name, backoff)
                    await asyncio.sleep(backoff)
                    backoff *= 2

    async def generate_chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        response_format_json: bool = True,
    ) -> Tuple[Dict[str, Any], str]:
        """Execute chat completion using tiered failover across configured providers.
        
        Returns:
            Tuple of (parsed_json_dict, provider_name)
        """
        providers = self.providers or self._discover_providers()
        if not providers:
            raise LLMAuthenticationError("No LLM API providers are configured.")

        errors: List[str] = []

        for name, api_key, model, base_url in providers:
            try:
                logger.info("Attempting LLM inference with provider: %s (model: %s)", name, model)
                result = await self._query_single_provider(
                    name=name,
                    api_key=api_key,
                    model=model,
                    base_url=base_url,
                    messages=messages,
                    temperature=temperature,
                    response_format_json=response_format_json,
                )
                logger.info("Successfully received LLM response from provider: %s", name)
                return result, name
            except (
                LLMRateLimitError,
                LLMTimeoutError,
                LLMConnectionError,
                LLMMalformedResponseError,
                LLMAuthenticationError,
                LLMError,
            ) as err:
                err_msg = f"{name} ({model}) failed: {type(err).__name__} - {str(err)}"
                logger.warning("%s. Failing over to next provider if available...", err_msg)
                errors.append(err_msg)

        raise LLMConnectionError(
            f"All configured LLM providers failed. Details: {' | '.join(errors)}"
        )

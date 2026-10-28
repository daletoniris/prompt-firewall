"""
Middleware integration example -- FastAPI + Flask.

Shows how to plug the Prompt Firewall and PII Sanitizer into your
LLM application as middleware that runs on every request.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from prompt_firewall import PromptFirewall, FirewallResult
from pii_sanitizer import PIISanitizer, SanitizeResult

logger = logging.getLogger(__name__)


class LLMSecurityMiddleware:
    """
    Wraps your LLM calls with security layers.

    Usage:
        middleware = LLMSecurityMiddleware()

        # Before sending to LLM:
        check = middleware.pre_process(user_message)
        if check['blocked']:
            return {"error": "Request blocked by security policy"}

        # Send check['clean_text'] to your LLM instead of raw input
        llm_response = call_your_llm(check['clean_text'])

        # After getting LLM response:
        validated = middleware.post_process(llm_response, menu_items, business)
    """

    def __init__(
        self,
        block_threshold: float = 0.55,
        sanitize_pii: bool = True,
        log_attacks: bool = True,
    ):
        self.firewall = PromptFirewall(threshold=block_threshold)
        self.sanitizer = PIISanitizer() if sanitize_pii else None
        self.log_attacks = log_attacks

    def pre_process(self, text: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Run all pre-LLM security checks.

        Returns:
            {
                'blocked': bool,
                'clean_text': str,        # sanitized text (if not blocked)
                'firewall': FirewallResult,
                'pii': SanitizeResult | None,
            }
        """
        # Layer 1+2: Prompt injection detection
        fw_result = self.firewall.analyze(text)

        if fw_result.is_attack:
            if self.log_attacks:
                logger.warning(
                    "PROMPT INJECTION BLOCKED | score=%.2f | categories=%s | text=%s",
                    fw_result.score,
                    fw_result.categories,
                    text[:100],
                )
            return {
                'blocked': True,
                'clean_text': '',
                'firewall': fw_result,
                'pii': None,
            }

        # Layer 3: PII sanitization
        pii_result = None
        clean_text = text
        if self.sanitizer:
            pii_result = self.sanitizer.sanitize(text)
            clean_text = pii_result.cleaned_text
            if pii_result.has_pii:
                logger.info("PII sanitized: %s", pii_result.summary)

        return {
            'blocked': False,
            'clean_text': clean_text,
            'firewall': fw_result,
            'pii': pii_result,
        }

    def post_process(
        self,
        response: str,
        known_items: list = None,
        business_context: dict = None,
    ) -> Dict[str, Any]:
        """
        Run post-LLM validation (anti-hallucination).
        """
        from response_validator import ResponseValidator
        validator = ResponseValidator()
        return validator.validate(response, known_items, business_context)


# ═══════════════════════════════════════════════════════
# FastAPI example
# ═══════════════════════════════════════════════════════

FASTAPI_EXAMPLE = '''
from fastapi import FastAPI, HTTPException
from middleware import LLMSecurityMiddleware

app = FastAPI()
security = LLMSecurityMiddleware()

@app.post("/chat")
async def chat(request: dict):
    user_message = request.get("message", "")

    # Pre-process: firewall + PII sanitization
    check = security.pre_process(user_message)

    if check["blocked"]:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "blocked_by_firewall",
                "score": check["firewall"].score,
                "categories": check["firewall"].categories,
            }
        )

    # Send CLEAN text to your LLM
    llm_response = await call_your_llm(check["clean_text"])

    # Post-process: validate response
    validation = security.post_process(
        llm_response,
        known_items=get_menu_items(),
        business_context=get_business_config(),
    )

    if not validation["is_valid"]:
        # Log the hallucination, optionally regenerate
        logger.warning("Hallucination detected: %s", validation["issues"])

    return {"response": llm_response}
'''

# ═══════════════════════════════════════════════════════
# Flask example
# ═══════════════════════════════════════════════════════

FLASK_EXAMPLE = '''
from flask import Flask, request, jsonify
from middleware import LLMSecurityMiddleware

app = Flask(__name__)
security = LLMSecurityMiddleware()

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    user_message = data.get("message", "")

    check = security.pre_process(user_message)

    if check["blocked"]:
        return jsonify({
            "error": "blocked_by_firewall",
            "score": check["firewall"].score,
            "categories": check["firewall"].categories,
        }), 403

    llm_response = call_your_llm(check["clean_text"])

    return jsonify({"response": llm_response})
'''

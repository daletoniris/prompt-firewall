"""
PII Sanitizer -- Server-side data protection layer.

Detects and redacts PII/secrets from prompts BEFORE they reach external LLM APIs.
Critical when using third-party providers where you don't want personal data
leaving your infrastructure.

Categories:
- Credit cards (Luhn-validated)
- National IDs (DNI, SSN, CUIL/CUIT, CPF, passport, NIF/NIE)
- Email addresses, phone numbers, IP addresses
- API keys (OpenAI, Anthropic, AWS, GitHub, Google, Slack, generic)
- Passwords, private keys (PEM), connection strings
- Physical addresses, person names in structured context

Usage:
    sanitizer = PIISanitizer()
    result = sanitizer.sanitize("My card is 4532-0151-2342-6789")
    print(result.cleaned_text)    # "My card is [REDACTED_CREDIT_CARD_1]"
    print(result.has_pii)         # True
    print(result.summary)         # "redacted 1 items (credit_card:1)"
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class PIIMatch:
    category: str
    original: str
    placeholder: str
    start: int
    end: int
    confidence: float  # 0.0-1.0


@dataclass
class SanitizeResult:
    cleaned_text: str
    matches: List[PIIMatch] = field(default_factory=list)
    pii_map: Dict[str, str] = field(default_factory=dict)

    @property
    def has_pii(self) -> bool:
        return len(self.matches) > 0

    @property
    def categories_found(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for m in self.matches:
            counts[m.category] = counts.get(m.category, 0) + 1
        return counts

    @property
    def summary(self) -> str:
        if not self.matches:
            return "clean"
        parts = [f"{cat}:{n}" for cat, n in sorted(self.categories_found.items())]
        return f"redacted {len(self.matches)} items ({', '.join(parts)})"


# ═══════════════════════════════════════════════════════
# Luhn check for credit cards
# ═══════════════════════════════════════════════════════

def _luhn_check(number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ═══════════════════════════════════════════════════════
# Pattern registry
# ═══════════════════════════════════════════════════════

_PATTERNS: List[Tuple[str, re.Pattern, float]] = []

def _p(category: str, pattern: str, confidence: float = 0.9, flags: int = re.IGNORECASE):
    _PATTERNS.append((category, re.compile(pattern, flags), confidence))


# --- Credit Cards ---
_p("credit_card", r"\b(?:\d{4}[-\s]?){3}\d{4}\b", 0.85)

# --- National IDs ---
_p("national_id", r"\b(?:DNI|dni)\s*[:=]?\s*(\d{7,8})\b", 0.95)
_p("national_id", r"\b(?:CUIL|CUIT|cuil|cuit)\s*[:=]?\s*(\d{2}-?\d{7,8}-?\d)\b", 0.95)
_p("national_id", r"\b(?:SSN|ssn)\s*[:=]?\s*(\d{3}-?\d{2}-?\d{4})\b", 0.95)
_p("national_id", r"\b(?:passport|pasaporte)\s*[:=]?\s*([A-Z]{1,2}\d{6,9})\b", 0.90)
_p("national_id", r"\b(?:NIF|NIE|nif|nie)\s*[:=]?\s*([A-Z]?\d{7,8}[A-Z]?)\b", 0.90)
_p("national_id", r"\b(?:CPF|cpf)\s*[:=]?\s*(\d{3}\.?\d{3}\.?\d{3}-?\d{2})\b", 0.95)

# --- Emails ---
_p("email", r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", 0.95)

# --- Phone numbers ---
_p("phone", r"(?<!\d)(\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4})(?!\d)", 0.80)

# --- IP addresses ---
_p("ip_address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.70)

# --- API Keys with known prefixes ---
_p("api_key", r"(?<![A-Za-z0-9_])(sk-(?:proj-|openai-)[a-zA-Z0-9]{32,})\b", 0.99)
_p("api_key", r"(?<![A-Za-z0-9_])(sk-ant-api03-[a-zA-Z0-9_-]{32,})\b", 0.99)
_p("api_key", r"(?<![A-Za-z0-9_])(sk-or-v1-[a-zA-Z0-9_-]{48,})\b", 0.99)
_p("api_key", r"(?<![A-Za-z0-9_])(AIza[0-9A-Za-z_-]{35})\b", 0.99)
_p("api_key", r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9_]{36,})\b", 0.99)
_p("api_key", r"(?<![A-Za-z0-9_])((?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16})\b", 0.99)
_p("api_key", r"(?<![A-Za-z0-9_])(xox[bpsa]-[a-zA-Z0-9-]{24,})\b", 0.99)

# --- Generic key=value secrets ---
_p("api_key",
   r"\b(?:api[_-]?key|apikey|auth[_-]?token|access[_-]?token|"
   r"secret[_-]?key|bearer|private[_-]?key)\s*[:=]\s*['\"]?"
   r"([a-zA-Z0-9_\-]{20,})['\"]?",
   0.85)

# --- Passwords ---
_p("password",
   r"\b(?:password|passwd|pwd|pass|contraseña|clave)\s*[:=]\s*['\"]?([^\s'\";]{8,})['\"]?",
   0.90)

# --- Private keys ---
_p("private_key",
   r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
   r"[\s\S]{50,}?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)",
   0.99, re.MULTILINE)

# --- Connection strings ---
_p("connection_string",
   r"\b((?:mongodb|postgres(?:ql)?|mysql|redis|amqp|mqtts?|sqlite)://"
   r"[^\s\"']+)\b",
   0.95)

# --- Physical addresses (basic) ---
_p("address",
   r"\b\d{1,5}\s+(?:(?:N|S|E|W|North|South|East|West|Calle|Av|Avenida|Pasaje|Blvd)\.?\s+)?"
   r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\s*(?:#|Apt|Suite|Depto|Piso|Floor)?\s*\d*\b",
   0.60, 0)

# --- Names in structured context ---
_p("person_name",
   r"(?:(?:name|nombre|patient|paciente|cliente|customer|usuario|user)"
   r"\s*[:=]\s*['\"]?)([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})['\"]?",
   0.75)


# ═══════════════════════════════════════════════════════
# Sanitizer class
# ═══════════════════════════════════════════════════════

class PIISanitizer:
    """
    Server-side PII detection and redaction engine.

    Args:
        reversible: If True, store originals for response de-sanitization.
                   WARNING: PII stays in memory. Only for same-request use.
        extra_patterns: Additional (category, compiled_regex, confidence) tuples.
    """

    def __init__(self, reversible: bool = False, extra_patterns: Optional[List] = None):
        self.reversible = reversible
        self.patterns = list(_PATTERNS)
        if extra_patterns:
            self.patterns.extend(extra_patterns)
        self._counter: Dict[str, int] = {}

    def _next_placeholder(self, category: str) -> str:
        self._counter[category] = self._counter.get(category, 0) + 1
        n = self._counter[category]
        return f"[REDACTED_{category.upper()}_{n}]"

    def sanitize(self, text: str) -> SanitizeResult:
        """Scan text, redact PII, return result with cleaned text."""
        if not text:
            return SanitizeResult(cleaned_text=text)

        self._counter = {}  # Reset counters per call
        raw_matches: List[PIIMatch] = []

        for category, pattern, confidence in self.patterns:
            for match in pattern.finditer(text):
                if match.lastindex and match.lastindex >= 1:
                    value = match.group(1)
                    start = match.start(1)
                    end = match.end(1)
                else:
                    value = match.group(0)
                    start = match.start(0)
                    end = match.end(0)

                if len(value.strip()) < 4:
                    continue

                # Credit card: Luhn validation
                if category == "credit_card":
                    digits_only = re.sub(r'\D', '', value)
                    if not _luhn_check(digits_only):
                        continue
                    confidence = 0.99

                # IP: skip loopback and common non-PII
                if category == "ip_address":
                    if value in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                        continue
                    octets = value.split(".")
                    if any(int(o) > 255 for o in octets if o.isdigit()):
                        continue

                placeholder = self._next_placeholder(category)
                raw_matches.append(PIIMatch(
                    category=category,
                    original=value,
                    placeholder=placeholder,
                    start=start,
                    end=end,
                    confidence=confidence,
                ))

        # Remove overlapping matches (keep highest confidence)
        raw_matches.sort(key=lambda m: (-m.confidence, m.start))
        final_matches: List[PIIMatch] = []
        used_ranges: List[Tuple[int, int]] = []

        for m in raw_matches:
            overlaps = any(
                not (m.end <= s or m.start >= e)
                for s, e in used_ranges
            )
            if not overlaps:
                final_matches.append(m)
                used_ranges.append((m.start, m.end))

        # Apply replacements (reverse order to preserve positions)
        final_matches.sort(key=lambda m: m.start, reverse=True)
        cleaned = text
        pii_map: Dict[str, str] = {}

        for m in final_matches:
            cleaned = cleaned[:m.start] + m.placeholder + cleaned[m.end:]
            if self.reversible:
                pii_map[m.placeholder] = m.original

        # Re-sort for output
        final_matches.sort(key=lambda m: m.start)

        return SanitizeResult(
            cleaned_text=cleaned,
            matches=final_matches,
            pii_map=pii_map if self.reversible else {},
        )

    def desanitize(self, text: str, pii_map: Dict[str, str]) -> str:
        """Reverse redaction in a response (only if reversible=True was used)."""
        result = text
        for placeholder, original in pii_map.items():
            result = result.replace(placeholder, original)
        return result

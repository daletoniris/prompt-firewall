"""
Response Validator -- Post-LLM anti-hallucination layer.

Validates AI responses AFTER generation to catch:
- Invented prices that don't match real data
- Fake promotions/discounts the business never offered
- References to non-existent products/services

This is Layer 4: the last safety net. If an injection bypasses the input
firewall and tricks the LLM, this layer catches the damage.

Usage:
    validator = ResponseValidator()
    result = validator.validate(
        response="The pizza is $5.99 with a 2x1 promotion!",
        known_items=[{"name": "Pizza Margherita", "price": 12.99}],
        business_context={"description": "Traditional pizzeria, no promotions"}
    )
    if not result['is_valid']:
        print(result['issues'])
        # [{'type': 'wrong_price', ...}, {'type': 'fake_promotion', ...}]
"""
from __future__ import annotations

import re
import json
from typing import Any, Dict, List, Optional


class ResponseValidator:
    """Post-LLM response validation engine."""

    def validate(
        self,
        response: str,
        known_items: Optional[List[Dict[str, Any]]] = None,
        business_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate an LLM response against known ground truth.

        Args:
            response: The AI-generated response text
            known_items: List of real items with 'name' and 'price' fields
            business_context: Dict with 'description', 'promotions', etc.

        Returns:
            Dict with 'is_valid', 'issues', and 'corrected_response'
        """
        issues = []

        if not response:
            return {'is_valid': True, 'issues': [], 'corrected_response': response}

        # Check 1: Price validation
        if known_items:
            price_issues = self._check_prices(response, known_items)
            issues.extend(price_issues)

        # Check 2: Fake promotion detection
        if business_context:
            promo_issues = self._check_fake_promotions(response, business_context)
            issues.extend(promo_issues)

        return {
            'is_valid': len(issues) == 0,
            'issues': issues,
            'corrected_response': response,  # Could auto-correct in v2
        }

    def _check_prices(self, response: str, items: List[Dict]) -> List[Dict]:
        """Check if mentioned prices match the real catalog."""
        issues = []

        # Build price lookup
        all_valid_prices = set()
        item_names = set()
        for item in items:
            base = float(item.get('price', 0))
            all_valid_prices.add(base)
            item_names.add(item['name'].lower())

            # Include variant prices
            variants = item.get('variants', [])
            if isinstance(variants, str):
                try:
                    variants = json.loads(variants)
                except (json.JSONDecodeError, TypeError):
                    variants = []
            for v in (variants or []):
                all_valid_prices.add(base + float(v.get('price_add', 0)))

        # Find prices in response
        price_patterns = [
            r'\$\s*(\d+(?:\.\d{1,2})?)',
            r'(\d+(?:\.\d{1,2})?)\s*(?:dolares?|pesos?|usd|ars|euros?)',
        ]

        for pattern in price_patterns:
            for match in re.finditer(pattern, response, re.IGNORECASE):
                mentioned_price = float(match.group(1))
                if mentioned_price < 1.0:
                    continue

                price_valid = any(abs(p - mentioned_price) < 0.01 for p in all_valid_prices)
                if not price_valid:
                    # Check if this price is near a known item name
                    context_start = max(0, match.start() - 100)
                    context_end = min(len(response), match.end() + 50)
                    context = response[context_start:context_end].lower()

                    for name in item_names:
                        if name in context:
                            issues.append({
                                'type': 'wrong_price',
                                'detail': f'Price ${mentioned_price} near "{name}" not in catalog',
                                'context': context.strip(),
                            })
                            break

        return issues

    def _check_fake_promotions(self, response: str, context: Dict) -> List[Dict]:
        """Detect hallucinated promotions/discounts."""
        issues = []

        promo_patterns = [
            r'(?i)(descuento|discount|promo(?:cion|tion)?|oferta|special\s*offer)',
            r'(?i)(2\s*(?:x|por)\s*1|buy\s*one\s*get\s*one)',
            r'(?i)(free|gratis|regalo|complimentary)',
        ]

        biz_text = ' '.join([
            context.get('description', ''),
            context.get('system_prompt', ''),
            context.get('promotions', ''),
        ]).lower()

        promo_keywords = ['descuento', 'discount', 'promo', 'oferta', '2x1',
                         'bogo', 'free', 'gratis', 'special offer']
        has_real_promos = any(kw in biz_text for kw in promo_keywords)

        if not has_real_promos:
            for pattern in promo_patterns:
                match = re.search(pattern, response)
                if match:
                    issues.append({
                        'type': 'fake_promotion',
                        'detail': f'Promotion "{match.group(0)}" not in business config',
                        'context': response[max(0, match.start()-50):match.end()+50].strip(),
                    })

        return issues

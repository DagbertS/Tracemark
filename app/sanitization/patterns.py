"""PII detection patterns — regex-based entity recognition.

Covers: email, phone (international + US/EU), credit card (Luhn-validated),
IBAN, Belgian national ID, and person names (heuristic).
"""

import re
from typing import List, Tuple


def _luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
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


# Each pattern: (name, compiled_regex, validator_fn or None)
# validator_fn receives the matched string and returns True if valid
PII_PATTERNS: List[Tuple[str, "re.Pattern[str]", object]] = [
    # Email addresses — RFC 5322 simplified
    (
        "email",
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        None,
    ),
    # Phone numbers — E.164 and common international formats
    # Matches: +32 2 123 45 67, +1-555-123-4567, (555) 123-4567, 555-123-4567
    (
        "phone",
        re.compile(
            r"(?:\+\d{1,3}[\s\-]?)?"           # optional country code
            r"(?:\(?\d{1,4}\)?[\s\-])?"          # optional area code
            r"\d{2,4}[\s\-]?\d{2,4}[\s\-]?\d{2,4}"  # number groups
            r"(?!\.\d)"                          # not a decimal/IP
        ),
        # Simple length validator — must have at least 7 digits
        lambda m: sum(c.isdigit() for c in m) >= 7,
    ),
    # Credit card numbers — 13-19 digits with optional separators
    (
        "credit_card",
        re.compile(
            r"\b(?:\d[\s\-]?){13,19}\b"
        ),
        lambda m: _luhn_check(m),
    ),
    # IBAN — International Bank Account Number
    (
        "iban",
        re.compile(
            r"\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?[\d]{0,4}[\s]?[\d]{0,2}\b"
        ),
        None,
    ),
    # Belgian national ID (Rijksregisternummer)
    (
        "belgian_national_id",
        re.compile(
            r"\b\d{2}\.\d{2}\.\d{2}[\-]\d{3}\.\d{2}\b"
        ),
        None,
    ),
    # Person names — heuristic: 2-3 capitalized words
    # Avoids common English words and technical terms
    (
        "name",
        re.compile(
            r"\b(?!(?:The|This|That|These|Those|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday"
            r"|January|February|March|April|May|June|July|August|September|October|November|December"
            r"|Hello|Please|Thank|Sorry|Dear|Best|Kind|Regards|Sincerely"
            r"|North|South|East|West|New|Old|Great|United|National"
            r"|AI|API|SDK|HTTP|JSON|SQL|REST|SSE|LLM)\b)"
            r"[A-Z][a-z]{1,20}\s[A-Z][a-z]{1,20}"
            r"(?:\s[A-Z][a-z]{1,20})?"
            r"\b"
        ),
        None,
    ),
]

# Common English words that look like names but aren't — used for filtering
COMMON_FALSE_POSITIVES = {
    "New York", "San Francisco", "Los Angeles", "Las Vegas",
    "North America", "South America", "East Coast", "West Coast",
    "United States", "United Kingdom", "New Zealand",
    "Good Morning", "Good Evening", "Good Afternoon",
    "Dear Sir", "Dear Madam", "Thank You",
    "Machine Learning", "Artificial Intelligence", "Data Science",
    "Open Source", "Cloud Computing", "Deep Learning",
}

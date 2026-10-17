"""Best-effort personal-information exclusion for generated passwords.

Comma- or newline-separated terms are matched case-insensitively after Unicode NFKC
normalization and removal of non-alphanumeric separators. This does not infer
all transliterations, encoded dates, or indirect personal references.
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable


def normalize_for_exclusion(value: str) -> str:
    """Case-fold and retain only Unicode letters and digits for comparisons."""
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(char for char in normalized if char.isalnum())


def _split_terms(raw_terms: str | Iterable[str]) -> list[str]:
    pieces = [raw_terms] if isinstance(raw_terms, str) else list(raw_terms)
    result: list[str] = []
    for piece in pieces:
        # A term may be separated by commas or line breaks. Split CRLF as one
        # boundary while accepting standalone CR and LF as well.
        result.extend(re.split(r",|\r\n|\r|\n", str(piece)))
    return result


def parse_exclusion_terms(raw_terms: str | Iterable[str] | None) -> list[str]:
    """Parse comma- or newline-separated terms and deduplicate normalized matches.

    Terms shorter than two normalized alphanumeric characters are rejected.
    """
    result: list[str] = []
    seen: set[str] = set()
    for piece in _split_terms(raw_terms or []):
        term = piece.strip()
        if not term:
            continue
        normalized = normalize_for_exclusion(term)
        if len(normalized) < 2:
            raise ValueError("Each exclusion term must contain at least two letters or numbers.")
        if normalized not in seen:
            result.append(term)
            seen.add(normalized)
    return result


def violates_exclusion(candidate: str, terms: Iterable[str]) -> bool:
    """Return whether a candidate contains a supported variation of any term."""
    normalized_candidate = normalize_for_exclusion(candidate)
    return any(
        normalized_term in normalized_candidate
        for term in terms
        if (normalized_term := normalize_for_exclusion(term))
    )

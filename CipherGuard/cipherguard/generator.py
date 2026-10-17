"""Cryptographically secure password generation with include/exclude constraints."""
from __future__ import annotations

import secrets
import string
from collections.abc import Iterable

from .exclusion import parse_exclusion_terms, normalize_for_exclusion, violates_exclusion

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MAX_GENERATION_ATTEMPTS = 1000
CHARACTER_SETS = {
    "uppercase": string.ascii_uppercase,
    "lowercase": string.ascii_lowercase,
    "numbers": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{};:,.?/",
}


class PasswordGenerationError(ValueError):
    """Raised when the requested password configuration is invalid."""


def parse_inclusion_terms(raw_terms: str | Iterable[str] | None) -> list[str]:
    """Parse comma-separated required terms, preserving case-sensitive values."""
    pieces = [raw_terms] if isinstance(raw_terms, str) else list(raw_terms or [])
    terms: list[str] = []
    seen: set[str] = set()
    for piece in pieces:
        for raw in str(piece).split(","):
            term = raw.strip()
            if term and term not in seen:
                terms.append(term)
                seen.add(term)
    return terms


def _contains_all(candidate: str, terms: Iterable[str]) -> bool:
    return all(term in candidate for term in terms)


def generate_password(
    length: int = 20,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    excluded_terms: Iterable[str] | str | None = None,
    included_terms: Iterable[str] | str | None = None,
) -> str:
    """Generate a secure password satisfying class, inclusion and exclusion rules.

    Required terms are preserved as contiguous blocks; remaining selected-class
    guarantees and filler characters are individual blocks. Blocks are shuffled
    with a cryptographic RNG, then the complete candidate is validated. This
    favors satisfying constraints over claiming perfectly uniform sampling over
    all valid constrained passwords.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise PasswordGenerationError("Password length must be a whole number.")
    if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
        raise PasswordGenerationError(
            f"Choose a password length between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}."
        )

    flags = {"uppercase": uppercase, "lowercase": lowercase, "numbers": numbers, "symbols": symbols}
    selected_sets = [chars for name, chars in CHARACTER_SETS.items() if flags[name]]
    if not selected_sets:
        raise PasswordGenerationError("Select at least one character type.")

    try:
        exclusions = parse_exclusion_terms(excluded_terms)
    except ValueError as exc:
        raise PasswordGenerationError(str(exc)) from exc
    inclusions = parse_inclusion_terms(included_terms)
    alphabet = "".join(selected_sets)

    # Every required character must be available in the selected character set.
    unavailable = sorted({char for term in inclusions for char in term if char not in alphabet})
    if unavailable:
        display = " ".join(repr(char) for char in unavailable[:8])
        raise PasswordGenerationError(
            f"Required entries contain characters outside the enabled character types ({display}). Enable the needed type or edit the required entries."
        )
    if any(violates_exclusion(term, exclusions) for term in inclusions):
        raise PasswordGenerationError("A required entry conflicts with an excluded term. Edit one of the fields and try again.")

    # Remove required terms already guaranteed as a substring of a longer term.
    effective_terms = [term for term in inclusions if not any(term != other and term in other for other in inclusions)]
    # Case-sensitive terms may overlap, but this conservative bound avoids silently
    # truncating any requirement. Category guarantees already covered by terms do
    # not need a separate seed character.
    required_chars = set("".join(inclusions))
    missing_class_count = sum(1 for chars in selected_sets if not any(c in chars for c in required_chars))
    minimum_size = sum(len(term) for term in effective_terms) + missing_class_count
    if minimum_size > length:
        raise PasswordGenerationError(
            f"These required entries and selected character types need at least {minimum_size} characters. Increase the password length or simplify the requirements."
        )

    for _ in range(MAX_GENERATION_ATTEMPTS):
        blocks = list(effective_terms)
        # Recompute class seeds for every candidate so retries remain randomized.
        blocks.extend(secrets.choice(chars) for chars in selected_sets if not any(c in chars for c in required_chars))
        remaining = length - sum(len(block) for block in blocks)
        blocks.extend(secrets.choice(alphabet) for _ in range(remaining))
        secrets.SystemRandom().shuffle(blocks)
        candidate = "".join(blocks)
        if len(candidate) != length or not _contains_all(candidate, inclusions):
            continue
        if any(not any(char in chars for char in candidate) for chars in selected_sets):
            continue
        if violates_exclusion(candidate, exclusions):
            continue
        return candidate
    raise PasswordGenerationError(
        "Could not find a password that satisfies these inclusion and exclusion rules. Remove or simplify a term, or change the character settings and try again."
    )

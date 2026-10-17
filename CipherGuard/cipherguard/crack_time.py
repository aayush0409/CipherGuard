"""Educational crack-time scenarios using deterministic, deliberately coarse heuristics.

This is not a password-cracking benchmark or a prediction of real attacker behavior.
Only summary metadata is returned; callers should not log or persist password input.
"""
from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass

COMMON_PASSWORDS = frozenset({
    "123456", "123456789", "12345678", "password", "password1",
    "qwerty", "qwerty123", "letmein", "admin", "welcome", "iloveyou",
    "abc123", "dragon", "monkey", "football", "sunshine", "princess",
    "master", "login", "passw0rd",
})
SEQUENCES = (
    "0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba", "qwertyuiop", "poiuytrewq",
    "asdfghjkl", "lkjhgfdsa", "zxcvbnm", "mnbvcxz",
)
SECONDS_PER_YEAR = 365.25 * 24 * 60 * 60


@dataclass(frozen=True)
class AttackScenario:
    key: str
    name: str
    guesses_per_second: float
    description: str
    assumptions: str


@dataclass(frozen=True)
class ScenarioEstimate:
    key: str
    name: str
    guesses_per_second: float
    description: str
    assumptions: str
    lower_time: str
    upper_time: str
    lower_log2_seconds: float
    upper_log2_seconds: float


@dataclass(frozen=True)
class CrackTimeEstimate:
    length: int
    effective_guess_bits: float
    observations: tuple[str, ...]
    scenarios: tuple[ScenarioEstimate, ...]


# Illustrative fixed rates, not claims about every service/device. A real service may
# lock accounts out; offline rates depend heavily on the hash and its work factor.
# Keep display order tied to numeric throughput: more guesses/second means a
# shorter estimate for the same password model. Do not sort formatted durations.
SCENARIOS = tuple(sorted((
    AttackScenario("rate-limited", "Rate-limited online", 1 / 600,
                   "About one guess every 10 minutes.",
                   "A strongly rate-limited login; lockouts or MFA can make guessing less useful."),
    AttackScenario("permissive-online", "Permissive online", 1,
                   "One guess per second.",
                   "A hypothetical endpoint allowing sustained guesses without effective lockout."),
    AttackScenario("slow-hash", "Offline, slow password hash", 1_000,
                   "1,000 guesses per second.",
                   "Illustrative attacker throughput for a deliberately expensive password hash; actual throughput varies widely."),
    AttackScenario("fast-hash", "Offline, fast hash", 10_000_000_000,
                   "10 billion guesses per second.",
                   "Illustrative high-throughput hardware against a fast, unsalted hash; not applicable to well-configured slow hashes."),
), key=lambda scenario: scenario.guesses_per_second, reverse=True))


def _fold(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _has_sequence(value: str) -> bool:
    folded = _fold(value)
    for sequence in SEQUENCES:
        for width in range(3, min(6, len(sequence)) + 1):
            if any(sequence[i:i + width] in folded
                   for i in range(len(sequence) - width + 1)):
                return True
    return False


def estimate_effective_guess_bits(password: str) -> tuple[float, tuple[str, ...]]:
    """Return a rough log2 guess-count and transparent pattern observations.

    The model is intentionally conservative for common/patterned strings. It is not
    calibrated to a cracking corpus and must not be interpreted as measured entropy.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be text.")
    if not password:
        return 0.0, ("No password entered.",)

    length = len(password)
    folded = _fold(password)
    has_lower = any(char.islower() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(not char.isalnum() and not char.isspace() for char in password)
    groups = sum((has_lower, has_upper, has_digit, has_symbol))
    # Approximate per-character contribution based on visible character categories,
    # with a diminishing contribution after long lengths to avoid absurd precision.
    if has_symbol:
        bits_per_char = 6.55 if groups >= 3 else 6.0
    elif has_digit and (has_lower or has_upper):
        bits_per_char = 6.15 if groups >= 3 else 5.7
    elif has_lower and has_upper:
        bits_per_char = 5.7
    elif has_lower or has_upper:
        bits_per_char = 4.7
    elif has_digit:
        bits_per_char = 3.3
    else:
        bits_per_char = 4.0
    # Long strings do not get a limitless linear bonus from this crude model.
    raw_bits = sum(min(bits_per_char, max(2.0, bits_per_char * (1 - max(0, i - 24) / 120)))
                   for i in range(length))
    observations: list[str] = []

    if folded in COMMON_PASSWORDS:
        raw_bits = min(raw_bits, 5.0)
        observations.append("Matches a common password or familiar pattern.")
    else:
        common_tokens = ("password", "qwerty", "letmein", "admin", "welcome", "iloveyou")
        token = next((word for word in common_tokens if word in folded), None)
        if token:
            raw_bits -= min(24.0, 8.0 + len(token) * 1.5)
            raw_bits = min(raw_bits, max(12.0, length * 1.5))
            observations.append("Contains a recognizable common-password word.")

    if _has_sequence(password):
        raw_bits -= min(18.0, max(8.0, length * 0.7))
        raw_bits = min(raw_bits, max(12.0, length * 1.5))
        observations.append("Contains a familiar numeric, alphabetic, or keyboard sequence.")
    unique = len(set(password))
    if unique <= max(1, length // 3):
        raw_bits -= min(45.0, length * 1.4)
        raw_bits = min(raw_bits, max(8.0, unique * 3.0 + length * 0.3))
        observations.append("Contains substantial character repetition.")
    elif re.search(r"(.)\1{2,}", password):
        raw_bits -= 8.0
        observations.append("Contains a run of repeated characters.")
    if re.search(r"(19|20)\d{2}", password):
        raw_bits -= 5.0
        observations.append("Contains a year-like number.")
    if re.search(r"(.{2,})\1", password, re.IGNORECASE):
        raw_bits -= min(20.0, length * 0.6)
        observations.append("Contains a repeated multi-character chunk.")
    if groups == 1 and length < 12:
        raw_bits -= 3.0
        observations.append("Uses one character category and is short.")
    if not observations:
        observations.append("No obvious common pattern detected by these basic checks.")
    # This cap is for stable logarithmic math, not a claim that a password has this entropy.
    return max(0.0, min(1024.0, raw_bits)), tuple(dict.fromkeys(observations))


def format_duration_from_log2_seconds(log2_seconds: float) -> str:
    """Format a duration represented as log2(seconds), avoiding huge exponentiation."""
    if math.isnan(log2_seconds):
        return "not estimable"
    if math.isinf(log2_seconds):
        return "an astronomically large duration" if log2_seconds > 0 else "under 1 second"
    if log2_seconds <= math.log2(1):
        return "under 1 second"
    log10_seconds = log2_seconds * math.log10(2)
    if log10_seconds < math.log10(60):
        return "under 1 minute" if log10_seconds >= 0 else "under 1 second"
    units = ((math.log10(60), "minute", 60),
             (math.log10(3600), "hour", 3600),
             (math.log10(86400), "day", 86400),
             (math.log10(SECONDS_PER_YEAR), "year", SECONDS_PER_YEAR),
             (math.log10(1000 * SECONDS_PER_YEAR), "millennium", 1000 * SECONDS_PER_YEAR))
    if log10_seconds >= 18:
        years_log10 = log10_seconds - math.log10(SECONDS_PER_YEAR)
        exponent = math.floor(years_log10)
        return f"about 10^{exponent} years" if exponent < 1000 else "an astronomically large duration"
    unit_name, unit_seconds = "second", 1
    for threshold, name, seconds in units:
        if log10_seconds >= threshold:
            unit_name, unit_seconds = name, seconds
    amount_log10 = log10_seconds - math.log10(unit_seconds)
    amount = 10 ** amount_log10
    rounded = max(1, round(amount))
    if unit_name in ("year", "millennium") and rounded >= 1000:
        return f"about {rounded:,} {unit_name}s"
    return f"about {rounded:,} {unit_name}{'' if rounded == 1 else 's'}"


def estimate_crack_time(password: str) -> CrackTimeEstimate:
    """Estimate coarse median-guess time ranges under documented hypothetical rates."""
    bits, observations = estimate_effective_guess_bits(password)
    scenarios = []
    for scenario in SCENARIOS:
        # A broad 4x range around a median-ish guess estimate, rather than a false exact time.
        lower_log2 = max(-20.0, bits - 2.0 - math.log2(scenario.guesses_per_second))
        upper_log2 = max(-20.0, bits - math.log2(scenario.guesses_per_second))
        scenarios.append(ScenarioEstimate(
            scenario.key, scenario.name, scenario.guesses_per_second,
            scenario.description, scenario.assumptions,
            format_duration_from_log2_seconds(lower_log2),
            format_duration_from_log2_seconds(upper_log2), lower_log2, upper_log2,
        ))
    return CrackTimeEstimate(len(password), bits, observations, tuple(scenarios))

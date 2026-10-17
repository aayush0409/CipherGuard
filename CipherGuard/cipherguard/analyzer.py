"""Deterministic heuristic password analysis; results are estimates, not guarantees."""
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
THRESHOLDS = ((20, "Very Weak"), (40, "Weak"), (60, "Fair"),
              (80, "Strong"), (101, "Very Strong"))


@dataclass(frozen=True)
class AnalysisResult:
    score: int
    rating: str
    length: int
    unique_characters: int
    character_groups: int
    weaknesses: tuple[str, ...]
    positives: tuple[str, ...]
    recommendations: tuple[str, ...]


def _contains_sequence(value: str) -> bool:
    folded = unicodedata.normalize("NFKC", value).casefold()
    for sequence in SEQUENCES:
        for width in range(3, min(6, len(sequence)) + 1):
            if any(sequence[i:i + width] in folded
                   for i in range(len(sequence) - width + 1)):
                return True
    return False


def analyze_password(password: str) -> AnalysisResult:
    """Analyze in memory only. The caller is responsible for not persisting input."""
    if not isinstance(password, str):
        raise TypeError("Password must be text.")
    length = len(password)
    if not password:
        return AnalysisResult(
            0, "Very Weak", 0, 0, 0,
            ("Enter a password to begin analysis.",), (),
            ("Use a unique password or passphrase of at least 16 characters.",),
        )

    folded = unicodedata.normalize("NFKC", password).casefold()
    groups = sum((
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() and not c.isspace() for c in password),
    ))
    unique = len(set(password))
    score = 0
    weaknesses, positives, recommendations = [], [], []

    if length < 8:
        score += 4
        weaknesses.append("Very short length makes guessing easier.")
        recommendations.append("Use at least 16 characters for an important account.")
    elif length < 12:
        score += 15
        weaknesses.append("Shorter than the recommended length for a strong password.")
        recommendations.append("Increase the length to 16 characters or more.")
    elif length < 16:
        score += 28
        weaknesses.append("Moderate length; a longer password would improve resilience.")
        recommendations.append("Prefer 16–20 or more characters.")
    elif length < 20:
        score += 42
        positives.append("Good length provides a useful foundation.")
    elif length < 24:
        score += 60
        positives.append("Long password length is a positive security signal.")
    else:
        score += 72
        positives.append("Very long password length is a positive security signal.")

    if groups >= 3:
        score += 8
        positives.append("Uses several character categories.")
    elif groups == 2:
        score += 4
        positives.append("Uses more than one character category.")
    else:
        weaknesses.append("Uses only one character category.")
        recommendations.append("Consider a longer passphrase with less predictable wording.")

    if unique <= max(1, length // 3):
        score -= 22
        weaknesses.append("Contains substantial character repetition.")
        recommendations.append("Avoid repeated characters and repeated chunks.")
    elif re.search(r"(.)\\1{2,}", password):
        score -= 12
        weaknesses.append("Contains a run of repeated characters.")
        recommendations.append("Replace repeated runs with unrelated characters.")

    if folded in COMMON_PASSWORDS:
        score = min(score, 5)
        weaknesses.append("Matches a common password in the bundled reference list.")
        recommendations.append("Replace it with a unique password not based on a common phrase.")
    elif any(word in folded for word in ("password", "qwerty", "letmein", "admin")):
        score -= 15
        weaknesses.append("Contains a recognizable common-password word.")
        recommendations.append("Avoid common words and familiar password templates.")

    if _contains_sequence(password):
        score -= 18
        weaknesses.append("Contains a recognizable alphabetic, numeric, or keyboard sequence.")
        recommendations.append("Avoid sequences such as 123456, abcdef, or keyboard walks.")

    if re.search(r"(19|20)\\d{2}", password):
        score -= 8
        weaknesses.append("Contains a year-like number that may be predictable.")
        recommendations.append("Avoid years and date-like patterns others could guess.")

    if re.search(r"(.{2,})\\1", password, re.IGNORECASE):
        score -= 12
        weaknesses.append("Contains a repeated multi-character substring.")
        recommendations.append("Avoid repeating a word, chunk, or template.")

    if re.search(r"(?:p[a@]ssw[o0]rd|[a@]dm[i1]n)", folded):
        score -= 10
        weaknesses.append("Contains a predictable word with a common character substitution.")
        recommendations.append("Do not rely on substitutions such as @ for a or 0 for o.")

    score = max(0, min(100, score))
    if any("common password" in item.lower() or "sequence" in item.lower()
           for item in weaknesses):
        score = min(score, 59)
    rating = next(name for threshold, name in THRESHOLDS if score < threshold)
    if not recommendations:
        recommendations.append("Use it for one account only and store it in a reputable password manager.")
    return AnalysisResult(
        score, rating, length, unique, groups,
        tuple(dict.fromkeys(weaknesses)), tuple(dict.fromkeys(positives)),
        tuple(dict.fromkeys(recommendations)),
    )

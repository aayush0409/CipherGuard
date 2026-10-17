"""Deterministic tests for the educational password analysis heuristic."""
import pytest
from cipherguard.analyzer import analyze_password


def test_empty_input_is_handled_without_exception():
    result = analyze_password("")
    assert result.score == 0
    assert result.rating == "Very Weak"
    assert "Enter a password" in result.weaknesses[0]


@pytest.mark.parametrize("password", ["a", "12", "abc"])
def test_very_short_passwords_are_very_weak(password):
    result = analyze_password(password)
    assert result.rating == "Very Weak"
    assert result.length == len(password)


def test_long_password_length_is_counted():
    value = "R7!vQ2#mL9@xT4$kP8zN"
    result = analyze_password(value)
    assert result.length == len(value)
    assert result.unique_characters == len(set(value))


@pytest.mark.parametrize("password", ["password", "123456", "qwerty"])
def test_common_passwords_are_very_weak(password):
    assert analyze_password(password).rating == "Very Weak"
    assert any("common password" in item.lower() for item in analyze_password(password).weaknesses)


def test_repeated_characters_are_flagged():
    result = analyze_password("aaaaaaaaaaaaaaaaaaaa")
    assert any("repetition" in item.lower() or "repeated" in item.lower() for item in result.weaknesses)
    assert result.rating in {"Very Weak", "Weak", "Fair"}


@pytest.mark.parametrize("password", ["Abcdef123!xyz", "Qwerty123!Long", "Secure9876!"])
def test_sequences_and_keyboard_patterns_are_flagged(password):
    result = analyze_password(password)
    assert any("sequence" in item.lower() for item in result.weaknesses)
    assert result.score < 60


def test_mixed_character_predictable_password_does_not_score_very_strong():
    result = analyze_password("Qwerty123!Long")
    assert result.rating != "Very Strong"


def test_long_varied_password_without_obvious_patterns_scores_higher():
    result = analyze_password("vN8$kR2!pL6@xT9#cW4&")
    assert result.score >= 50
    assert result.rating in {"Strong", "Very Strong"}


def test_scoring_is_deterministic_and_thresholds_consistent():
    first = analyze_password("password")
    second = analyze_password("password")
    assert first == second
    assert 0 <= first.score <= 100
    if first.score < 20:
        assert first.rating == "Very Weak"
    elif first.score < 40:
        assert first.rating == "Weak"
    elif first.score < 60:
        assert first.rating == "Fair"
    elif first.score < 80:
        assert first.rating == "Strong"
    else:
        assert first.rating == "Very Strong"


def test_non_string_input_is_rejected():
    with pytest.raises(TypeError):
        analyze_password(None)

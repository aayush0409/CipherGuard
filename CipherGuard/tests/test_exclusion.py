"""Tests for best-effort personal-information exclusion."""
import pytest

from cipherguard.exclusion import normalize_for_exclusion, parse_exclusion_terms, violates_exclusion
from cipherguard.generator import PasswordGenerationError, generate_password


def test_normalization_ignores_case_and_separators():
    assert normalize_for_exclusion("Jane Doe") == "janedoe"
    assert violates_exclusion("JANE-doe_42", ["Jane Doe"])
    assert violates_exclusion("xxjanedoeYY", ["Jane Doe"])


def test_different_terms_can_be_supplied_and_duplicates_are_removed():
    assert parse_exclusion_terms("Jane Doe\n\nJANE-DOE\n2001") == ["Jane Doe", "2001"]


def test_short_exclusion_term_is_rejected():
    with pytest.raises(ValueError, match="at least two"):
        parse_exclusion_terms(["!"])


def test_generator_never_returns_supported_exclusion_match():
    terms = ["Aayush-Prasad", "1989-12-31"]
    for _ in range(20):
        value = generate_password(length=24, excluded_terms=terms)
        assert not violates_exclusion(value, terms)


def test_generator_rejects_too_short_exclusion_term():
    # A normalized one-character term is rejected before candidate generation.
    with pytest.raises(PasswordGenerationError, match="at least two"):
        generate_password(length=20, excluded_terms=["a"])


def test_unicode_nfkc_and_casefold_normalization():
    assert normalize_for_exclusion("Ｆｏｏ-BAR") == "foobar"
    assert violates_exclusion("xxFOObarYY", ["Ｆｏｏ bar"])


def test_empty_terms_do_not_reject_candidates():
    assert parse_exclusion_terms("\n  \n") == []
    assert not violates_exclusion("SecurePassword42!", [])


def test_duplicate_terms_normalize_before_deduplication():
    assert parse_exclusion_terms(["Jane Doe", "JANE-DOE", "jane_doe"]) == ["Jane Doe"]


def test_comma_separated_exclusions_trim_empty_and_deduplicate():
    assert parse_exclusion_terms(" Jane Doe, , JANE-DOE, 2001 ,, delhi ") == ["Jane Doe", "2001", "delhi"]


def test_exclusion_normalization_handles_unicode_and_separators():
    assert violates_exclusion("xxＦｏｏ_bar99", ["Foo bar"])


def test_exclusion_retries_are_bounded(monkeypatch):
    import cipherguard.generator as generator

    monkeypatch.setattr(generator, "MAX_GENERATION_ATTEMPTS", 2)
    # Every generated character is 'a', so the excluded term always matches.
    monkeypatch.setattr(generator.secrets, "choice", lambda seq: "a")
    monkeypatch.setattr(generator.secrets.SystemRandom, "shuffle", lambda self, values: None)
    with pytest.raises(PasswordGenerationError, match="Could not find a password"):
        generate_password(length=8, uppercase=False, lowercase=True, numbers=False, symbols=False, excluded_terms="aa")


def test_comma_and_newline_separators_trim_empty_and_deduplicate():
    assert parse_exclusion_terms(" Jane Doe, , JANE-DOE\n\n2001, delhi ") == ["Jane Doe", "2001", "delhi"]
    assert parse_exclusion_terms("Jane Doe\n\nJANE-DOE\n2001") == ["Jane Doe", "2001"]


def test_invalid_term_on_newline_is_rejected():
    with pytest.raises(ValueError, match="at least two"):
        parse_exclusion_terms("x\nPrivateUniqueTerm9981")


def test_crlf_newline_entries_are_supported():
    assert parse_exclusion_terms("Jane Doe\r\nJANE-DOE\r\n2001") == ["Jane Doe", "2001"]

"""Unit tests for secure generation and combined constraints."""
import pytest

from cipherguard.generator import (
    MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, PasswordGenerationError,
    generate_password, parse_inclusion_terms,
)
from cipherguard.exclusion import violates_exclusion

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"


def assert_classes(value, uppercase=True, lowercase=True, numbers=True, symbols=True):
    if uppercase: assert any(c.isupper() for c in value)
    if lowercase: assert any(c.islower() for c in value)
    if numbers: assert any(c.isdigit() for c in value)
    if symbols: assert any(c in SYMBOLS for c in value)


def test_default_password_has_expected_length_and_all_classes():
    value = generate_password()
    assert len(value) == 20
    assert_classes(value)


def test_selected_character_class_is_enforced():
    value = generate_password(16, uppercase=False, lowercase=False, numbers=True, symbols=False)
    assert len(value) == 16 and value.isdigit()


def test_minimum_and_maximum_lengths_are_supported():
    assert len(generate_password(MIN_PASSWORD_LENGTH)) == MIN_PASSWORD_LENGTH
    assert len(generate_password(MAX_PASSWORD_LENGTH)) == MAX_PASSWORD_LENGTH


@pytest.mark.parametrize("length", [True, 7, 129, -1, "20", 3.5])
def test_invalid_length_is_rejected(length):
    with pytest.raises(PasswordGenerationError): generate_password(length=length)


def test_no_character_sets_is_rejected():
    with pytest.raises(PasswordGenerationError, match="Select at least one"):
        generate_password(uppercase=False, lowercase=False, numbers=False, symbols=False)


def test_too_short_length_is_rejected_before_class_validation():
    with pytest.raises(PasswordGenerationError, match="between 8 and 128"):
        generate_password(length=7)


def test_multiple_required_terms_and_case_sensitivity():
    value = generate_password(24, included_terms="CG, @, 7, Z")
    assert len(value) == 24
    assert all(term in value for term in ["CG", "@", "7", "Z"])
    assert_classes(value)


def test_long_required_term_is_kept_contiguous():
    value = generate_password(32, included_terms="CipherGuard42")
    assert "CipherGuard42" in value
    assert len(value) == 32


def test_duplicate_required_terms_are_deduplicated_exactly():
    assert parse_inclusion_terms("CG, CG, cg, , @") == ["CG", "cg", "@"]
    value = generate_password(20, included_terms="CG, CG")
    assert value.count("CG") >= 1


def test_required_character_outside_enabled_categories_errors():
    with pytest.raises(PasswordGenerationError, match="outside the enabled character types"):
        generate_password(20, uppercase=False, lowercase=True, numbers=False, symbols=False, included_terms="A")


def test_impossible_combined_length_errors():
    with pytest.raises(PasswordGenerationError, match="need at least"):
        generate_password(8, uppercase=True, lowercase=True, numbers=True, symbols=True, included_terms="ABCD, efgh")


def test_inclusion_conflicting_with_exclusion_errors():
    with pytest.raises(PasswordGenerationError, match="conflicts with an excluded term"):
        generate_password(20, included_terms="JaneDoe", excluded_terms="jane-doe")


def test_all_classes_inclusions_exclusions_and_length_hold_together():
    exclusions = "Aayush, delhi, 5623"
    inclusions = "CG, @, 7, Z"
    for _ in range(10):
        value = generate_password(32, excluded_terms=exclusions, included_terms=inclusions)
        assert len(value) == 32
        assert all(term in value for term in ["CG", "@", "7", "Z"])
        assert not violates_exclusion(value, ["Aayush", "delhi", "5623"])
        assert_classes(value)


def test_empty_constraints_work_normally():
    assert len(generate_password(24, excluded_terms=" , ,", included_terms=" , ")) == 24

"""Deterministic tests for educational crack-time scenario estimates."""
import math

import pytest

from cipherguard.crack_time import (
    SCENARIOS,
    estimate_crack_time,
    estimate_effective_guess_bits,
    format_duration_from_log2_seconds,
)


def test_empty_and_very_short_inputs_are_handled():
    empty = estimate_crack_time("")
    assert empty.length == 0
    assert empty.effective_guess_bits == 0
    assert len(empty.scenarios) >= 3
    assert estimate_crack_time("a").effective_guess_bits <= 1
    assert estimate_crack_time("aB7!").length == 4


@pytest.mark.parametrize("password", ["password", "123456", "qwerty", "letmein"])
def test_common_passwords_get_a_small_guess_estimate(password):
    bits, observations = estimate_effective_guess_bits(password)
    assert bits <= 5
    assert any("common password" in item.lower() for item in observations)


def test_sequences_and_predictable_patterns_reduce_estimate():
    common = estimate_crack_time("Qwerty123!Long")
    varied = estimate_crack_time("vN8$kR2!pL6@xT9#cW4&")
    assert common.effective_guess_bits < varied.effective_guess_bits
    assert any("sequence" in item.lower() or "common-password" in item.lower()
               for item in common.observations)


def test_long_varied_password_has_more_effective_guess_bits():
    short_bits, _ = estimate_effective_guess_bits("aB3!")
    long_bits, _ = estimate_effective_guess_bits("vN8$kR2!pL6@xT9#cW4&")
    assert long_bits > short_bits
    assert long_bits <= 1024


def test_scenarios_are_ordered_fastest_to_slowest_with_paired_metadata():
    expected = ["fast-hash", "slow-hash", "permissive-online", "rate-limited"]
    estimate = estimate_crack_time("A longish unique phrase 9!x")
    assert [scenario.key for scenario in SCENARIOS] == expected
    assert [scenario.key for scenario in estimate.scenarios] == expected
    assert len(estimate.scenarios) == 4
    assert len({scenario.key for scenario in estimate.scenarios}) == 4
    assert [scenario.guesses_per_second for scenario in estimate.scenarios] == sorted(
        (scenario.guesses_per_second for scenario in estimate.scenarios), reverse=True
    )
    for scenario, source in zip(estimate.scenarios, SCENARIOS):
        assert scenario.name == source.name
        assert scenario.guesses_per_second == source.guesses_per_second
        assert scenario.description == source.description
        assert scenario.assumptions == source.assumptions
        assert scenario.lower_time and scenario.upper_time


@pytest.mark.parametrize("password", [
    "", "a", "password", "123456", "qwerty123", "aaaaaaaaaaaa",
    "vN8$kR2!pL6@xT9#cW4&", "X9!mQ2#vL7@pR5$kD8&zN4*eT6",
])
def test_scenario_order_is_stable_for_different_passwords(password):
    estimate = estimate_crack_time(password)
    assert [scenario.key for scenario in estimate.scenarios] == [
        "fast-hash", "slow-hash", "permissive-online", "rate-limited"
    ]


def test_duration_formatting_handles_small_and_extremely_large_values():
    assert format_duration_from_log2_seconds(-1) == "under 1 second"
    assert format_duration_from_log2_seconds(1) == "under 1 minute"
    assert "years" in format_duration_from_log2_seconds(1000)
    assert format_duration_from_log2_seconds(100_000) == "an astronomically large duration"
    assert format_duration_from_log2_seconds(math.inf) == "an astronomically large duration"


def test_estimates_are_deterministic_and_password_type_is_validated():
    first = estimate_crack_time("vN8$kR2!pL6@xT9#cW4&")
    second = estimate_crack_time("vN8$kR2!pL6@xT9#cW4&")
    assert first == second
    with pytest.raises(TypeError, match="text"):
        estimate_crack_time(None)

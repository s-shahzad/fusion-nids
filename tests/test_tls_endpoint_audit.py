import pytest

from scripts.tls_endpoint_audit import _parse_https_target, _validate_numeric_inputs


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf")])
def test_rejects_invalid_timeout(value):
    with pytest.raises(ValueError, match="Timeout"):
        _validate_numeric_inputs(value, 14.0)


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf")])
def test_rejects_invalid_minimum_validity(value):
    with pytest.raises(ValueError, match="Minimum validity"):
        _validate_numeric_inputs(5.0, value)


def test_accepts_zero_validity_threshold_and_default_port():
    _validate_numeric_inputs(5.0, 0.0)
    assert _parse_https_target("https://example.test") == ("example.test", 443)


def test_rejects_explicit_zero_port():
    with pytest.raises(ValueError, match="invalid port"):
        _parse_https_target("https://example.test:0")

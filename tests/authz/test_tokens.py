from __future__ import annotations

import pytest

from sentinel_arena.authz import expected_token, make_challenge
from sentinel_arena.authz.tokens import tokens_match

SECRET = b"s3cret"


def test_token_is_deterministic():
    a = expected_token("user1", "example.com", secret=SECRET)
    b = expected_token("user1", "example.com", secret=SECRET)
    assert a == b


def test_token_varies_by_user_and_host():
    base = expected_token("user1", "example.com", secret=SECRET)
    assert base != expected_token("user2", "example.com", secret=SECRET)
    assert base != expected_token("user1", "other.com", secret=SECRET)
    assert base != expected_token("user1", "example.com", secret=SECRET, rotation=1)


def test_host_is_normalized():
    assert expected_token("u", "Example.COM.", secret=SECRET) == expected_token(
        "u", "example.com", secret=SECRET
    )


@pytest.mark.parametrize("bad", ["http://example.com", "example.com/path", "a b", "host:443", "*.example.com", ""])
def test_rejects_non_bare_hosts(bad):
    with pytest.raises(ValueError):
        expected_token("u", bad, secret=SECRET)


def test_empty_secret_or_user_rejected():
    with pytest.raises(ValueError):
        expected_token("u", "example.com", secret=b"")
    with pytest.raises(ValueError):
        expected_token("", "example.com", secret=SECRET)


def test_challenge_artifacts():
    ch = make_challenge("user1", "example.com", secret=SECRET)
    assert ch.token in ch.dns_txt_value
    assert ch.dns_txt_name == "_sentinel-arena-site-verification.example.com"
    assert ch.well_known_url == "https://example.com/.well-known/sentinel-arena.txt"
    assert ch.token in ch.meta_tag and "meta" in ch.meta_tag
    assert ch.well_known_body == ch.token


def test_tokens_match_constant_time():
    assert tokens_match("abc", " abc ")
    assert not tokens_match("abc", "abd")

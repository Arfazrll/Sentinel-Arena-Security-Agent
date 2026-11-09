from __future__ import annotations

from datetime import datetime, timezone

from sentinel_arena.authz import OwnershipVerifier, VerificationMethod, make_challenge
from conftest import FakeDns, FakeHttp

SECRET = b"test-secret-not-for-production"
CLOCK = lambda: datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _challenge(host="staging.example.com", user="user1"):
    return make_challenge(user, host, secret=SECRET)


def test_dns_txt_verifies_when_record_present():
    ch = _challenge()
    dns = FakeDns({f"_sentinel-arena-site-verification.{ch.host}": [ch.dns_txt_value]})
    v = OwnershipVerifier(dns=dns, clock=CLOCK)
    res = v.verify(ch, VerificationMethod.DNS_TXT)
    assert res.verified


def test_dns_txt_accepts_bare_token_value():
    ch = _challenge()
    dns = FakeDns({f"_sentinel-arena-site-verification.{ch.host}": [ch.token]})
    res = OwnershipVerifier(dns=dns, clock=CLOCK).verify(ch, VerificationMethod.DNS_TXT)
    assert res.verified


def test_dns_txt_fails_without_record():
    ch = _challenge()
    v = OwnershipVerifier(dns=FakeDns({}), clock=CLOCK)
    res = v.verify(ch, VerificationMethod.DNS_TXT)
    assert not res.verified


def test_dns_txt_rejects_another_users_token():
    mine = _challenge(user="user1")
    other = _challenge(user="user2")
    dns = FakeDns({f"_sentinel-arena-site-verification.{mine.host}": [other.dns_txt_value]})
    res = OwnershipVerifier(dns=dns, clock=CLOCK).verify(mine, VerificationMethod.DNS_TXT)
    assert not res.verified


def test_well_known_verifies():
    ch = _challenge()
    http = FakeHttp({ch.well_known_url: f"# comment\n{ch.token}\n"})
    res = OwnershipVerifier(http=http, clock=CLOCK).verify(ch, VerificationMethod.WELL_KNOWN_FILE)
    assert res.verified


def test_well_known_fetch_failure_is_not_a_crash():
    ch = _challenge()
    res = OwnershipVerifier(http=FakeHttp({}), clock=CLOCK).verify(
        ch, VerificationMethod.WELL_KNOWN_FILE
    )
    assert not res.verified and "fetch failed" in res.detail


def test_meta_tag_verifies():
    ch = _challenge()
    html = f'<html><head>{ch.meta_tag}</head><body>hi</body></html>'
    http = FakeHttp({f"https://{ch.host}/": html})
    res = OwnershipVerifier(http=http, clock=CLOCK).verify(ch, VerificationMethod.META_TAG)
    assert res.verified


def test_meta_tag_wrong_token_fails():
    ch = _challenge()
    html = '<meta name="sentinel-arena-site-verification" content="wrong">'
    http = FakeHttp({f"https://{ch.host}/": html})
    res = OwnershipVerifier(http=http, clock=CLOCK).verify(ch, VerificationMethod.META_TAG)
    assert not res.verified

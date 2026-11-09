from __future__ import annotations

import urllib.request

import pytest

from sentinel_arena.range.vulnerable_app import AppConfig, start_app


@pytest.fixture
def app():
    cfg = AppConfig(token="tok123", flag_path="/secretflag", admin_path="/xyz-admin",
                    flag_value="FLAG{deadbeef}", credential="hunter2")
    server, base_url, _ = start_app(cfg)
    yield cfg, base_url
    server.shutdown()
    server.server_close()


def _get(url, actor="tester"):
    req = urllib.request.Request(url, headers={"X-Arena-Actor": actor})
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers or {})


def test_health_ok_and_secure(app):
    cfg, base = app
    status, body, headers = _get(base + "/health")
    assert status == 200 and body == "ok"
    assert "X-Frame-Options" in headers  # health is served securely


def test_homepage_leaks_admin_path_and_lacks_headers(app):
    cfg, base = app
    status, body, headers = _get(base + "/")
    assert status == 200
    assert cfg.admin_path in body  # planted info leak
    assert "Content-Security-Policy" not in headers  # planted A05


def test_well_known_serves_token(app):
    cfg, base = app
    status, body, _ = _get(base + "/.well-known/sentinel-arena.txt")
    assert status == 200 and body == "tok123"


def test_reflected_search(app):
    cfg, base = app
    status, body, _ = _get(base + "/search?q=ZZmarkerZZ")
    assert "ZZmarkerZZ" in body


def test_admin_discloses_flag_path_and_flag_is_readable(app):
    cfg, base = app
    _, admin_body, _ = _get(base + cfg.admin_path)
    assert cfg.flag_path in admin_body
    status, flag_body, _ = _get(base + cfg.flag_path)
    assert status == 200 and flag_body == "FLAG{deadbeef}"


def test_blocked_actor_is_forbidden_but_health_still_up(app):
    cfg, base = app
    cfg.blocked_actors.add("baddie")
    status, _, _ = _get(base + "/", actor="baddie")
    assert status == 403
    # Health still answers for everyone (service-liveness separate from access).
    status_h, _, _ = _get(base + "/health", actor="baddie")
    assert status_h == 200

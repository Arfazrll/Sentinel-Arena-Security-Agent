from __future__ import annotations

from sentinel_arena.scenarios import list_scenarios, load_scenario


def test_shop01_loads_and_validates():
    s = load_scenario("shop-01")
    assert s.id == "shop-01"
    assert s.max_ticks > 0
    assert any(w.detect == "reflected_xss" for w in s.weaknesses)


def test_scenario_listing_includes_shop01():
    assert "shop-01" in list_scenarios()


def test_randomizer_is_deterministic_per_seed():
    s = load_scenario("shop-01")
    a = s.randomized(42)
    b = s.randomized(42)
    assert a == b


def test_randomizer_varies_by_seed():
    s = load_scenario("shop-01")
    assert s.randomized(1).flag_path != s.randomized(2).flag_path
    assert s.randomized(1).flag_value != s.randomized(2).flag_value


def test_randomized_paths_differ_from_template():
    s = load_scenario("shop-01")
    r = s.randomized(42)
    # Both flag_path and admin_path are in the randomize list.
    assert r.flag_path != s.flag_path
    assert r.admin_path != s.admin_path
    assert r.flag_value.startswith("FLAG{")

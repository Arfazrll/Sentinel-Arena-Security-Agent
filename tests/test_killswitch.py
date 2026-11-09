"""The kill switch must halt an engagement immediately (invariant #7)."""

from __future__ import annotations

from sentinel_arena.engagement import run_engagement
from sentinel_arena.engine.killswitch import KillSwitch


def test_killswitch_halts_engagement_early(tmp_path):
    ks = KillSwitch()

    # Trip the switch the moment the first event is emitted.
    def on_event(ev):
        ks.trip("test")

    art = run_engagement("shop-01", seed=42, blue_name="scripted",
                         out_dir=tmp_path / "kill", killswitch=ks, on_event=on_event)
    # It stopped almost immediately rather than running all 12 ticks.
    assert art.result.ended_reason.startswith("killswitch")
    assert art.result.ticks_run < 12


def test_killswitch_reports_reason():
    ks = KillSwitch()
    assert not ks.tripped
    ks.trip("manual halt")
    assert ks.tripped and ks.reason == "manual halt"

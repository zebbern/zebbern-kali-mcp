"""pivot_add_pivot dropped the method and lied about subnet being optional.

Found by calling it and reading the reply. Both faults are the family this
sweep keeps turning up -- the wrapper's declared interface and what the backend
does are two different things:

  method   documented as "ssh, chisel, ligolo, socat", sent in the request body,
           and read by nobody. Pivot had no such field, so a pivot recorded as
           chisel came back field-for-field identical to an ssh one.
  subnet   declared `subnet: str = ""`, so the signature says optional, while
           the route requires internal_network and answers 400. Every call that
           trusted the default failed.

A pivot is a record an operator builds a route out of, so losing how it is
reached is losing the half that says what to do with it.
"""

import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.network_pivot import Pivot  # noqa: E402

WRAPPER_SRC = (
    Path(__file__).resolve().parents[1] / "mcp_tools" / "network_pivot.py"
).read_text(encoding="utf-8")


def test_a_pivot_records_how_it_is_reached():
    pivot = Pivot(
        id="pivot_1", name="edge", host="10.0.0.1",
        internal_network="10.1.0.0/24", tunnels=[],
        created_at="2026-01-01T00:00:00", method="chisel",
    )

    assert pivot.to_dict()["method"] == "chisel", (
        "without this a chisel pivot and an ssh pivot are the same record"
    )


def test_method_defaults_so_an_older_state_file_still_loads():
    """_load_state does Pivot(**v), so a state.json written before the field
    existed must still reconstruct -- and the whole loader is one try/except,
    meaning one bad pivot silently drops the tunnels and proxy chains too."""
    stored = {
        "id": "pivot_1", "name": "edge", "host": "10.0.0.1",
        "internal_network": "10.1.0.0/24", "tunnels": [],
        "created_at": "2026-01-01T00:00:00", "notes": "",
    }

    pivot = Pivot(**stored)

    assert pivot.method == "ssh"


def test_the_manager_accepts_and_stores_the_method(tmp_path):
    from core.network_pivot import NetworkPivotManager

    manager = NetworkPivotManager(output_dir=str(tmp_path))
    result = manager.add_pivot(
        name="edge", host="10.0.0.1", internal_network="10.1.0.0/24",
        method="ligolo",
    )

    assert result["success"] is True
    assert result["pivot"]["method"] == "ligolo"


def test_the_manager_still_defaults_the_method(tmp_path):
    from core.network_pivot import NetworkPivotManager

    manager = NetworkPivotManager(output_dir=str(tmp_path))
    result = manager.add_pivot(
        name="edge", host="10.0.0.1", internal_network="10.1.0.0/24"
    )

    assert result["pivot"]["method"] == "ssh"


def test_a_stored_pivot_survives_a_reload_with_its_method(tmp_path):
    """The point of the record is that it outlives the process -- pivots are
    the one session type persisted to state.json rather than held in memory."""
    from core.network_pivot import NetworkPivotManager

    NetworkPivotManager(output_dir=str(tmp_path)).add_pivot(
        name="edge", host="10.0.0.1", internal_network="10.1.0.0/24",
        method="socat",
    )
    reloaded = NetworkPivotManager(output_dir=str(tmp_path))

    stored = list(reloaded.pivots.values())
    assert len(stored) == 1
    assert stored[0].method == "socat"


def test_the_wrapper_does_not_pretend_subnet_is_optional():
    """`subnet: str = ""` made every call that trusted the default a 400."""
    start = WRAPPER_SRC.index("def pivot_add_pivot")
    signature = WRAPPER_SRC[start:WRAPPER_SRC.index(")", start)]

    assert 'subnet: str = ""' not in signature, (
        "the route requires internal_network, so an empty default cannot work"
    )
    assert "subnet: str" in signature


class TestPivotsCanBeForgotten:
    """There was no way to remove a pivot -- no manager method, no route, no
    tool -- while pivots are the one session type persisted to state.json. A
    mistyped host stayed in the operator's map for the life of the volume."""

    def _manager(self, tmp_path):
        from core.network_pivot import NetworkPivotManager
        return NetworkPivotManager(output_dir=str(tmp_path))

    def test_a_pivot_can_be_removed(self, tmp_path):
        manager = self._manager(tmp_path)
        added = manager.add_pivot(
            name="typo", host="10.0.0.1", internal_network="10.1.0.0/24"
        )

        result = manager.remove_pivot(added["pivot_id"])

        assert result["success"] is True
        assert result["count"] == 0
        assert manager.list_pivots()["pivots"] == []

    def test_removal_survives_a_reload(self, tmp_path):
        """It has to reach state.json, or it comes back on the next restart."""
        manager = self._manager(tmp_path)
        added = manager.add_pivot(
            name="typo", host="10.0.0.1", internal_network="10.1.0.0/24"
        )
        manager.remove_pivot(added["pivot_id"])

        assert self._manager(tmp_path).pivots == {}

    def test_removing_an_unknown_pivot_says_so(self, tmp_path):
        result = self._manager(tmp_path).remove_pivot("pivot_nope")

        assert result["success"] is False
        assert "not found" in result["error"]

    def test_a_linked_tunnel_is_reported_not_silently_killed(self, tmp_path):
        """Stopping someone's live tunnel because they tidied a note would be a
        worse surprise than leaving it running and saying so."""
        manager = self._manager(tmp_path)
        added = manager.add_pivot(
            name="edge", host="10.0.0.1", internal_network="10.1.0.0/24"
        )
        manager.pivots[added["pivot_id"]].tunnels.append("tunnel_1")

        result = manager.remove_pivot(added["pivot_id"])

        assert result["orphaned_tunnels"] == ["tunnel_1"]
        assert "pivot_stop_tunnel" in result["note"]

    def test_a_clean_removal_carries_no_scary_note(self, tmp_path):
        manager = self._manager(tmp_path)
        added = manager.add_pivot(
            name="edge", host="10.0.0.1", internal_network="10.1.0.0/24"
        )

        assert manager.remove_pivot(added["pivot_id"])["note"] == ""


def test_the_wrapper_exposes_removal():
    assert "def pivot_remove" in WRAPPER_SRC, (
        "a manager method nothing calls is not a fix"
    )
    assert "api/pivot/remove" in WRAPPER_SRC

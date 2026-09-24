"""End-to-end tests for GET /api/analyses/{id}/redundant-rules."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-red-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _save(client: TestClient, rules: list[dict], name: str | None = None) -> str:
    body: dict = {"rules": rules}
    if name is not None:
        body["name"] = name
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["persisted"] is True
    return r.json()["id"]


def _verdicts(payload: dict) -> dict[str, dict]:
    return {v["rule_id"]: v for v in payload["rules"]}


# ---------------------------------------------------------------------------
def test_nested_conflicting_rules_none_singly_removable(client: TestClient) -> None:
    # permit /8 -> deny /16 -> permit /24: every rule forwards a distinct
    # action surface, so removing any one of them changes final actions.
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200},
        {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50},
    ])

    r = client.get(f"/api/analyses/{aid}/redundant-rules")
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["analysis_id"] == aid
    assert payload["rule_count"] == 3
    assert payload["safe_to_remove_count"] == 0

    # Original rule order is preserved.
    assert [v["rule_id"] for v in payload["rules"]] == ["a", "b", "c"]

    by_id = _verdicts(payload)
    # Deleting a: everything outside the /16 (and not the /24) loses permit
    # -> none; deleting b: /16-minus-/24 reverts deny -> permit (65280).
    assert by_id["a"]["safe_to_remove"] is False
    assert by_id["a"]["changed_addresses"] == 2 ** 24 - 2 ** 16
    assert by_id["b"]["safe_to_remove"] is False
    assert by_id["b"]["changed_addresses"] == 2 ** 16 - 2 ** 8
    # Deleting c: the /24 reverts permit -> deny under b.
    assert by_id["c"]["safe_to_remove"] is False
    assert by_id["c"]["changed_addresses"] == 2 ** 8


def test_same_action_longer_prefix_child_is_safe_parent_is_not(client: TestClient) -> None:
    # permit /8 with a permit /24 inside: the child changes nothing, so it
    # is safe to delete even though it is stored as an active winner; the
    # parent is NOT safe (its deletion exposes the whole /8 to none).
    aid = _save(client, [
        {"rule_id": "p", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "c", "cidr": "10.9.9.0/24", "action": "permit"},
    ])

    by_id = _verdicts(client.get(f"/api/analyses/{aid}/redundant-rules").json())
    assert by_id["c"] == {"rule_id": "c", "safe_to_remove": True, "changed_addresses": 0}
    assert by_id["p"]["safe_to_remove"] is False
    # Deleting p exposes /8 minus c's /24: c keeps permitting its own range.
    assert by_id["p"]["changed_addresses"] == 2 ** 24 - 2 ** 8


def test_shadowed_status_is_not_blindly_trusted(client: TestClient) -> None:
    # permit /8 -> deny /16 fully shadowed by two deny /17 leaves.  A
    # status-only heuristic mis-fires in both directions here: the active
    # leaves are singly removable (the shadowed /16 backs each half up),
    # and safety can only be established by re-running LPM and diffing.
    aid = _save(client, [
        {"rule_id": "r1", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "r2", "cidr": "10.0.0.0/16", "action": "deny"},
        {"rule_id": "r3", "cidr": "10.0.0.0/17", "action": "deny"},
        {"rule_id": "r4", "cidr": "10.0.128.0/17", "action": "deny"},
    ])
    by_id = _verdicts(client.get(f"/api/analyses/{aid}/redundant-rules").json())

    # Any ONE of the deny rules is redundant: removing the shadowed /16
    # leaves the leaves denying; removing one leaf makes the /16 forward
    # that /17 again — same action, zero changed addresses.
    for rid in ("r2", "r3", "r4"):
        assert by_id[rid]["safe_to_remove"] is True, rid
        assert by_id[rid]["changed_addresses"] == 0

    # Removing the leaves together WOULD be load-bearing (r2 only forwards
    # when both stay), but this inventory tests single deletions; the root
    # permit /8 is the one rule that cannot go.
    assert by_id["r1"]["safe_to_remove"] is False
    assert by_id["r1"]["changed_addresses"] == 2 ** 24 - 2 ** 16


def test_same_cidr_duplicate_is_always_safe(client: TestClient) -> None:
    # Same-action and conflicting-action exact-prefix losers never forward,
    # so deleting them changes nothing.  The winner is only removable while
    # a same-action loser is left behind to inherit the CIDR.
    aid = _save(client, [
        {"rule_id": "w1", "cidr": "172.16.0.0/12", "action": "permit", "priority": 10},
        {"rule_id": "same", "cidr": "172.16.0.0/12", "action": "permit", "priority": 20},
        {"rule_id": "conflict", "cidr": "172.16.0.0/12", "action": "deny", "priority": 30},
    ])
    by_id = _verdicts(client.get(f"/api/analyses/{aid}/redundant-rules").json())
    assert by_id["same"]["safe_to_remove"] is True
    assert by_id["conflict"]["safe_to_remove"] is True
    # Removing the winner promotes the same-action duplicate -> still permit,
    # so the winner is also redundant in this particular set.
    assert by_id["w1"]["safe_to_remove"] is True
    assert by_id["w1"]["changed_addresses"] == 0

    # ...but with only a conflicting duplicate left, the winner is load
    # bearing: deleting it promotes the deny loser and flips the whole /12.
    aid2 = _save(client, [
        {"rule_id": "w", "cidr": "172.16.0.0/12", "action": "permit", "priority": 10},
        {"rule_id": "loser", "cidr": "172.16.0.0/12", "action": "deny", "priority": 30},
    ])
    by_id = _verdicts(client.get(f"/api/analyses/{aid2}/redundant-rules").json())
    assert by_id["loser"]["safe_to_remove"] is True
    assert by_id["w"]["safe_to_remove"] is False
    assert by_id["w"]["changed_addresses"] == 2 ** 20


def test_single_rule_version_gives_correct_result(client: TestClient) -> None:
    aid = _save(client, [{"rule_id": "only", "cidr": "192.168.0.0/24", "action": "deny"}])

    r = client.get(f"/api/analyses/{aid}/redundant-rules")
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["safe_to_remove_count"] == 0
    assert payload["rules"] == [
        {"rule_id": "only", "safe_to_remove": False, "changed_addresses": 2 ** 8}
    ]


def test_ipv4_and_ipv6_counted_independently(client: TestClient) -> None:
    # One permit rule per family: deleting it must surface exactly that
    # family's address count (2**32 for a /0 is expensive geometrically, so
    # use small bounded ranges but verify the IPv6 figure is the v6 one).
    aid = _save(client, [
        {"rule_id": "v4", "cidr": "10.0.0.0/24", "action": "permit"},
        {"rule_id": "v6", "cidr": "2001:db8::/48", "action": "deny"},
    ])
    by_id = _verdicts(client.get(f"/api/analyses/{aid}/redundant-rules").json())
    assert by_id["v4"]["changed_addresses"] == 2 ** 8
    assert by_id["v6"]["changed_addresses"] == 2 ** 80
    assert by_id["v4"]["safe_to_remove"] is False
    assert by_id["v6"]["safe_to_remove"] is False

    # A same-action shadowed v6 duplicate is safe and leaves v4 untouched.
    aid2 = _save(client, [
        {"rule_id": "v4", "cidr": "10.0.0.0/24", "action": "permit"},
        {"rule_id": "v6", "cidr": "2001:db8::/48", "action": "deny"},
        {"rule_id": "v6dup", "cidr": "2001:db8::/48", "action": "deny"},
    ])
    by_id = _verdicts(client.get(f"/api/analyses/{aid2}/redundant-rules").json())
    assert by_id["v6dup"]["safe_to_remove"] is True
    assert by_id["v6dup"]["changed_addresses"] == 0


def test_inventory_is_not_persisted(client: TestClient) -> None:
    aid = _save(client, [
        {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit"},
        {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "permit"},
    ])
    before = client.get("/api/analyses").json()
    assert client.get(f"/api/analyses/{aid}/redundant-rules").status_code == 200
    after = client.get("/api/analyses").json()
    assert after == before
    # The base version's stored rules are untouched.
    assert {r["rule_id"] for r in client.get(f"/api/analyses/{aid}").json()["rules"]} == {"a", "b"}


def test_unknown_analysis_returns_404(client: TestClient) -> None:
    r = client.get("/api/analyses/an_0000000000000000/redundant-rules")
    assert r.status_code == 404
    assert "an_0000000000000000" in r.json()["detail"]

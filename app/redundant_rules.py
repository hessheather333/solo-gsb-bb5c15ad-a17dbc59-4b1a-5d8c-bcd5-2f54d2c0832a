"""Redundant-rule inventory for a saved analysis version.

For *each* rule of a stored version this module asks one precise question:
if only this rule were deleted and the ruleset were re-analysed under the
same longest-prefix-match semantics, would the **final effective action**
(``permit`` / ``deny`` / ``none``) stay identical at every IPv4 and IPv6
address?

The answer cannot be read off the stored analysis:

* a ``status == "shadowed"`` flag is a sufficient hint but not the only case
  — an *active* child whose action equals every ancestor it overrides is
  equally removable, while a fully shadowed rule can still sit on the
  same-action run a leaf jumps over, so the status alone is never trusted;
* overlapping rules that merely share an action are not necessarily
  redundant — removing the *parent* of a same-action pair exposes its
  surface to whatever the grandparent decides.

Therefore every rule is removed one at a time from the rebuilt analyzer
input, the ruleset is re-analysed, and the result is compared against the
base version with the regular semantic diff.  A rule is
``safe_to_remove`` only when the diff reports zero changed addresses across
both IP families; the reported ``changed_addresses`` is the total surface
that would flip (IPv4 + IPv6).  Nothing is persisted.

The work is O(n) full analyses per version plus O(n) geometric diffs, i.e.
roughly O(n³) trie work — adequate for the hundreds-to-thousands rule sets
the analyzer targets (see README "复杂度").
"""

from __future__ import annotations

from typing import Any

from .analyzer import analyze_rules
from .diff import diff_analyses
from .simulate import rebuild_input_rules


def _empty_result() -> dict[str, Any]:
    """Stand-in analysis result for an empty ruleset.

    The analyzer itself rejects empty inputs, but "the version minus its
    only rule" is meaningful here: no address matches any rule, so every
    address is implicitly ``none``.  The semantic diff derives actions from
    ``effective_cidrs`` alone, so an empty rule list is all that is needed.
    """
    return {"rules": []}


def _changed_addresses(diff: dict[str, Any]) -> int:
    return int(diff["summary"]["total_changed_addresses"])


def inventory_redundant_rules(base: dict[str, Any]) -> list[dict[str, Any]]:
    """Return one verdict per rule, in the version's original rule order.

    Each verdict is ``{"rule_id", "safe_to_remove", "changed_addresses"}``
    where ``changed_addresses`` is the exact number of IPv4/IPv6 addresses
    whose final action would change after deleting that rule alone (``0``
    iff safe).
    """
    base_input = rebuild_input_rules(base)

    verdicts: list[dict[str, Any]] = []
    for rule in sorted(base.get("rules", []), key=lambda r: r["index"]):
        rule_id = rule["rule_id"]
        surviving = [r for r in base_input if r["rule_id"] != rule_id]
        if surviving:
            candidate = analyze_rules(surviving)
        else:
            # Single-rule versions: removing the only rule leaves an empty
            # policy, whose action is "none" everywhere.
            candidate = _empty_result()
        changed = _changed_addresses(diff_analyses(base, candidate))
        verdicts.append(
            {
                "rule_id": rule_id,
                "safe_to_remove": changed == 0,
                "changed_addresses": changed,
            }
        )
    return verdicts

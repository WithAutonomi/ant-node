#!/usr/bin/env python3
"""Test matrix for check_pr.py — runs the real checker as a subprocess against a
set of PR fields and asserts the pass/fail outcome. No third-party deps; run with
`python3 .github/scripts/test_check_pr.py` (also executed by the pr-checks
workflow's self-test job).

This file is duplicated verbatim across the six crate repos; keep it identical.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check_pr.py")

VALID_BODY = """\
## Linear issue
- https://linear.app/autonominetwork/issue/V2-719/add-the-standard-pr-template

## Risk tier
- [x] T0 — docs / tooling / CI.

## Compatibility
- Wire: none
- Storage: none
- API: none

## Semver impact
- [x] fix

## Test evidence
Ran the checker test matrix; all cases pass.

## New dependency
none

## ADR
n/a

## Mitigation / rollback
Revert the PR.
"""


def body_without(section_swap):
    """Return VALID_BODY with a section's content replaced (old -> new)."""
    old, new = section_swap
    assert old in VALID_BODY, old
    return VALID_BODY.replace(old, new)


# Unfilled template: the only Linear-looking token is the example in a comment.
UNFILLED = """\
## Linear issue
<!-- REQUIRED. Link the issue: an issue key like V2-123, or a linear.app URL. -->
## Risk tier
- [ ] T0
## Semver impact
- [ ] fix
"""

# (name, mode, env, expected_exit)
CASES = [
    # --- linear-link: rejections ---
    ("linear: UTF-8 only", "linear", {"PR_TITLE": "fix UTF-8", "PR_BRANCH": "fix/utf8"}, 1),
    ("linear: SHA-256 / RFC-123", "linear", {"PR_TITLE": "SHA-256 RFC-123", "PR_BRANCH": "x"}, 1),
    ("linear: linear.app/changelog", "linear", {"PR_BODY": "see https://linear.app/changelog", "PR_BRANCH": "x"}, 1),
    ("linear: linear.app/not-an-issue", "linear", {"PR_BODY": "https://linear.app/not-an-issue", "PR_BRANCH": "x"}, 1),
    ("linear: unfilled template (example in comment)", "linear", {"PR_BODY": UNFILLED, "PR_BRANCH": "x"}, 1),
    # --- linear-link: acceptances ---
    ("linear: issue URL in body", "linear", {"PR_BODY": "https://linear.app/autonominetwork/issue/V2-719/foo"}, 0),
    ("linear: key in branch (lowercased)", "linear", {"PR_BRANCH": "chrisoneil/v2-720-ci-check"}, 0),
    ("linear: key in title", "linear", {"PR_TITLE": "AUTO-42 do the thing", "PR_BRANCH": "x"}, 0),
    # --- pr-template: acceptances ---
    ("template: valid T0 body", "template", {"PR_BASE": "main", "PR_BODY": VALID_BODY}, 0),
    ("template: rc-* base is a no-op pass", "template", {"PR_BASE": "rc-2025.10", "PR_BODY": "anything"}, 0),
    ("template: T2 with ADR link", "template", {"PR_BASE": "main", "PR_BODY": body_without(
        ("- [x] T0 — docs / tooling / CI.", "- [x] T2 — behavioural.")).replace(
        "n/a", "https://github.com/x/adr/0001.md")}, 0),
    # --- pr-template: rejections ---
    ("template: not the template", "template", {"PR_BASE": "main", "PR_BODY": "freeform text"}, 1),
    ("template: only Wire axis filled", "template", {"PR_BASE": "main", "PR_BODY": body_without(
        ("- Storage: none\n- API: none", "- Storage:\n- API:"))}, 1),
    ("template: empty ADR (T0)", "template", {"PR_BASE": "main", "PR_BODY": body_without(("n/a", ""))}, 1),
    ("template: T2 with ADR n/a (no link)", "template", {"PR_BASE": "main", "PR_BODY": body_without(
        ("- [x] T0 — docs / tooling / CI.", "- [x] T2 — behavioural."))}, 1),
    ("template: no tier checked", "template", {"PR_BASE": "main", "PR_BODY": body_without(
        ("- [x] T0 — docs / tooling / CI.", "- [ ] T0 — docs / tooling / CI."))}, 1),
    ("template: two tiers checked", "template", {"PR_BASE": "main", "PR_BODY": body_without(
        ("- [x] T0 — docs / tooling / CI.", "- [x] T0 a\n- [x] T2 b"))}, 1),
]


def run(mode, env):
    full = dict(os.environ)
    for k in ("PR_TITLE", "PR_BODY", "PR_BRANCH", "PR_BASE"):
        full.pop(k, None)
    full.update(env)
    return subprocess.run(
        [sys.executable, CHECKER, mode], env=full, capture_output=True, text=True
    ).returncode


def main():
    failures = 0
    for name, mode, env, expected in CASES:
        got = run(mode, env)
        status = "ok" if got == expected else "FAIL"
        if got != expected:
            failures += 1
        print(f"[{status}] {name} (mode={mode}, expected={expected}, got={got})")
    print(f"\n{len(CASES) - failures}/{len(CASES)} cases passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

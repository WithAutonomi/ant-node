#!/usr/bin/env python3
"""Release-process PR checks.

Two modes, each wired to its own required status check:

  check_pr.py linear     V2-720 — require a linked Linear issue on every PR
                         (main + rc-*).
  check_pr.py template   V2-719 — require the standard PR template to be present
                         and fully filled (enforced on PRs targeting main; a
                         no-op that passes on rc-* so hotfix/regression PRs are
                         not forced to carry the full template).

PR fields are read from the environment (set by the workflow from the event
payload): PR_TITLE, PR_BODY, PR_BRANCH, PR_BASE.

This file is duplicated verbatim across the six crate repos; keep them
identical when updating.
"""
import os
import re
import sys

# Known Linear team keys (the issue-key prefixes). A Linear reference is a URL
# under linear.app OR an issue key with one of these prefixes — this is what
# keeps unrelated technical tokens like "UTF-8" / "SHA-256" / "RFC-123" from
# satisfying the gate. Add a new team's key here when a team is created.
LINEAR_TEAM_PREFIXES = ("V2", "AUTO", "REL", "INFRA", "QA")

# Case-insensitive so it also matches Linear-generated branch names, which are
# lower-cased (e.g. chrisoneil/v2-720-...).
LINEAR_KEY = re.compile(
    r"\b(?:" + "|".join(LINEAR_TEAM_PREFIXES) + r")-[0-9]+\b", re.IGNORECASE
)
# A real Linear issue URL: linear.app/<workspace>/issue/<KEY>[/<slug>]. Constrained
# to the /issue/<key> path so generic pages (linear.app/changelog,
# linear.app/not-an-issue) do not count as a linked issue.
LINEAR_URL = re.compile(
    r"linear\.app/[^/\s]+/issue/[A-Za-z][A-Za-z0-9]*-[0-9]+", re.IGNORECASE
)

# Canonical section headings, exactly as they appear in the template, keyed by
# their lower-cased form. Used so failure messages name the real heading.
CANONICAL_HEADINGS = {
    "linear issue": "Linear issue",
    "risk tier": "Risk tier",
    "compatibility": "Compatibility",
    "semver impact": "Semver impact",
    "test evidence": "Test evidence",
    "new dependency": "New dependency",
    "adr": "ADR",
    "mitigation / rollback": "Mitigation / rollback",
}


def env(name):
    return os.environ.get(name, "") or ""


def fail(msg):
    print(msg)
    sys.exit(1)


def ok(msg):
    print(msg)
    sys.exit(0)


def strip_comments(text):
    """Remove HTML comments so template scaffolding and its examples (e.g. the
    'V2-123' hint in the Linear-issue comment) never count as real content."""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


def linear_ref(*parts):
    """Return the first Linear URL/key found in the given (comment-free) parts."""
    haystack = "\n".join(parts)
    m = LINEAR_URL.search(haystack) or LINEAR_KEY.search(haystack)
    return m.group(0) if m else None


def sections(body):
    """Split a markdown body into {heading-lowercased: text-until-next-##}."""
    result, current, buf = {}, None, []
    for line in body.splitlines():
        m = re.match(r"^\s*##\s+(.*?)\s*$", line)
        if m:
            if current is not None:
                result[current] = "\n".join(buf)
            current, buf = m.group(1).strip().lower(), []
        elif current is not None:
            buf.append(line)
    if current is not None:
        result[current] = "\n".join(buf)
    return result


def check_linear():
    # Strip comments from the body so the template's own example does not count.
    ref = linear_ref(env("PR_TITLE"), strip_comments(env("PR_BODY")), env("PR_BRANCH"))
    if ref:
        ok(f"✅ Linear reference found: {ref}")
    fail(
        "❌ No linked Linear issue found.\n\n"
        "Every PR must reference a Linear issue — an issue key ("
        + " / ".join(f"{p}-123" for p in LINEAR_TEAM_PREFIXES)
        + "), or a linear.app/<workspace>/issue/<key> URL — in the PR title, body,\n"
        "or branch name. Add it to the '## Linear issue' section and update the PR."
    )


def check_template():
    base = env("PR_BASE")
    if base and base != "main":
        ok(f"✅ pr-template not enforced on base '{base}' (main only).")

    body = env("PR_BODY")
    secs = sections(body)
    errors = []

    # The Risk tier / Semver impact headings are the sentinels that the template
    # is actually in use.
    if "risk tier" not in secs or "semver impact" not in secs:
        fail(
            "❌ PR template not detected.\n\n"
            "Your PR description must use .github/PULL_REQUEST_TEMPLATE.md (the\n"
            "'## Risk tier' and '## Semver impact' sections are missing). Copy the\n"
            "template into the PR body and fill every field."
        )

    for heading in CANONICAL_HEADINGS:
        if heading not in secs:
            errors.append(f"missing section: ## {CANONICAL_HEADINGS[heading]}")

    # Exactly one Risk tier box checked.
    tiers = re.findall(
        r"^\s*-\s*\[[xX]\]\s*(T[0-3])\b", secs.get("risk tier", ""), re.MULTILINE
    )
    if len(tiers) != 1:
        errors.append(
            f"Risk tier: check exactly one box (found {len(tiers)} checked)"
        )
    tier = tiers[0] if len(tiers) == 1 else None

    # Exactly one Semver impact box checked.
    semver = re.findall(
        r"^\s*-\s*\[[xX]\]\s*(breaking|feature|fix)\b",
        secs.get("semver impact", ""),
        re.MULTILINE | re.IGNORECASE,
    )
    if len(semver) != 1:
        errors.append(
            f"Semver impact: check exactly one box (found {len(semver)} checked)"
        )

    # Free-text sections that must not be empty.
    for heading in ("test evidence", "new dependency", "mitigation / rollback"):
        if heading in secs and not strip_comments(secs[heading]).strip():
            errors.append(f"'## {CANONICAL_HEADINGS[heading]}' is empty")

    # Compatibility: every axis must carry a value (use 'none' where N/A).
    # Use [ \t] rather than \s after the colon so an empty axis cannot "borrow"
    # the next line's content across a newline.
    comp = strip_comments(secs.get("compatibility", ""))
    for axis in ("Wire", "Storage", "API"):
        if not re.search(rf"^[ \t]*-[ \t]*{axis}[ \t]*:[ \t]*\S", comp, re.MULTILINE):
            errors.append(
                f"'## Compatibility': fill in {axis} (use 'none' if not applicable)"
            )

    # Linear reference present in its own section (comments stripped).
    if "linear issue" in secs and not linear_ref(strip_comments(secs["linear issue"])):
        errors.append("'## Linear issue': add the issue key or a linear.app link")

    # ADR must be filled explicitly: 'n/a' for T0/T1, a link for T2/T3.
    adr = strip_comments(secs.get("adr", "")).strip()
    if not adr:
        errors.append(
            "'## ADR' is empty: write 'n/a' for Tier 0/1, or an ADR link for Tier 2/3"
        )
    elif tier in ("T2", "T3") and not re.search(r"https?://", adr):
        errors.append(f"ADR is required for {tier}: add an ADR link in '## ADR'")

    if errors:
        fail(
            "❌ PR template incomplete:\n"
            + "\n".join(f"  - {e}" for e in errors)
            + "\n\nFill in .github/PULL_REQUEST_TEMPLATE.md completely and update the PR."
        )
    ok(f"✅ PR template complete (tier {tier}).")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "linear":
        check_linear()
    elif mode == "template":
        check_template()
    else:
        fail(f"usage: check_pr.py [linear|template] (got: {mode!r})")


if __name__ == "__main__":
    main()

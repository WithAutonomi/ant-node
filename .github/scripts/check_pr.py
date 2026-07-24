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

# A Linear issue key (e.g. V2-123, ENG-45) or a linear.app URL. The key pattern
# is deliberately broad and case-insensitive so it also matches Linear-generated
# branch names (which are lower-cased, e.g. chrisoneil/v2-720-...). It can match
# the odd technical token like "UTF-8"; that permeability is acceptable for a
# gate backed by human review and the train-manifest verification, and it keeps
# false negatives (blocking a legitimate PR) rare.
LINEAR_KEY = re.compile(r"\b[A-Za-z][A-Za-z0-9]*-[0-9]+\b")
LINEAR_URL = re.compile(r"linear\.app/", re.IGNORECASE)


def env(name):
    return os.environ.get(name, "") or ""


def fail(msg):
    print(msg)
    sys.exit(1)


def ok(msg):
    print(msg)
    sys.exit(0)


def strip_comments(text):
    """Remove HTML comments so template scaffolding does not count as content."""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


def has_linear_ref(*parts):
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
    ref = has_linear_ref(env("PR_TITLE"), env("PR_BODY"), env("PR_BRANCH"))
    if ref:
        ok(f"✅ Linear reference found: {ref}")
    fail(
        "❌ No linked Linear issue found.\n\n"
        "Every PR must reference a Linear issue — an issue key like V2-123 in\n"
        "the PR title, body, or branch name, or a linear.app link in the body.\n\n"
        "Add it to the '## Linear issue' section of the PR description and update\n"
        "the pull request."
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

    for heading in (
        "linear issue",
        "risk tier",
        "compatibility",
        "semver impact",
        "test evidence",
        "new dependency",
        "adr",
        "mitigation / rollback",
    ):
        if heading not in secs:
            errors.append(f"missing section: ## {heading.title()}")

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
            errors.append(f"'## {heading.title()}' is empty")

    # Compatibility: at least one axis filled (a value after the colon).
    comp = strip_comments(secs.get("compatibility", ""))
    if not re.search(r"^\s*-\s*(Wire|Storage|API)\s*:\s*\S", comp, re.MULTILINE):
        errors.append(
            "'## Compatibility': fill at least one of Wire/Storage/API (use 'none')"
        )

    # Linear reference present in its own section.
    if "linear issue" in secs and not has_linear_ref(
        strip_comments(secs["linear issue"])
    ):
        errors.append("'## Linear issue': add the issue key or a linear.app link")

    # ADR required for Tier 2/3.
    if tier in ("T2", "T3"):
        adr = strip_comments(secs.get("adr", ""))
        if not re.search(r"https?://", adr):
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

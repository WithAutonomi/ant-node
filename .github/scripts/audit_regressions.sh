#!/usr/bin/env bash
# Fail if a lockfile has a RustSec vulnerability that its base lockfile doesn't.
#
#   audit_regressions.sh HEAD_LOCK [BASE_LOCK]
#
# A PR's Security Audit should fail on an advisory the PR brings in, and not on
# one that was published against a dependency main already had: that one would
# red every open PR the day it lands, whatever the PR changes (V2-1800). So
# this audits both lockfiles against the same advisory database and fails only
# on (advisory, crate) pairs that are in HEAD_LOCK and not in BASE_LOCK. Moving
# an already-vulnerable crate to another vulnerable version is not new. The
# vulnerabilities both share are listed as warnings, so they stay visible.
#
# With no BASE_LOCK every vulnerability in HEAD_LOCK counts as new. Ignores in
# .cargo/audit.toml in the working directory apply to both audits.
set -euo pipefail

head_lock=$1
base_lock=${2:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# audit LOCKFILE REPORT [cargo audit args]
audit() {
  # cargo audit exits non-zero when it finds a vulnerability, so its status
  # can't tell a finding from a crash. A run that didn't produce a report fails
  # the check on the jq test below instead.
  cargo audit --json --file "$1" "${@:3}" > "$2" || true
  if ! jq -e '.vulnerabilities.list | type == "array"' "$2" > /dev/null 2>&1; then
    echo "::error::cargo audit produced no report for $1"
    cat "$2"
    exit 1
  fi
}

# One line per vulnerability: "ID CRATE VERSION: title". The first two fields
# are what "new" is judged on.
vulnerabilities() {
  jq -r '.vulnerabilities.list[] | "\(.advisory.id) \(.package.name) \(.package.version): \(.advisory.title)"' "$1" | sort -u
}

# One line per informational warning (unmaintained, unsound, yanked).
warnings() {
  jq -r '.warnings // {} | to_entries[] | .value[]
         | "\(.kind) \(.advisory.id // "-") \(.package.name) \(.package.version)"' "$1" | sort -u
}

# The first audit fetches the advisory database; the second reuses that copy,
# so both lockfiles are judged against the same advisories.
audit "$head_lock" "$work/head.json"
vulnerabilities "$work/head.json" > "$work/head.txt"
warnings "$work/head.json" > "$work/head-warnings.txt"
if [ -n "$base_lock" ]; then
  audit "$base_lock" "$work/base.json" --no-fetch
  vulnerabilities "$work/base.json" > "$work/base.txt"
  warnings "$work/base.json" > "$work/base-warnings.txt"
else
  : > "$work/base.txt"
  : > "$work/base-warnings.txt"
fi

# Split HEAD's vulnerabilities by whether BASE has the same advisory for the
# same crate. (FILENAME, not NR == FNR: that is also true on the second file
# when the first is empty.)
awk 'FILENAME == ARGV[1] { seen[$1 " " $2] = 1; next } !(($1 " " $2) in seen)' \
  "$work/base.txt" "$work/head.txt" > "$work/new.txt"
awk 'FILENAME == ARGV[1] { seen[$1 " " $2] = 1; next } ($1 " " $2) in seen' \
  "$work/base.txt" "$work/head.txt" > "$work/existing.txt"
# Informational warnings are never fatal; the new ones get an annotation.
comm -13 "$work/base-warnings.txt" "$work/head-warnings.txt" > "$work/new-warnings.txt"

while IFS= read -r line; do
  echo "::warning::already in the base lockfile, not introduced here: $line"
done < "$work/existing.txt"
while IFS= read -r line; do
  echo "::warning::new informational advisory: $line"
done < "$work/new-warnings.txt"

echo "vulnerabilities: $(wc -l < "$work/head.txt") in $head_lock," \
  "$(wc -l < "$work/existing.txt") already in the base, $(wc -l < "$work/new.txt") new"
if [ -s "$work/new.txt" ]; then
  while IFS= read -r line; do
    echo "::error::introduced by this change: $line"
  done < "$work/new.txt"
  exit 1
fi

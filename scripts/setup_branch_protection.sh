#!/usr/bin/env bash
# Apply the branch protection ТЗ 1.0.1 §6 requires.
#
# Branch protection lives in the repository's settings, not in the repository's files, so it
# cannot be committed — which is exactly why it drifts. This script makes the intended state
# explicit and reproducible, and prints what it would change before changing anything.
#
# It is not run automatically. Changing who may push to the default branch is the repository
# owner's decision, so run it deliberately:
#
#   ./scripts/setup_branch_protection.sh --dry-run          # show the intended state
#   ./scripts/setup_branch_protection.sh                    # apply it
#   ./scripts/setup_branch_protection.sh --branch release   # a branch other than main
#
# Requires the GitHub CLI, authenticated with admin rights on the repository.
set -euo pipefail

BRANCH="main"
DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --branch) BRANCH="${2:?--branch needs a value}"; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

command -v gh >/dev/null 2>&1 || {
  echo "the GitHub CLI (gh) is required: https://cli.github.com" >&2
  exit 1
}

REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"

# Every job of .github/workflows/ci.yml that must be green before a merge. The names are the
# job display names, which is what the checks API reports.
REQUIRED_CHECKS=(
  "Lint, format and types"
  "Tests"
  "Security scanning"
  "SBOM and container scan"
  "Migrations from scratch"
  "Security console"
  "Clean Compose start"
)

checks_json="$(printf '%s\n' "${REQUIRED_CHECKS[@]}" | jq -R . | jq -sc .)"

read -r -d '' PAYLOAD <<JSON || true
{
  "required_status_checks": {
    "strict": true,
    "contexts": ${checks_json}
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON

echo "Repository: ${REPO}"
echo "Branch:     ${BRANCH}"
echo
echo "Intended protection:"
echo "  - merge only with every required check green (strict: the branch must be up to date)"
echo "  - direct push to the protected branch refused, for administrators too"
echo "  - force push and branch deletion refused"
echo "  - at least one approving review, stale reviews dismissed on a new push"
echo "  - review conversations must be resolved"
echo
echo "Required checks:"
printf '  - %s\n' "${REQUIRED_CHECKS[@]}"
echo

if [ "$DRY_RUN" -eq 1 ]; then
  echo "(dry run: nothing was changed)"
  exit 0
fi

printf 'Apply this to %s on %s? [y/N] ' "$BRANCH" "$REPO"
read -r answer
case "$answer" in
  y|Y|yes|YES) ;;
  *) echo "aborted"; exit 0 ;;
esac

printf '%s' "$PAYLOAD" | gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/${REPO}/branches/${BRANCH}/protection" \
  --input - >/dev/null

echo "Branch protection applied."
echo
echo "Verify with:"
echo "  gh api /repos/${REPO}/branches/${BRANCH}/protection --jq '.required_status_checks.contexts'"
echo
echo "Note: a required check that has never run on this repository blocks every merge until it"
echo "does. If a job name here does not match .github/workflows/ci.yml, fix the name rather than"
echo "removing the requirement."

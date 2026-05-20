# Pull Requests

When all commits on a branch are done, `make check` passes, and the review agent has reported back, push and open a PR automatically.

- **Target:** always `main`
- **State:** always open as **draft**
- **Title:** `type(scope): short description` — same convention as the commit that drove the work (see `.claude/rules/commits.md`)
- **Body:** summarise what changed (bullet points from the commits) and reference the relevant planning doc phase (e.g. _Implements Phase 1 — Proof Integrity, `planning/programmable-oracle-mvp-plan.md`_)

```bash
git push -u origin <branch>
gh pr create --draft --base main --title "..." --body "..."
```

## Agent Run Report (PR comment)

Immediately after the PR is created, post an agent run report as a PR comment. Assemble it from:
1. `git log main..HEAD --oneline` — the implementation commits
2. The review agent's returned report (captured earlier)

```bash
gh pr comment <PR-number> --body "$(cat <<'EOF'
## Agent Run Report

### Implementation Commits
- <commit hash> <commit message>
- ...

### Review Report
<paste the review agent's full structured output here>
EOF
)"
```

This comment is the permanent record of what every agent did on this branch. It must be posted before the branch is considered done.

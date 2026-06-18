---
name: shellscan
description: Run shellscan to lint shell in `.sh` files, shebang files, GitLab CI YAML, and GitHub Actions YAML, then triage the findings with exact fixes. Use whenever the user asks to shellcheck, lint, audit, or secure shell scripts, `.gitlab-ci.yml`, workflows, or CI run blocks, even when they only mention shellcheck or ask whether pipeline shell is safe.
---

# shellscan

Finds shell wherever it lives — `.sh` files, shebang files, GitLab CI YAML, and
GitHub Actions YAML — then runs shellcheck plus CI injection rules. The scanner
does the extraction and report generation; this skill chooses the scan mode,
reads the report, and states what matters.

## Run

The published image is the scanner. With Docker available, run it from the root
of the project to scan:

```sh
docker run --rm -v "$PWD:/shellscan" \
  -e SHELLSCAN_SECURITY=1 -e SHELLSCAN_FORMAT=codequality \
  registry.gitlab.com/coroboros/security/infrastructure/shellscan:<version> \
  all > report.json || [ $? -eq 1 ]
```

`|| [ $? -eq 1 ]` keeps findings from reading as a command failure while a broken
scan still surfaces. Without Docker, a checkout of
[the shellscan repo](https://gitlab.com/coroboros/security/infrastructure/shellscan)
runs the same scan from the target project root — `bash <checkout>/src/shellscan.sh` —
if `shellcheck`, `yq` (mikefarah v4), `fd`, and `jq` are on PATH. If neither path
works, stop and name the missing dependency. A plain shellcheck pass misses
embedded CI shell, anchors, and security rules, so it can report a false
all-clear.

Pick the mode from the ask: `all` (default) covers everything; `gitlab-ci` /
`github-actions` when the question is about CI YAML; `.sh` / `shebang` for
narrower asks. Set
`SHELLSCAN_SECURITY=1` whenever CI YAML is in scope — those rules are the attack
surface. Exit `0` clean, `1` findings, `2` broken scan; a failed discovery never
reads as a clean scan, so report it instead of proceeding.

## Analyze

Read `report.json` and produce a triage, not a re-print:

1. **Lead with the verdict** — clean or N findings, worst severity, where they
   concentrate.
2. **Explain the real risk** of the top findings in plain language, security
   rules first (`SHELLSCAN-*` — what an attacker gains), then the shellcheck
   findings that change behavior (quoting, word-splitting), style last. Cite
   file and line; for CI-embedded findings the line is the YAML line a reviewer
   actually reads. Keep injection claims calibrated: an unquoted CI variable
   yields word-splitting, option, and glob injection — full command injection
   only where the value reaches `eval` or `sh -c`. The exception is a GitHub
   `${{ }}` expression of attacker-controllable data in a `run` script: it is
   substituted before any shell parses, so it is full command injection and
   quoting does not help.
3. **Give the exact fix** for each top finding — quote the variable, replace the
   `curl | sh` with a verified download, move the secret out of `echo`.
4. **On a legacy tree, offer incremental adoption** — accepted findings'
   fingerprints (the `fingerprint` field of each report entry) go into
   `.shellscanignore` so the gate catches only what is new. A fingerprint is
   file + rule + message, not line: baselining one accepts every current and
   future instance of that rule in that file. Name what each baselined
   fingerprint accepts; never silently baseline a security rule.

Keep it short and decision-oriented. The findings are in the report; the
judgment is the work.

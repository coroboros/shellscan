---
name: shellscan
description: Find and lint every shell in a project — `.sh` files, files with a shell shebang, and scripts embedded in GitLab CI or GitHub Actions YAML — by running the shellscan scanner (shellcheck with YAML extraction, anchors expanded, opt-in security rules for the CI injection surface), then triaging the findings into a plain-language read with the exact fixes. Use whenever someone wants shell linted, checked, or audited — "shellcheck this repo", "lint my scripts", "check the shell in my .gitlab-ci.yml", "lint my workflows", "is this pipeline shell safe", "audit the CI scripts before we go public" — even when they only name shellcheck, ask generally whether their pipeline scripts are secure, or want a shell-quality gate that only fails on new findings.
---

# shellscan

Finds shell wherever it lives — `.sh` files, shebang files, scripts embedded in
GitLab CI and GitHub Actions YAML (anchors expanded, `${{ }}` expressions
neutralized) — and runs it through shellcheck, plus security rules for the CI
injection surface shellcheck has no opinion on. The scanner does the detection;
this skill adds the judgment: choosing the right scan, reading the report, and
saying what matters.

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
works, stop and say what is missing — a hand-rolled shellcheck pass misses the
embedded CI shell, the anchors, and the security rules, so it reports a false
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

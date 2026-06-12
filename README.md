<div align="center">

<img src="assets/logo.png" width="288" height="288" alt="shellscan"/>

<!-- omit in toc -->
# shellscan

**Find and lint every shell in a project — `.sh` files, shebangs, and scripts embedded in GitLab CI and GitHub Actions YAML.**

An Alpine-based image wraps [`shellcheck`](https://github.com/koalaman/shellcheck) with four discovery modes: `.sh` files, files with a shell shebang (`/bin/bash` and `env bash` forms), and shell scripts embedded in CI YAML — GitLab CI `before_script` / `script` / `after_script` keys and GitHub Actions `run` steps — extracted via [`yq`](https://github.com/mikefarah/yq), with YAML anchors expanded. File discovery uses [`fd`](https://github.com/sharkdp/fd). Findings render as terminal output, [GitLab Code Quality JSON for the merge-request widget, or SARIF 2.1.0 for GitHub code scanning](#reports); embedded-script findings map back to their YAML source lines. Opt-in [security rules](#security-rules) flag remote code piped into a shell, secrets echoed to job logs, unquoted attacker-controllable CI variables, and GitHub expressions injecting untrusted data into `run` scripts.

[![latest](https://img.shields.io/gitlab/v/release/coroboros%2Fsecurity%2Finfrastructure%2Fshellscan?style=flat-square&label=latest&color=000000)](https://gitlab.com/coroboros/security/infrastructure/shellscan/-/releases)
[![pipeline](https://img.shields.io/gitlab/pipeline-status/coroboros%2Fsecurity%2Finfrastructure%2Fshellscan?branch=main&style=flat-square&label=pipeline&color=000000)](https://gitlab.com/coroboros/security/infrastructure/shellscan/-/pipelines)
[![ghcr.io](https://img.shields.io/badge/ghcr.io-shellscan-000000?style=flat-square&logo=github)](https://github.com/orgs/coroboros/packages/container/package/shellscan)
[![Docker Hub](https://img.shields.io/badge/docker_hub-shellscan-000000?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/coroboros/shellscan)
[![license](https://img.shields.io/badge/license-Apache_2.0-000000?style=flat-square)](LICENSE.md)
[![stars](https://img.shields.io/gitlab/stars/coroboros%2Fsecurity%2Finfrastructure%2Fshellscan?style=flat-square&label=stars&color=000000)](https://gitlab.com/coroboros/security/infrastructure/shellscan)
[![coverage](https://img.shields.io/gitlab/pipeline-coverage/coroboros%2Fsecurity%2Finfrastructure%2Fshellscan?branch=main&job=test-shell-coverage&style=flat-square&label=coverage&color=000000)](https://gitlab.com/coroboros/security/infrastructure/shellscan/-/jobs/artifacts/main/file/coverage/index.html?job=test-shell-coverage)
[![skills](https://img.shields.io/badge/skills-000000?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDE2IDE2IiBmaWxsPSJ3aGl0ZSI+PHBvbHlnb24gcG9pbnRzPSI4LDAgMTAsNiAxNiw4IDEwLDEwIDgsMTYgNiwxMCAwLDggNiw2Ii8+PC9zdmc+)](https://github.com/coroboros/agent-skills)
[![coroboros.com](https://img.shields.io/badge/coroboros.com-000000?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PGNpcmNsZSBjeD0iMTIiIGN5PSIxMiIgcj0iMTAiLz48cGF0aCBkPSJNMiAxMmgyME0xMiAyYTE1LjMgMTUuMyAwIDAgMSA0IDEwIDE1LjMgMTUuMyAwIDAgMS00IDEwIDE1LjMgMTUuMyAwIDAgMS00LTEwIDE1LjMgMTUuMyAwIDAgMSA0LTEweiIvPjwvc3ZnPg==)](https://coroboros.com)

</div>

<!-- omit in toc -->
## Contents

- [Requirements](#requirements)
- [Image](#image)
- [Tags](#tags)
- [Commands](#commands)
- [Run](#run)
- [Reports](#reports)
- [Security rules](#security-rules)
- [Agents](#agents)
- [Packages](#packages)
- [Provenance](#provenance)
- [Compared to alternatives](#compared-to-alternatives)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Requirements

Docker, BuildKit, or any OCI runtime able to pull from the GitLab Container Registry.

## Image

`ghcr.io/coroboros/shellscan:{tag}` — mirrored to `docker.io/coroboros/shellscan:{tag}`, and in the GitLab Container Registry at `registry.gitlab.com/coroboros/security/infrastructure/shellscan:{tag}`.

- **Architectures**: `linux/amd64`, `linux/arm64`
- **Working directory**: `/shellscan`
- **Entrypoint**: `shellscan`
- **User**: non-root `shellscan` (uid 10000)

## Tags

| Tag | Shellcheck | Base | Architectures | Size | CI median |
| --- | --- | --- | --- | --- | --- |
| `1.1.0` | v0.11.0 | `koalaman/shellcheck-alpine:v0.11.0` | `amd64`, `arm64` | 18.6 MB (amd64), 27.0 MB (arm64) | 3m29s |
| `1.0.1` | v0.11.0 | `koalaman/shellcheck-alpine:v0.11.0` | `amd64`, `arm64` | 18.6 MB (amd64), 27.0 MB (arm64) | 2m30s |
| `1.0.0` | v0.11.0 | `koalaman/shellcheck-alpine:v0.11.0` | `amd64`, `arm64` | 18.6 MB (amd64), 27.0 MB (arm64) | 1m56s |

Sizes from the GitLab Container Registry. CI median computed over the 10 most recent successful pipelines on `main`. Beyond the SemVer tags, `main` tracks the latest green build (rolling) and every build is tagged by its `<sha>` (immutable).

## Commands

`shellscan [mode] [fd_options]`

<details>
<summary><code>mode</code></summary>

<br>

Discovery mode passed as the first positional argument.

| Mode | Behavior |
| --- | --- |
| `all` | Default. Scan every situation below combined. |
| `gitlab-ci` | Scan scripts embedded in `.yml` / `.yaml` files under `before_script` / `script` / `after_script` keys. YAML anchors are expanded. |
| `github-actions` | Scan `run` scripts embedded in `.yml` / `.yaml` files under `jobs.<id>.steps[].run` (workflows) and `runs.steps[].run` (composite actions). `${{ }}` expressions are neutralized before linting; shellcheck runs with the step's bash/sh dialect and skips steps whose effective `shell:` resolves to pwsh, python, cmd, or node — Windows runners and windows-only matrices default to pwsh. The [security rules](#security-rules) run on every `run` script regardless. YAML anchors are expanded. |
| `shebang` | Scan files with a shell shebang (`sh`, `bash`, `dash`, `ksh`). |
| `.sh` | Scan `.sh` files. |
| `-h` | Print help and exit. |

</details>

<details>
<summary><code>fd_options</code></summary>

<br>

Extra options for the `fd` invocation, passed as one quoted argument ([reference](https://github.com/sharkdp/fd#how-to-use)). Options are whitespace-split and passed verbatim — `fd` matches its own glob patterns, the shell never expands them. Command-execution flags (`-x`, `-X`, `--exec`, `--exec-batch`) are refused.

</details>

<details>
<summary><code>Environment variables</code></summary>

<br>

| Variable | Default | Purpose |
| --- | --- | --- |
| `SHELLCHECK_OPTS` | `--color=always` | Options passed to [`shellcheck`](https://github.com/koalaman/shellcheck/blob/master/shellcheck.1.md#environment-variables). |
| `SHELLSCAN_JOBS` | `1` | Parallel scan workers. Above `1` speeds up large scans; shellcheck output interleaves across files, final counts and exit code stay correct. |
| `SHELLSCAN_FORMAT` | `human` | Output format: `human`, `codequality` (GitLab Code Quality JSON), or `sarif` (SARIF 2.1.0). Machine formats own stdout; progress moves to stderr. |
| `SHELLSCAN_BASELINE` | `.shellscanignore` | Baseline file of finding fingerprints suppressed in machine formats — one per line, `#` comments allowed. |
| `SHELLSCAN_SECURITY` | `0` | Set to `1` to enable the [security rules](#security-rules) on scripts embedded in CI YAML — GitLab CI and GitHub Actions. |

</details>

<details>
<summary><code>Exit codes</code></summary>

<br>

| Code | Meaning |
| --- | --- |
| `0` | Scan succeeded, no findings. |
| `1` | Findings reported. |
| `2` | Usage error, refused option, or discovery failure. A failed discovery aborts — it never reads as a clean scan of zero files. |

</details>

<details>
<summary><code>Examples</code></summary>

<br>

```shell
shellscan gitlab-ci
```

```shell
SHELLCHECK_OPTS="--severity=info --color=never" \
shellscan gitlab-ci '--exclude *.yaml --exclude .gitlab-ci.yml'
```

```shell
SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=codequality \
shellscan gitlab-ci > gl-code-quality-report.json
```

```shell
SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=sarif \
shellscan github-actions > shellscan.sarif
```

</details>

## Run

<details>
<summary>GitLab CI</summary>

<br>

```yaml
check-sh-files:
  image:
    name: registry.gitlab.com/coroboros/security/infrastructure/shellscan:1.1.0
    entrypoint: [""]
  stage: check
  variables:
    SHELLCHECK_OPTS: >-
      --severity=warning
      --color=never
  script:
    - shellscan .sh
```

```yaml
check-ci-yaml-files:
  image:
    name: registry.gitlab.com/coroboros/security/infrastructure/shellscan:1.1.0
    entrypoint: [""]
  stage: check
  script:
    - shellscan gitlab-ci
```

```yaml
check-files-with-shebang:
  image:
    name: registry.gitlab.com/coroboros/security/infrastructure/shellscan:1.1.0
    entrypoint: [""]
  stage: check
  script:
    - cd ..
    - shellscan shebang '--exclude *.sh'
```

```yaml
parallel-scan:
  image:
    name: registry.gitlab.com/coroboros/security/infrastructure/shellscan:1.1.0
    entrypoint: [""]
  stage: check
  variables:
    SHELLSCAN_JOBS: "4"
  script:
    - shellscan all
```

</details>

<details>
<summary>CI/CD component</summary>

<br>

One include wires the scan with a Code Quality report consumed by the MR widget. Findings are non-blocking by default; set `fail_on_findings: true` to gate the pipeline.

```yaml
include:
  - component: gitlab.com/coroboros/security/infrastructure/shellscan/shellscan@1.1.0
    inputs:
      mode: all
      security: true
```

Inputs: `stage`, `mode`, `security`, `fail_on_findings`, `image` — see [`templates/shellscan.yml`](templates/shellscan.yml).

</details>

<details>
<summary>GitHub Actions</summary>

<br>

The same image scans a GitHub repository — `github-actions` mode lints the workflows themselves, and the SARIF report lands in code scanning:

```yaml
jobs:
  shellscan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: scan
        run: |
          docker run --rm -v "$PWD:/shellscan" \
            -e SHELLSCAN_SECURITY=1 -e SHELLSCAN_FORMAT=sarif \
            ghcr.io/coroboros/shellscan:1.1.0 all > shellscan.sarif || [ $? -eq 1 ]
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shellscan.sarif
```

</details>

<details>
<summary>pre-commit</summary>

<br>

The hook runs the published image — nothing to build or install locally beyond Docker.

```yaml
repos:
  - repo: https://gitlab.com/coroboros/security/infrastructure/shellscan
    rev: 1.1.0
    hooks:
      - id: shellscan
```

</details>

<details>
<summary>Docker</summary>

<br>

Mount the project as the `/shellscan` volume and run any mode:

```shell
docker run --rm \
  -v "$PWD:/shellscan" \
  registry.gitlab.com/coroboros/security/infrastructure/shellscan:1.1.0
```

```shell
docker run --rm \
  -v "$PWD:/shellscan" \
  registry.gitlab.com/coroboros/security/infrastructure/shellscan:1.1.0 \
  gitlab-ci '--exclude "*.yaml"'
```

</details>

## Reports

`SHELLSCAN_FORMAT=codequality` emits [GitLab Code Quality JSON](https://docs.gitlab.com/ci/testing/code_quality/); `SHELLSCAN_FORMAT=sarif` emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for GitHub code scanning. Both formats write the report to stdout and move progress to stderr. Findings from scripts embedded in CI YAML carry the YAML source line and their selector — `before_script` / `script` / `after_script` for GitLab CI, `jobs.<id>.steps[].run` for GitHub Actions — so annotations land on the YAML line a reviewer actually reads.

Wire the Code Quality report into a job and findings surface in the merge request widget:

```yaml
shellscan:
  image:
    name: registry.gitlab.com/coroboros/security/infrastructure/shellscan:1.1.0
    entrypoint: [""]
  stage: check
  variables:
    SHELLSCAN_FORMAT: codequality
  script:
    - shellscan gitlab-ci > gl-code-quality-report.json || [ $? -eq 1 ]
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
```

`|| [ $? -eq 1 ]` keeps findings non-blocking while discovery failures (exit `2`) still fail the job. Drop it to gate the pipeline on findings.

Every finding carries a stable SHA-256 fingerprint of its file, rule, and message. List fingerprints in `.shellscanignore` (one per line, `#` comments allowed) to suppress known findings — adopt shellscan on a legacy tree without fixing decades of shell first, and let the gate catch only what is new.

## Security rules

`SHELLSCAN_SECURITY=1` adds rules that target the scripts inside CI YAML — GitLab CI and GitHub Actions — the injection surface shellcheck has no opinion on.

| Rule | Severity | Flags |
| --- | --- | --- |
| `SHELLSCAN-CURL-PIPE` | critical | `curl` or `wget` piped into a shell — remote code executed unverified. |
| `SHELLSCAN-EVAL` | major | `eval` on an expanded value — dynamic input runs as code. |
| `SHELLSCAN-SECRET-ECHO` | major | `echo` / `printf` of a secret-named variable — the secret lands in job logs. |
| `SHELLSCAN-CI-INJECTION` | major | Unquoted attacker-controllable CI variable (`CI_COMMIT_MESSAGE`, `CI_MERGE_REQUEST_TITLE`, branch and tag names) — a crafted commit injects shell syntax into the job. |
| `SHELLSCAN-GHA-INJECTION` | critical | `${{ }}` expression of attacker-controllable data (`github.event.pull_request.title`, `github.head_ref`, commit messages) inside a `run` script — substituted before any shell parses, so quoting cannot help; pass it through an environment variable. |

Each finding reports the YAML source line. The rules run on extracted scripts only — `.sh` and shebang files already get the full shellcheck treatment. The injection rules are platform-scoped: `SHELLSCAN-CI-INJECTION` fires on GitLab CI scripts, `SHELLSCAN-GHA-INJECTION` on GitHub Actions `run` scripts — a literal `${{ }}` in a GitLab script is inert text and never flagged.

## Agents

shellscan ships an agent skill — its own scan-and-triage guide — for coding agents. Install it into an agent:

```sh
npx skills add https://gitlab.com/coroboros/security/infrastructure/shellscan
```

Or read it without installing: [`skills/shellscan/SKILL.md`](skills/shellscan/SKILL.md).

## Packages

Same across all shellscan tags.

| Package | Purpose |
| --- | --- |
| `shellcheck` | The linter — provided by the `koalaman/shellcheck-alpine` base image. |
| `bash` | Shell — `src/shellscan.sh` runs on bash. |
| `fd` | Fast file discovery — used to enumerate files to scan. |
| `yq` | YAML processor — extracts scripts from `before_script` / `script` / `after_script` and `run` keys and expands anchors. |
| `jq` | JSON processor — renders Code Quality and SARIF reports from shellcheck `json1` output. |
| `ca-certificates` | TLS certificate bundle. |

## Provenance

Every published image is, via the shared [`coroboros/ci`](https://gitlab.com/coroboros/ci) `container-images` template:

- **multi-arch** — BuildKit, `linux/amd64,linux/arm64`;
- **scanned** — Trivy (OS CVEs) behind a blocking secrets + CVE gate (gitleaks, osv-scanner), so a vulnerable image is never promoted to the consumed tag;
- **signed** — cosign keyless on the immutable digest, with a **CycloneDX SBOM** attestation.

The signed digest is published to `ghcr.io/coroboros/shellscan` and mirrored to `docker.io/coroboros/shellscan` on a version tag. Pin the `@sha256` digest downstream for byte-reproducible scans.

## Compared to alternatives

| Capability | `shellcheck` direct | `yamllint` | `pre-commit` + shellcheck | GitLab CI Lint | `super-linter` | `actionlint` | **`shellscan`** |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Lint `.sh` files | yes | no | yes | no | yes | no | yes |
| Lint files via shebang detection | no | no | no | no | yes | no | yes |
| Extract shells embedded in GitLab CI YAML | no | no | no | no | no | no | yes |
| Extract shells embedded in GitHub Actions YAML | no | no | no | no | via `actionlint` | yes | yes |
| Expand YAML anchors before scanning | no | no | no | no | no | yes (workflows) | yes |
| Single binary / no orchestration setup | yes | yes | no | yes | no | yes | yes (image) |
| Configurable file discovery (`fd` options) | no | no | no | no | no | no | yes |
| Parallel scan (configurable workers) | no | no | no | no | no | auto | yes |
| GitLab Code Quality + SARIF output | no | no | no | no | no | SARIF via template | yes |
| Security rules on CI-embedded shell | no | no | no | no | no | GH untrusted inputs | yes |
| Baseline file for incremental adoption | no | no | no | no | no | no | yes |

The unique angle: shellscan finds shell **wherever it lives** in a project — including the often-overlooked scripts hidden inside CI YAML — runs it through the canonical `shellcheck` linter with YAML anchors expanded, and reports findings where reviewers look: the MR Code Quality widget, GitHub code scanning, or the terminal. [`actionlint`](https://github.com/rhysd/actionlint) proved the demand for linting shell inside CI config on GitHub Actions; shellscan covers both platforms in one scanner, with platform-aware security rules on top.

## Security

Report a vulnerability privately via the [security policy](SECURITY.md) — **ob@coroboros.com**, never a public issue.

## Contributing

Bug reports and MRs welcome.

- Open an issue before submitting non-trivial MRs.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
- Sign off each commit (DCO): `git commit -s`.
- Target the `main` branch.

Run the unit tests locally:

```shell
bash test/unit.sh
```

Coverage report (requires Ruby + Bundler):

```shell
bundle install
bundle exec bashcov --command-name shellscan --mute test/coverage.sh
```

## License

[Apache 2.0](LICENSE.md)

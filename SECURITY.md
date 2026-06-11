# Security policy

## Supported versions

Latest `main` only. Tagged releases follow the same support model as the `main` branch at the time of the release.

## Reporting a vulnerability

Report vulnerabilities to **ob@coroboros.com**. Do not open public issues, MRs, or comments for security problems.

Expected initial response: within 5 business days.

Coordinated disclosure preferred. A fix window of 30 days is the default before public disclosure; we will agree on a different window when the severity demands it.

## Scope

This repository builds the shellscan linter image. In scope:

- **Supply chain of the build** — a base image or apk package that resolves to a compromised artifact, or a build step that fetches unverified content.
- **Image hardening** — the image runs non-root (`shellscan`, uid 10000) with `shellscan` as its entrypoint; a privilege or escape path baked into the image is in scope.
- **Provenance** — every published image is container-scanned and cosign-signed with a CycloneDX SBOM attestation, via the shared [`coroboros/ci`](https://gitlab.com/coroboros/ci) template. A signing or attestation gap is in scope.

shellscan statically lints and never executes the scanned scripts — `fd` command-execution flags are refused and discovery failures abort the scan. A path that makes shellscan execute scanned content, or a scan error that reads as a clean pass, is in scope. Lint quality of standard findings is upstream `shellcheck`; the `SHELLSCAN-*` security rules are authored here and false-negative reports on them are welcome.

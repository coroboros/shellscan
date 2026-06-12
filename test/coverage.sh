#!/usr/bin/env bash
# Coverage harness — drives shellscan through every scenario under one bashcov run so all
# branches accumulate. test/unit.sh asserts behaviour (shunit2, which can't run under bashcov);
# this only exercises paths, so each scan's exit code is irrelevant — hence `|| true`.

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
sc="${root}/src/shellscan.sh"
f="${root}/test/unit/files"
fe="${root}/test/unit/files-edge"

"${sc}" -h || true
"${sc}" nonsense-mode || true
( cd "${f}/shell/success" && "${sc}" .sh ) || true
( cd "${f}/shell/error" && "${sc}" .sh ) || true
( cd "${f}/shebang/success" && "${sc}" shebang ) || true
( cd "${f}/shebang/error" && "${sc}" shebang ) || true
( cd "${f}/gitlab-ci/success" && "${sc}" gitlab-ci ) || true
( cd "${f}/gitlab-ci/error" && "${sc}" gitlab-ci ) || true
( cd "${f}/gitlab-ci/invalid" && "${sc}" gitlab-ci ) || true
( cd "${f}/github-actions/success" && "${sc}" github-actions ) || true
( cd "${f}/github-actions/error" && "${sc}" github-actions ) || true
( cd "${f}/github-actions/invalid" && "${sc}" github-actions ) || true
( cd "${f}/github-actions/error" && SHELLSCAN_FORMAT=codequality "${sc}" github-actions ) || true
( cd "${fe}" && "${sc}" all ) || true
( cd "${f}/shell/success" && "${sc}" .sh '--extension sh' ) || true
( cd "${f}/shell/success" && "${sc}" .sh '--max-depth=1' ) || true
( cd "${f}/shell/success" && "${sc}" .sh '--exec echo' ) || true
( cd "${f}/shell/success" && "${sc}" .sh '--this-is-not-a-real-fd-flag' ) || true
( cd "${fe}/env-shebang" && "${sc}" shebang ) || true
( cd "${f}/shell/error" && SHELLSCAN_FORMAT=codequality "${sc}" .sh ) || true
( cd "${f}/gitlab-ci/error" && SHELLSCAN_FORMAT=sarif "${sc}" gitlab-ci ) || true
( cd "${fe}/security" && SHELLSCAN_SECURITY=1 "${sc}" gitlab-ci ) || true
( cd "${fe}/security" && SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=codequality "${sc}" gitlab-ci ) || true
( cd "${fe}/security" && SHELLSCAN_SECURITY=1 "${sc}" github-actions ) || true
( cd "${fe}/security" && SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=codequality "${sc}" github-actions ) || true
SHELLSCAN_FORMAT=bogus "${sc}" .sh || true
( cd "${f}/shell/success" && SHELLSCAN_FORMAT=codequality "${sc}" .sh ) || true
( cd "${f}/shell/success" && "${sc}" .sh '-x echo' ) || true
( cd "${f}/gitlab-ci/invalid" && SHELLSCAN_FORMAT=codequality "${sc}" gitlab-ci ) || true
sb=$(mktemp)
( cd "${f}/shell/error" && SHELLSCAN_FORMAT=codequality "${sc}" .sh 2> /dev/null ) | jq -r '.[0].fingerprint // empty' > "${sb}" || true
( cd "${f}/shell/error" && SHELLSCAN_BASELINE="${sb}" SHELLSCAN_FORMAT=codequality "${sc}" .sh ) || true
rm -f "${sb}"
( cd "${f}/shell/success" && SHELLSCAN_JOBS=4 "${sc}" all ) || true

#!/usr/bin/env bash
# shellcheck disable=SC2329

set -euo pipefail

export SHELLCHECK_OPTS=${SHELLCHECK_OPTS:-'--color=always'}
export TERM=xterm-color

export text_bold="\033[1m"
export text_normal="\033[0m"
export text_red="\033[31m"
export text_yellow="\033[33m"

mode=${1:-all}
fd_options=${2:-}

SHELLSCAN_JOBS=${SHELLSCAN_JOBS:-1}

# human prints shellcheck as-is; codequality/sarif emit machine reports consumable by GitLab/GitHub.
SHELLSCAN_FORMAT=${SHELLSCAN_FORMAT:-human}
# Fingerprints listed here (one per line, # comments allowed) are suppressed in machine formats.
SHELLSCAN_BASELINE=${SHELLSCAN_BASELINE:-.shellscanignore}
# Opt-in security rules for shell embedded in GitLab CI YAML (curl|sh, CI-variable injection, ...).
SHELLSCAN_SECURITY=${SHELLSCAN_SECURITY:-0}
case ${SHELLSCAN_SECURITY} in
  1 | true | yes | on) SHELLSCAN_SECURITY=1 ;;
  *) SHELLSCAN_SECURITY=0 ;;
esac
export SHELLSCAN_FORMAT SHELLSCAN_SECURITY

case ${SHELLSCAN_FORMAT} in
  human | codequality | sarif) ;;
  *)
    echo "shellscan: unknown SHELLSCAN_FORMAT \"${SHELLSCAN_FORMAT}\" (use human, codequality, or sarif)." >&2
    exit 2
    ;;
esac

# --print0: NUL-delimited discovery, safe for filenames with spaces or newlines in untrusted trees.
fd_base=(fd --no-ignore --hidden --exclude .git --type file --type symlink --print0)

# fd options are whitespace-split and passed verbatim — no shell glob or eval, so a crafted
# filename in the scanned tree can never become an fd argument. fd matches its own patterns.
# Command-execution flags are refused: shellscan never runs commands from a scanned tree.
declare -a fd_args=()
if [[ -n "${fd_options}" ]]; then
  read -ra fd_args <<< "${fd_options}"
  for _arg in "${fd_args[@]}"; do
    case ${_arg} in
      --exec | --exec-batch | --exec=* | --exec-batch=*)
        echo "shellscan: fd command-execution options are not allowed (--exec/--exec-batch)." >&2
        exit 2
        ;;
      --*) : ;;
      -*x* | -*X*)
        echo "shellscan: fd command-execution options are not allowed (-x/-X)." >&2
        exit 2
        ;;
    esac
  done
fi

total_errors=0

SHELLSCAN_TMPS=()
_cleanup() {
  if (( ${#SHELLSCAN_TMPS[@]} > 0 )); then
    rm -f "${SHELLSCAN_TMPS[@]}" || true
  fi
}
trap _cleanup EXIT INT TERM

# Normalized findings accumulate here (one JSON object per line) for the machine formats.
SHELLSCAN_FINDINGS=$(mktemp "${TMPDIR:-/tmp}/shellscan.XXXXXX")
SHELLSCAN_TMPS+=("${SHELLSCAN_FINDINGS}")
export SHELLSCAN_FINDINGS

# Progress goes to stdout for humans, stderr otherwise so the machine report owns stdout.
_log() {
  if [[ "${SHELLSCAN_FORMAT}" == "human" ]]; then
    echo "$@"
  else
    echo "$@" >&2
  fi
}
export -f _log

_sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

# Append one normalized finding from shellscan's own rules.
_emit_finding() {
  jq -nc --arg file "$1" --argjson line "$2" --arg level "$3" --arg code "$4" --arg message "$5" '{file: $file, line: $line, endLine: $line, col: 1, endCol: 1, level: $level, code: $code, message: $message, source: "shellscan"}' >> "${SHELLSCAN_FINDINGS}"
}
export -f _emit_finding

# Run one security rule over an extracted snippet; report each matching line at its YAML source line.
_security_rule() {
  local file=$1 selector=$2 base=$3 script=$4 code=$5 level=$6 regex=$7 msg=$8
  local lineno ln
  while IFS=: read -r lineno _; do
    [[ "${lineno}" =~ ^[0-9]+$ ]] || continue
    ln=$(( base + lineno - 1 ))
    if [[ "${SHELLSCAN_FORMAT}" == "human" ]]; then
      _log "$(echo -e "🔒 ${text_yellow}${code}${text_normal} ${file} [${selector}] line ${ln}: ${msg}")"
      echo SELECTOR_FAIL >> "${SHELLSCAN_RESULTS}"
    else
      _emit_finding "${file}" "${ln}" "${level}" "${code}" "${msg}"
    fi
  done < <(printf '%s\n' "${script}" | grep -nE "${regex}" || true)
}
export -f _security_rule

# Security rules for shell embedded in CI YAML — the class shellcheck does not cover.
_security_scan_snippet() {
  local file=$1 selector=$2 script=$3 base
  base=$(yq eval "${selector} | line" "${file}" 2> /dev/null) || base=1
  [[ "${base}" =~ ^[0-9]+$ ]] || base=1

  _security_rule "${file}" "${selector}" "${base}" "${script}" SHELLSCAN-CURL-PIPE error '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(bash|sh)([^[:alnum:]]|$)' 'Piping a network download into a shell executes unverified remote code.'
  _security_rule "${file}" "${selector}" "${base}" "${script}" SHELLSCAN-EVAL warning '(^|[^[:alnum:]_])eval[[:space:]].*\$' 'eval on an expanded value runs dynamic, possibly attacker-influenced input as code.'
  _security_rule "${file}" "${selector}" "${base}" "${script}" SHELLSCAN-SECRET-ECHO warning '(echo|printf)[[:space:]].*\$\{?[A-Za-z_]*(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_?KEY|ACCESS_KEY)' 'Printing a secret-named variable risks leaking it to CI job logs.'
  _security_rule "${file}" "${selector}" "${base}" "${script}" SHELLSCAN-CI-INJECTION warning '(^|[[:space:]=(])\$\{?(CI_COMMIT_REF_NAME|CI_COMMIT_BRANCH|CI_COMMIT_TAG|CI_COMMIT_TITLE|CI_COMMIT_MESSAGE|CI_COMMIT_DESCRIPTION|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?' 'Unquoted attacker-controllable CI variable can inject shell syntax — quote it.'
}
export -f _security_scan_snippet

discover_files() {
  local pattern=${1:-}
  if [[ -n "${pattern}" ]]; then
    "${fd_base[@]}" "${fd_args[@]}" "${pattern}"
  else
    "${fd_base[@]}" "${fd_args[@]}"
  fi
}
export -f discover_files

# Scan a real file: human prints shellcheck, machine formats collect json1 findings. Returns
# non-zero when the file has findings, so callers can tally pass/fail identically in both modes.
_scan_real_file() {
  local file=$1
  if [[ "${SHELLSCAN_FORMAT}" == "human" ]]; then
    shellcheck -x "${file}"
  else
    local json
    json=$(shellcheck -f json1 -x "${file}" 2> /dev/null) || true
    jq -c --arg file "${file}" '.comments[] | {file: $file, line: .line, endLine: .endLine, col: .column, endCol: .endColumn, level: .level, code: ("SC" + (.code | tostring)), message: .message, source: "shellcheck"}' <<< "${json}" >> "${SHELLSCAN_FINDINGS}"
    [[ "$(jq '.comments | length' <<< "${json}")" -eq 0 ]]
  fi
}
export -f _scan_real_file

# Scan a script extracted from CI YAML. Machine formats remap shellcheck's snippet line numbers
# back onto the YAML file at the script block's line, and tag each finding with its selector.
_scan_snippet() {
  local file=$1 selector=$2 script=$3
  if [[ "${SHELLSCAN_FORMAT}" == "human" ]]; then
    printf '%s' "${script}" | shellcheck --shell=bash -
  else
    local base json
    base=$(yq eval "${selector} | line" "${file}" 2> /dev/null) || base=1
    [[ "${base}" =~ ^[0-9]+$ ]] || base=1
    json=$(printf '%s' "${script}" | shellcheck -f json1 --shell=bash - 2> /dev/null) || true
    jq -c --arg file "${file}" --arg sel "${selector}" --argjson base "${base}" '.comments[] | {file: $file, line: ($base + .line - 1), endLine: ($base + .endLine - 1), col: .column, endCol: .endColumn, level: .level, code: ("SC" + (.code | tostring)), message: (.message + " [" + $sel + "]"), source: "shellcheck"}' <<< "${json}" >> "${SHELLSCAN_FINDINGS}"
    [[ "$(jq '.comments | length' <<< "${json}")" -eq 0 ]]
  fi
}
export -f _scan_snippet

_check_one_sh_file() {
  local file=$1
  if _scan_real_file "${file}"; then
    echo OK >> "${SHELLSCAN_RESULTS}"
  else
    echo FAIL >> "${SHELLSCAN_RESULTS}"
  fi
}
export -f _check_one_sh_file

_check_one_shebang_file() {
  local file=$1
  local first=""
  IFS= read -rN 256 first < "${file}" 2> /dev/null || true
  if [[ "${first}" =~ ^#![[:space:]]*[^[:space:]]*/(bash|dash|ksh|sh)([[:space:]]|$) ]] \
    || [[ "${first}" =~ ^#![[:space:]]*[^[:space:]]*/env[[:space:]]+(-S[[:space:]]+)?(bash|dash|ksh|sh)([[:space:]]|$) ]]; then
    if _scan_real_file "${file}"; then
      echo OK >> "${SHELLSCAN_RESULTS}"
    else
      echo FAIL >> "${SHELLSCAN_RESULTS}"
    fi
  fi
}
export -f _check_one_shebang_file

_check_one_yaml_file() {
  local file=$1
  echo FILE >> "${SHELLSCAN_RESULTS}"

  local selectors selector script
  if ! selectors=$(yq eval '.[] | select(tag=="!!map") | (.before_script,.script,.after_script) | select(. != null) | path | ".[\"" + join("\"].[\"") + "\"]"' "${file}" 2>&1); then
    echo -e "🚨 ${text_red}Could not parse ${file} to extract embedded script(s) -> ${selectors}${text_normal}\n" >&2
    if [[ "${SHELLSCAN_FORMAT}" == "human" ]]; then
      echo SELECTOR_FAIL >> "${SHELLSCAN_RESULTS}"
    else
      _emit_finding "${file}" 1 error SHELLSCAN-YAML-PARSE "Could not parse ${file} to extract embedded script(s)."
    fi
    return 0
  fi

  if [[ -z "${selectors}" ]]; then
    return 0
  fi

  for selector in ${selectors}; do
    if ! script=$(yq eval "${selector} | explode(.) | flatten | join(\"\n\")" "${file}" 2>&1); then
      _log "$(echo -e "⚠️  ${text_yellow}Could not merge aliases/anchors for the script specified in ${text_bold}${selector}${text_normal} found in ${file} -> ${script}${text_normal}\n")"
      if ! script=$(yq eval "${selector} | join(\"\n\")" "${file}" 2> /dev/null); then
        continue
      fi
    fi
    if ! _scan_snippet "${file}" "${selector}" "${script}"; then
      if [[ "${SHELLSCAN_FORMAT}" == "human" ]]; then
        echo -e "${text_red}Above issue(s) found in ${file} in the script specified in ${text_bold}${selector}${text_normal}\n\n"
        echo SELECTOR_FAIL >> "${SHELLSCAN_RESULTS}"
      fi
    fi
    if [[ "${SHELLSCAN_SECURITY}" != "0" ]]; then
      _security_scan_snippet "${file}" "${selector}" "${script}"
    fi
  done
}
export -f _check_one_yaml_file

_run() {
  local worker=$1
  local pattern=${2:-}
  SHELLSCAN_RESULTS=$(mktemp "${TMPDIR:-/tmp}/shellscan.XXXXXX")
  SHELLSCAN_TMPS+=("${SHELLSCAN_RESULTS}")
  export SHELLSCAN_RESULTS

  # Fail closed: an fd discovery error must abort, never read as "0 files scanned, success".
  local listing
  listing=$(mktemp "${TMPDIR:-/tmp}/shellscan.XXXXXX")
  SHELLSCAN_TMPS+=("${listing}")
  if ! discover_files "${pattern}" > "${listing}"; then
    echo -e "🚨 ${text_red}File discovery failed (fd exited non-zero). Aborting scan.${text_normal}" >&2
    exit 2
  fi

  if (( SHELLSCAN_JOBS <= 1 )); then
    while IFS= read -r -d '' f; do
      "${worker}" "${f}"
    done < "${listing}"
  else
    xargs -r -0 -P "${SHELLSCAN_JOBS}" -I {} bash -c "${worker} \"\$@\"" _ {} < "${listing}"
  fi
}

check_gitlab_ci_scripts() {
  _log "Checking scripts embedded in GitLab CI YAML files..."
  _run _check_one_yaml_file '\.yaml$|\.yml$'

  local nb_files=0
  local nb_errors=0
  nb_files=$(grep -c '^FILE$' "${SHELLSCAN_RESULTS}" 2> /dev/null) || nb_files=0
  nb_errors=$(grep -c '^SELECTOR_FAIL$' "${SHELLSCAN_RESULTS}" 2> /dev/null) || nb_errors=0

  total_errors=$((total_errors + nb_errors))
  _log "✅ Checked $nb_files GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: $nb_errors."
}

check_shebang_files() {
  _log "Checking files with a shell shebang..."
  _run _check_one_shebang_file ''

  local nb_files=0
  local nb_errors=0
  nb_files=$(wc -l < "${SHELLSCAN_RESULTS}" 2> /dev/null | tr -d ' ') || nb_files=0
  nb_errors=$(grep -c '^FAIL$' "${SHELLSCAN_RESULTS}" 2> /dev/null) || nb_errors=0

  total_errors=$((total_errors + nb_errors))
  _log "✅ Checked $nb_files file(s) with a shell shebang. Errors: $nb_errors."
}

check_sh_files() {
  _log "Checking .sh files..."
  _run _check_one_sh_file '\.sh$'

  local nb_files=0
  local nb_errors=0
  nb_files=$(wc -l < "${SHELLSCAN_RESULTS}" 2> /dev/null | tr -d ' ') || nb_files=0
  nb_errors=$(grep -c '^FAIL$' "${SHELLSCAN_RESULTS}" 2> /dev/null) || nb_errors=0

  total_errors=$((total_errors + nb_errors))
  _log "✅ Checked $nb_files .sh file(s). Errors: $nb_errors."
}

check_all() {
  check_gitlab_ci_scripts
  check_shebang_files
  check_sh_files
}

# Severity-mapped, baseline-filtered render of the collected findings to the requested machine format.
_render() {
  local enriched baseline_set=""
  enriched=$(mktemp "${TMPDIR:-/tmp}/shellscan.XXXXXX")
  SHELLSCAN_TMPS+=("${enriched}")
  if [[ -f "${SHELLSCAN_BASELINE}" ]]; then
    baseline_set=$(grep -vE '^[[:space:]]*(#|$)' "${SHELLSCAN_BASELINE}" || true)
  fi

  local count=0 finding file code message fp
  while IFS= read -r finding; do
    [[ -z "${finding}" ]] && continue
    file=$(jq -r '.file' <<< "${finding}")
    code=$(jq -r '.code' <<< "${finding}")
    message=$(jq -r '.message' <<< "${finding}")
    fp=$(printf '%s\037%s\037%s' "${file}" "${code}" "${message}" | _sha256)
    if [[ -n "${baseline_set}" ]] && grep -qxF "${fp}" <<< "${baseline_set}"; then
      continue
    fi
    jq -c --arg fp "${fp}" '. + {fingerprint: $fp}' <<< "${finding}" >> "${enriched}"
    count=$((count + 1))
  done < "${SHELLSCAN_FINDINGS}"

  case ${SHELLSCAN_FORMAT} in
    codequality)
      jq -s 'map({ description: .message, check_name: .code, fingerprint: .fingerprint, severity: (if .level == "error" then "critical" elif .level == "warning" then "major" elif .level == "info" then "minor" else "info" end), location: { path: .file, lines: { begin: .line } } })' "${enriched}"
      ;;
    sarif)
      jq -s '{ "$schema": "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [{ tool: { driver: { name: "shellscan", informationUri: "https://gitlab.com/coroboros/security/infrastructure/shellscan", rules: (map({ id: .code }) | unique_by(.id)) } }, results: map({ ruleId: .code, level: (if .level == "error" then "error" elif .level == "warning" then "warning" else "note" end), message: { text: .message }, partialFingerprints: { shellscanFingerprint: .fingerprint }, locations: [{ physicalLocation: { artifactLocation: { uri: .file }, region: { startLine: .line } } }] }) }] }' "${enriched}"
      ;;
  esac

  if (( count > 0 )); then
    echo "🚨 ${count} finding(s)." >&2
    exit 1
  fi
  echo "✅ Shell scan succeeded." >&2
  exit 0
}

print_help() {
  cat << 'EOF'
shellscan - scan shell files or shell scripts embedded in files

shellscan [mode] [fd_options]

mode
    Scripts or files to scan. One of: all (default), gitlab-ci, shebang, .sh.

fd_options
    Extra options for fd (https://github.com/sharkdp/fd), the file-discovery program.
    Whitespace-separated and passed verbatim — fd matches its own glob patterns, the shell
    does not. Command-execution flags (-x, -X, --exec, --exec-batch) are refused.

-h
    Print help information.

Environment:
    SHELLCHECK_OPTS   Options passed to shellcheck (default: --color=always), e.g. --severity=error.
    SHELLSCAN_JOBS    Parallel scan workers (default: 1). Above 1 speeds up large scans; shellcheck output interleaves across files.
    SHELLSCAN_FORMAT  Output format: human (default), codequality (GitLab Code Quality JSON), or sarif (SARIF 2.1.0).
    SHELLSCAN_BASELINE  Baseline file of fingerprints to suppress in machine formats (default: .shellscanignore).
    SHELLSCAN_SECURITY  Set to 1 to enable security rules for shell embedded in GitLab CI YAML.

Exit codes:
    0   scan succeeded, no findings.
    1   findings reported.
    2   usage error, refused option, or discovery/tooling failure.
EOF
}

case ${mode} in
  all) check_all ;;
  gitlab-ci) check_gitlab_ci_scripts ;;
  shebang) check_shebang_files ;;
  .sh) check_sh_files ;;
  -h) print_help; exit 0 ;;
  *)
    echo "Unsupported mode \"${mode}\"." >&2
    echo "Run 'shellscan -h' for help." >&2
    exit 2
    ;;
esac

if [[ "${SHELLSCAN_FORMAT}" != "human" ]]; then
  _render
fi

if (( total_errors > 0 )); then
  echo "🚨 Found $total_errors error(s) during shell scan."
  exit 1
fi

echo "✅ Shell scan succeeded."
exit 0

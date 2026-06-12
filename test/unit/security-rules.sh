#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
fixture="$base_dir"/test/unit/files-edge/security

testSecurityRulesFireInCodequality() {
  cd "$fixture"
  out=$(SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=codequality "$script" gitlab-ci 2>/dev/null)
  assertEquals 1 "$?"
  for code in SHELLSCAN-CURL-PIPE SHELLSCAN-EVAL SHELLSCAN-SECRET-ECHO SHELLSCAN-CI-INJECTION; do
    n=$(echo "$out" | jq --arg c "$code" '[.[] | select(.check_name == $c)] | length')
    assertTrue "$code should fire" "[ ${n:-0} -ge 1 ]"
  done
  # Platform-scoped: a literal ${{ }} in a GitLab script is inert text, never an injection.
  n=$(echo "$out" | jq '[.[] | select(.check_name == "SHELLSCAN-GHA-INJECTION")] | length')
  assertEquals 0 "$n"
}

testSecurityRulesOffByDefault() {
  cd "$fixture"
  out=$(SHELLSCAN_FORMAT=codequality "$script" gitlab-ci 2>/dev/null)
  n=$(echo "$out" | jq '[.[] | select(.check_name | startswith("SHELLSCAN-"))] | length')
  assertEquals 0 "$n"
}

testSecurityRulesHumanMode() {
  cd "$fixture"
  r=$(SHELLSCAN_SECURITY=1 "$script" gitlab-ci 2>&1)
  assertEquals 1 "$?"
  assertContains "$r" "SHELLSCAN-CURL-PIPE"
}

testSecurityRulesGithubActionsInCodequality() {
  cd "$fixture"
  out=$(SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=codequality "$script" github-actions 2>/dev/null)
  assertEquals 1 "$?"
  # Three injections: single-line, wrapped across lines, and in a pwsh step — substitution is
  # shell-agnostic, so the rule fires even where the shellcheck pass is skipped.
  n=$(echo "$out" | jq '[.[] | select(.check_name == "SHELLSCAN-GHA-INJECTION")] | length')
  assertEquals 3 "$n"
  n=$(echo "$out" | jq '[.[] | select(.check_name == "SHELLSCAN-CURL-PIPE")] | length')
  assertTrue "SHELLSCAN-CURL-PIPE should fire" "[ ${n:-0} -ge 1 ]"
  # Expression substitution happens before the shell parses — quoting cannot mitigate, so critical.
  sev=$(echo "$out" | jq -r '[.[] | select(.check_name == "SHELLSCAN-GHA-INJECTION")][0].severity')
  assertEquals critical "$sev"
}

testSecurityRulesGithubActionsHumanMode() {
  cd "$fixture"
  r=$(SHELLSCAN_SECURITY=1 "$script" github-actions 2>&1)
  assertEquals 1 "$?"
  assertContains "$r" "SHELLSCAN-GHA-INJECTION"
}

source "$base_dir"/test/unit/shunit2

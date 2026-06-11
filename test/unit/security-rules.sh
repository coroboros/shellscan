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

source "$base_dir"/test/unit/shunit2

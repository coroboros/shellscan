#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh

testCodequalityArrayShape() {
  cd "$base_dir"/test/unit/files/shell/error
  out=$(SHELLSCAN_FORMAT=codequality "$script" .sh 2>/dev/null)
  assertEquals 1 "$?"
  echo "$out" | jq -e 'type=="array" and length>0 and (.[0] | has("fingerprint") and has("check_name") and has("severity") and .location.path != null and .location.lines.begin != null)' >/dev/null
  assertEquals 0 "$?"
}

testCodequalitySuccessEmpty() {
  cd "$base_dir"/test/unit/files/shell/success
  out=$(SHELLSCAN_FORMAT=codequality "$script" .sh 2>/dev/null)
  assertEquals 0 "$?"
  assertEquals "[]" "$(echo "$out" | jq -c .)"
}

testSarifValid() {
  cd "$base_dir"/test/unit/files/gitlab-ci/error
  out=$(SHELLSCAN_FORMAT=sarif "$script" gitlab-ci 2>/dev/null)
  assertEquals 1 "$?"
  echo "$out" | jq -e '.version=="2.1.0" and .runs[0].tool.driver.name=="shellscan" and (.runs[0].results|length>0) and (.runs[0].results[0] | .ruleId != null and .locations[0].physicalLocation.region.startLine != null)' >/dev/null
  assertEquals 0 "$?"
}

testUnknownFormatRejected() {
  cd "$base_dir"/test/unit/files/shell/success
  SHELLSCAN_FORMAT=bogus "$script" .sh >/dev/null 2>&1
  assertEquals 2 "$?"
}

testNonNumericJobsRejected() {
  cd "$base_dir"/test/unit/files/shell/success
  SHELLSCAN_JOBS=abc "$script" .sh >/dev/null 2>&1
  assertEquals 2 "$?"
}

testBaselineSuppressesFinding() {
  cd "$base_dir"/test/unit/files/shell/error
  out=$(SHELLSCAN_FORMAT=codequality "$script" .sh 2>/dev/null)
  fp=$(echo "$out" | jq -r '.[0].fingerprint')
  n1=$(echo "$out" | jq 'length')
  base=$(mktemp)
  echo "$fp" > "$base"
  out2=$(SHELLSCAN_BASELINE="$base" SHELLSCAN_FORMAT=codequality "$script" .sh 2>/dev/null)
  rm -f "$base"
  n2=$(echo "$out2" | jq 'length')
  assertTrue "baseline reduced the finding count ($n1 -> $n2)" "[ $n2 -lt $n1 ]"
}

source "$base_dir"/test/unit/shunit2

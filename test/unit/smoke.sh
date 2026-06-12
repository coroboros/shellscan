#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files"

cd "$base_dir"/"$test_files"

testSmokeSequentialVsParallelEquivalent() {
  r1=$(SHELLSCAN_JOBS=1 "$script" all)
  rc1=$?
  r2=$(SHELLSCAN_JOBS=4 "$script" all)
  rc2=$?
  assertEquals "$rc1" "$rc2"
  assertContains "$r1" "Found 25 error(s) during shell scan."
  assertContains "$r2" "Found 25 error(s) during shell scan."
}

testSmokeHelpDoesNotLeaveTempfile() {
  before=$(find "${TMPDIR:-/tmp}" -name "shellscan.*" 2>/dev/null | wc -l | tr -d ' ')
  "$script" -h >/dev/null
  after=$(find "${TMPDIR:-/tmp}" -name "shellscan.*" 2>/dev/null | wc -l | tr -d ' ')
  assertEquals "$before" "$after"
}

source "$base_dir"/test/unit/shunit2

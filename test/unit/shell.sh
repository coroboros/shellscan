#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files/shell"

testScanningAllShellFiles() {
  cd "$base_dir"/"$test_files"
  r=$("$script" .sh)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 2 .sh file(s). Errors: 1."
}

testScanningShellFilesWithError() {
  cd "$base_dir"/"$test_files"/error
  r=$("$script" .sh)
  assertEquals 1 "$?"
  assertContains "$r" "Double quote to prevent globbing and word splitting"
  assertContains "$r" "Checked 1 .sh file(s). Errors: 1."
}

testScanningShellFilesWithSuccess() {
  cd "$base_dir"/"$test_files"/success
  r=$("$script" .sh)
  assertEquals 0 "$?"
  assertContains "$r" "Checked 1 .sh file(s). Errors: 0."
}

source "$base_dir"/test/unit/shunit2

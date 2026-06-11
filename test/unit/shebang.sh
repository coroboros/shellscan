#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files/shebang"

testScanningAllShebangFiles() {
  cd "$base_dir"/"$test_files"
  r=$("$script" shebang)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 8 file(s) with a shell shebang. Errors: 4."
}

testScanningShebangFilesWithError() {
  cd "$base_dir"/"$test_files"/error
  r=$("$script" shebang)
  assertEquals 1 "$?"
  assertContains "$r" "Double quote to prevent globbing and word splitting"
  assertContains "$r" "Checked 4 file(s) with a shell shebang. Errors: 4."
}

testScanningShebangFilesWithSuccess() {
  cd "$base_dir"/"$test_files"/success
  r=$("$script" shebang)
  assertEquals 0 "$?"
  assertContains "$r" "Checked 4 file(s) with a shell shebang. Errors: 0."
}

source "$base_dir"/test/unit/shunit2

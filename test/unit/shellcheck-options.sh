#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files"

testScanningAllFilesWithShellcheckOptions() {
  export SHELLCHECK_OPTS="--severity=error"
  cd "$base_dir"/"$test_files"
  r=$("$script")
  assertEquals 1 "$?"
  assertContains "$r" "Found 8 error(s) during shell scan."
  export SHELLCHECK_OPTS=""
}

source "$base_dir"/test/unit/shunit2

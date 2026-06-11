#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files"

testPrintingHelp() {
  r=$("$script" -h)
  assertEquals 0 "$?"
  assertContains "$r" "shellscan - scan shell files or shell scripts embedded in files"
  assertNotContains "$r" "Shell scan succeeded"
}

source "$base_dir"/test/unit/shunit2

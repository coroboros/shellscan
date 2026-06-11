#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files"

cd "$base_dir"/"$test_files"

testScanningAllFiles() {
  r=$("$script" all)
  assertEquals 1 "$?"
  assertContains "$r" "Found 12 error(s) during shell scan."
}

testScanningAllFilesByDefault() {
  r1=$("$script")
  assertEquals 1 "$?"

  r2=$("$script" all)
  assertEquals 1 "$?"

  assertEquals "$r1" "$r2"
}

testScanningOnlyGitlabCIFiles() {
  r=$("$script" gitlab-ci)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 7 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 6."
  assertContains "$r" "Found 6 error(s) during shell scan."
}

testScanningOnlyShellFiles() {
  r=$("$script" .sh)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 2 .sh file(s). Errors: 1."
  assertContains "$r" "Found 1 error(s) during shell scan."
}

testScanningOnlyShebangFiles() {
  r=$("$script" shebang)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 10 file(s) with a shell shebang. Errors: 5."
  assertContains "$r" "Found 5 error(s) during shell scan."
}

source "$base_dir"/test/unit/shunit2

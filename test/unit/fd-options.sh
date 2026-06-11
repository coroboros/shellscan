#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files"

testScanningShellFilesWithFdOptions() {
  cd "$base_dir"/"$test_files"/shell
  r=$("$script" .sh '--exclude *.sh')
  assertEquals 0 "$?"
  assertContains "$r" "Checked 0 .sh file(s). Errors: 0."
}

testScanningGitlabCIFilesWithFdOptions() {
  cd "$base_dir"/"$test_files"/gitlab-ci
  r=$("$script" gitlab-ci '--exclude *.yaml --exclude .gitlab-ci.yml')
  assertEquals 1 "$?"
  assertContains "$r" "Checked 1 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 5."
}

source "$base_dir"/test/unit/shunit2

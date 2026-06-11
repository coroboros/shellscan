#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files/gitlab-ci"

testScanningAllGitlabCIFiles() {
  cd "$base_dir"/"$test_files"
  r=$("$script" gitlab-ci)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 7 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 6."
}

testScanningGitlabCIInvalidFiles() {
  cd "$base_dir"/"$test_files"/invalid
  r=$("$script" gitlab-ci 2>&1)
  # Fail closed: unparseable YAML is an error, never a silent pass.
  assertEquals 1 "$?"
  assertContains "$r" "Could not parse"
  assertContains "$r" "Checked 1 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 1."
}

testScanningGitlabCIFilesWithError() {
  cd "$base_dir"/"$test_files"/error
  r=$("$script" gitlab-ci)
  assertEquals 1 "$?"
  assertContains "$r" "Double quote to prevent globbing and word splitting"
  assertContains "$r" "Quote the parameter to -name so the shell won't interpret it"
  assertContains "$r" "Tilde does not expand in quotes"
  assertContains "$r" "Quotes/backslashes will be treated literally"
  assertContains "$r" "This apostrophe terminated the single quoted string"
  assertContains "$r" "Want to escape a single quote?"
  assertContains "$r" "Checked 1 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 5."
}

testScanningGitlabCIFilesWithSuccess() {
  cd "$base_dir"/"$test_files"/success
  r=$("$script" gitlab-ci)
  assertEquals 0 "$?"
  assertContains "$r" "Checked 5 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 0."
}

source "$base_dir"/test/unit/shunit2

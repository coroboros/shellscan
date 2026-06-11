#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files"

cd "$base_dir"/"$test_files"

testParallelAllMatchesSequentialCount() {
  r1=$(SHELLSCAN_JOBS=1 "$script" all)
  rc1=$?
  r2=$(SHELLSCAN_JOBS=4 "$script" all)
  rc2=$?
  assertEquals "$rc1" "$rc2"
  assertContains "$r1" "Found 12 error(s) during shell scan."
  assertContains "$r2" "Found 12 error(s) during shell scan."
}

testParallelGitlabCIDeterministic() {
  r1=$(SHELLSCAN_JOBS=4 "$script" gitlab-ci)
  assertEquals 1 "$?"
  assertContains "$r1" "Checked 7 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 6."

  r2=$(SHELLSCAN_JOBS=4 "$script" gitlab-ci)
  assertEquals 1 "$?"
  assertContains "$r2" "Checked 7 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 6."

  r3=$(SHELLSCAN_JOBS=4 "$script" gitlab-ci)
  assertEquals 1 "$?"
  assertContains "$r3" "Checked 7 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 6."
}

testParallelShebangCount() {
  r=$(SHELLSCAN_JOBS=4 "$script" shebang)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 10 file(s) with a shell shebang. Errors: 5."
}

testParallelShFilesCount() {
  r=$(SHELLSCAN_JOBS=8 "$script" .sh)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 2 .sh file(s). Errors: 1."
}

testParallelHighJobsStillCorrect() {
  r=$(SHELLSCAN_JOBS=16 "$script" all)
  assertEquals 1 "$?"
  assertContains "$r" "Found 12 error(s) during shell scan."
}

source "$base_dir"/test/unit/shunit2

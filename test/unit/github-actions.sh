#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files/github-actions"

testScanningAllGithubActionsFiles() {
  cd "$base_dir"/"$test_files"
  r=$("$script" github-actions)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 4 GitHub Actions YAML file(s) with potential run scripts embedded. Selectors in error: 11."
}

testScanningGithubActionsInvalidFiles() {
  cd "$base_dir"/"$test_files"/invalid
  r=$("$script" github-actions 2>&1)
  # Fail closed: unparseable YAML is an error, never a silent pass.
  assertEquals 1 "$?"
  assertContains "$r" "Could not parse"
  assertContains "$r" "Checked 1 GitHub Actions YAML file(s) with potential run scripts embedded. Selectors in error: 1."
}

testScanningGithubActionsFilesWithError() {
  cd "$base_dir"/"$test_files"/error
  r=$("$script" github-actions)
  assertEquals 1 "$?"
  assertContains "$r" "Double quote to prevent globbing and word splitting"
  assertContains "$r" "This apostrophe terminated the single quoted string"
  assertContains "$r" "Checked 1 GitHub Actions YAML file(s) with potential run scripts embedded. Selectors in error: 10."
}

testScanningGithubActionsFilesWithSuccess() {
  # Anchored runs resolve, ${{ }} neutralizes, pwsh/python steps skip — any miss breaks exit 0.
  cd "$base_dir"/"$test_files"/success
  r=$("$script" github-actions)
  assertEquals 0 "$?"
  assertContains "$r" "Checked 2 GitHub Actions YAML file(s) with potential run scripts embedded. Selectors in error: 0."
}

testGithubActionsLineMappingInCodequality() {
  cd "$base_dir"/"$test_files"/error
  out=$(SHELLSCAN_FORMAT=codequality "$script" github-actions 2>/dev/null)
  assertEquals 1 "$?"
  # Block scalar content maps one line below the run key; flow scalars map onto it; aliased
  # and quoted-multiline runs pin every finding to their own line.
  lines=$(echo "$out" | jq -c '[.[].location.lines.begin] | unique')
  assertEquals "[9,10,12,14,16,19,22,25,27,31,50]" "$lines"
}

testInvalidYamlSingleFingerprintAcrossModes() {
  cd "$base_dir"/"$test_files"/invalid
  out=$(SHELLSCAN_FORMAT=codequality "$script" all 2>/dev/null)
  # Both YAML passes report the same parse failure with one shared fingerprint, so a
  # baseline written under one mode keeps suppressing the file under `all`.
  n=$(echo "$out" | jq '[.[] | select(.check_name == "SHELLSCAN-YAML-PARSE") | .fingerprint] | unique | length')
  assertEquals 1 "$n"
}

source "$base_dir"/test/unit/shunit2

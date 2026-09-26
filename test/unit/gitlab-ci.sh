#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
test_files="test/unit/files/gitlab-ci"

findingLines() {
  jq -r --arg code "$2" --arg path "$3" '[.[] | select(.check_name == $code and .location.path == $path) | .location.lines.begin] | sort | join(",")' <<< "$1"
}

normalizedFindings() {
  jq -c 'if type == "array" then map({code: .check_name, message: .description, file: .location.path, line: .location.lines.begin, fingerprint: .fingerprint}) else .runs[0].results | map({code: .ruleId, message: .message.text, file: .locations[0].physicalLocation.artifactLocation.uri, line: .locations[0].physicalLocation.region.startLine, fingerprint: .partialFingerprints.shellscanFingerprint}) end | sort_by(.file, .line, .code, .message)' <<< "$1"
}

testScanningAllGitlabCIFiles() {
  cd "$base_dir"/"$test_files"
  r=$("$script" gitlab-ci)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 8 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 6."
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

testScanningGitlabCIMultiDocumentFile() {
  cd "$base_dir"/test/unit/files-edge/gitlab-multi-document
  r=$("$script" gitlab-ci)
  assertEquals 1 "$?"
  assertContains "$r" "Double quote to prevent globbing and word splitting"
  assertContains "$r" "Checked 1 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 2."

  out=$(SHELLSCAN_FORMAT=codequality "$script" gitlab-ci 2>/dev/null)
  assertEquals 1 "$?"
  description=$(echo "$out" | jq -r '.[0].description')
  assertContains "$description" '[.["deploy"].["script"]]'
  lines=$(echo "$out" | jq -r '[.[] | select(.check_name == "SC2086") | .location.lines.begin] | sort | join(",")')
  assertEquals "10,15" "$lines"

  out=$(SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=codequality "$script" gitlab-ci 2>/dev/null)
  assertEquals 1 "$?"
  lines=$(echo "$out" | jq -r '[.[] | select(.check_name == "SHELLSCAN-CI-INJECTION") | .location.lines.begin] | sort | join(",")')
  assertEquals "10,15" "$lines"
}

testScanningGitlabCIValidMultiDocumentFile() {
  cd "$base_dir"/test/unit/files-edge/gitlab-multi-document-success
  r=$("$script" gitlab-ci)
  assertEquals 0 "$?"
  assertContains "$r" "Checked 1 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 0."

  out=$(SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=codequality "$script" gitlab-ci 2>/dev/null)
  assertEquals 0 "$?"
  assertEquals "[]" "$(echo "$out" | jq -c .)"
}

testGitlabCIReportsMatchAcrossFormatsAndWorkers() {
  for fixture in gitlab-multi-document gitlab-multi-document-success gitlab-source-lines gitlab-extraction-failure; do
    cd "$base_dir"/test/unit/files-edge/"$fixture"
    out=$(SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=codequality SHELLSCAN_JOBS=1 "$script" gitlab-ci 2>/dev/null)
    expected_status=$?
    expected=$(normalizedFindings "$out")
    for format in codequality sarif; do
      for jobs in 1 4; do
        [[ "$format" == codequality && "$jobs" == 1 ]] && continue
        out=$(SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT="$format" SHELLSCAN_JOBS="$jobs" "$script" gitlab-ci 2>/dev/null)
        assertEquals "$fixture $format $jobs exit status" "$expected_status" "$?"
        assertEquals "$fixture $format $jobs findings" "$expected" "$(normalizedFindings "$out")"
      done
    done
  done
}

testScanningGitlabCISourceLineFallbacks() {
  cd "$base_dir"/test/unit/files-edge/gitlab-source-lines
  r=$("$script" gitlab-ci)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 13 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 13."

  out=$(SHELLSCAN_FORMAT=codequality "$script" gitlab-ci 2>/dev/null)
  assertEquals 1 "$?"
  assertEquals "6" "$(findingLines "$out" "SC2086" "./whole-sequence-alias.yml")"
  assertEquals "2" "$(findingLines "$out" "SC2086" "./flow-sequence.yml")"
  assertEquals "3" "$(findingLines "$out" "SC2086" "./heterogeneous-sequence.yml")"
  assertEquals "3" "$(findingLines "$out" "SC2086" "./quoted-newline.yml")"
  assertEquals "2" "$(findingLines "$out" "SC2086" "./root-scalar.yml")"
  assertEquals "4" "$(findingLines "$out" "SC2086" "./root-literal.yml")"
  assertEquals "2" "$(findingLines "$out" "SC2086" "./root-quoted-newline.yml")"
  assertEquals "3" "$(findingLines "$out" "SC2086" "./multi-item-plain.yml")"
  assertEquals "3" "$(findingLines "$out" "SC2086" "./single-nested-sequence.yml")"
  assertEquals "3" "$(findingLines "$out" "SC2086" "./single-plain-gap.yml")"
  assertEquals "6" "$(findingLines "$out" "SC2086" "./nested-alias.yml")"
  assertEquals "3" "$(findingLines "$out" "SC2086" "./root-folded.yml")"
  assertEquals "4" "$(findingLines "$out" "SC2086" "./item-folded.yml")"

  out=$(SHELLSCAN_SECURITY=1 SHELLSCAN_FORMAT=codequality "$script" gitlab-ci 2>/dev/null)
  assertEquals 1 "$?"
  assertEquals "6" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./whole-sequence-alias.yml")"
  assertEquals "2" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./flow-sequence.yml")"
  assertEquals "3" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./heterogeneous-sequence.yml")"
  assertEquals "3" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./quoted-newline.yml")"
  assertEquals "2" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./root-scalar.yml")"
  assertEquals "4" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./root-literal.yml")"
  assertEquals "2" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./root-quoted-newline.yml")"
  assertEquals "3" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./multi-item-plain.yml")"
  assertEquals "3" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./single-nested-sequence.yml")"
  assertEquals "3" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./single-plain-gap.yml")"
  assertEquals "6" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./nested-alias.yml")"
  assertEquals "3" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./root-folded.yml")"
  assertEquals "4" "$(findingLines "$out" "SHELLSCAN-CI-INJECTION" "./item-folded.yml")"
}

testScanningGitlabCIExtractionFailure() {
  cd "$base_dir"/test/unit/files-edge/gitlab-extraction-failure
  r=$("$script" gitlab-ci 2>&1)
  assertEquals 1 "$?"
  assertContains "$r" "Could not parse"
  assertContains "$r" "Checked 4 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 4."

  out=$(SHELLSCAN_FORMAT=codequality "$script" gitlab-ci 2>/dev/null)
  assertEquals 1 "$?"
  n=$(echo "$out" | jq '[.[] | select(.check_name == "SHELLSCAN-YAML-PARSE")] | length')
  assertEquals 4 "$n"
  paths=$(echo "$out" | jq -r '[.[] | select(.check_name == "SHELLSCAN-YAML-PARSE") | .location.path] | sort | join(",")')
  assertEquals "./indirect-recursive-alias.yml,./nested-recursive-alias.yml,./recursive-alias.yml,./unsupported-script.yml" "$paths"
  lines=$(echo "$out" | jq -r '[.[] | select(.check_name == "SHELLSCAN-YAML-PARSE") | .location.lines.begin] | sort | join(",")')
  assertEquals "1,1,1,1" "$lines"
}

testScanningGitlabCIFilesWithSuccess() {
  cd "$base_dir"/"$test_files"/success
  r=$("$script" gitlab-ci)
  assertEquals 0 "$?"
  assertContains "$r" "Checked 6 GitLab CI YAML file(s) with potential scripts embedded. Selectors in error: 0."
}

source "$base_dir"/test/unit/shunit2

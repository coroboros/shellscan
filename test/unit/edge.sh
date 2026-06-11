#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh
edge_files="test/unit/files-edge"

testEdgeNoMatchingFilesGraceful() {
  cd "$base_dir"/test/unit/files/shell/success
  r=$("$script" .sh '--exclude *.sh')
  assertEquals 0 "$?"
  assertContains "$r" "Checked 0 .sh file(s). Errors: 0."
}

testEdgeEnvShebangDetected() {
  cd "$base_dir"/"$edge_files"/env-shebang
  r=$("$script" shebang)
  assertEquals 1 "$?"
  assertContains "$r" "Checked 1 file(s) with a shell shebang. Errors: 1."
}

testEdgeShebangNoNewline() {
  cd "$base_dir"/"$edge_files"/no-newline-shebang
  r=$("$script" shebang)
  assertEquals 0 "$?"
  assertContains "$r" "Checked 1 file(s) with a shell shebang. Errors: 0."
}

testEdgeShebangLongFirstLine() {
  cd "$base_dir"/"$edge_files"/long-first-line-shebang
  r=$("$script" shebang)
  assertEquals 0 "$?"
  assertContains "$r" "Checked 0 file(s) with a shell shebang. Errors: 0."
}

testEdgeBinaryNotShebang() {
  cd "$base_dir"/"$edge_files"/binary-file
  r=$("$script" shebang)
  assertEquals 0 "$?"
  assertContains "$r" "Checked 0 file(s) with a shell shebang. Errors: 0."
}

source "$base_dir"/test/unit/shunit2

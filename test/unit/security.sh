#!/bin/bash
base_dir=$(pwd)
script="$base_dir"/src/shellscan.sh

testExecLongFlagRefused() {
  cd "$base_dir"/test/unit/files/shell/success
  r=$("$script" .sh '--exec echo' 2>&1)
  assertEquals 2 "$?"
  assertContains "$r" "command-execution options are not allowed"
}

testExecShortFlagRefused() {
  cd "$base_dir"/test/unit/files/shell/success
  "$script" .sh '-x echo' >/dev/null 2>&1
  assertEquals 2 "$?"
}

testGlobInOptionsPassedLiterally() {
  # A '*' in fd options must reach fd as a literal pattern, never a shell glob that could turn a
  # crafted filename in the scanned tree (here one named --exec) into an fd command-execution flag.
  tmp=$(mktemp -d)
  : > "$tmp/--exec"
  printf '#!/bin/bash\ntrue\n' > "$tmp/keep.sh"
  cd "$tmp"
  r=$("$script" .sh '--exclude *' 2>&1)
  rc=$?
  cd "$base_dir"
  rm -rf "$tmp"
  assertEquals 0 "$rc"
  assertContains "$r" "Checked 0 .sh file(s)."
}

testDiscoveryFailureFailsClosed() {
  cd "$base_dir"/test/unit/files/shell/success
  r=$("$script" .sh '--this-is-not-a-real-fd-flag' 2>&1)
  assertEquals 2 "$?"
  assertContains "$r" "discovery failed"
}

testEqualsValueOptionPreserved() {
  cd "$base_dir"/test/unit/files/shell/success
  r=$("$script" .sh '--max-depth=1')
  assertEquals 0 "$?"
  assertContains "$r" "Checked 1 .sh file(s). Errors: 0."
}

source "$base_dir"/test/unit/shunit2

#!/bin/bash
set -e

dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

for test in "$dir"/unit/*.sh; do
  echo "--------------------------------------------------------------"
  echo "$test"
  echo "--------------------------------------------------------------"
  (exec "$test");
done

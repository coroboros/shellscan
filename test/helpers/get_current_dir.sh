#!/bin/bash

function get_current_dir() {
  local current_dir

  current_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

  echo "$current_dir"
}

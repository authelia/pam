#!/usr/bin/env bash

set -euo pipefail

FAILED=0

echo "--- :go::service_dog: Running golangci-lint"
golangci-lint run || FAILED=1

echo "--- :yaml::service_dog: Running yamllint"
yamllint . || FAILED=1

if [[ $FAILED -ne 0 ]]; then
  echo "Linting was not successful as one or more linters returned a non-zero exit code"
  exit 1
fi

echo "Linting was successful"

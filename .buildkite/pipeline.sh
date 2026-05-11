#!/usr/bin/env bash

set -euo pipefail

CI_BYPASS="false"
CI_MERGE_QUEUE="false"
CI_MERGE_QUEUE_BYPASS="false"

# Skip CI for documentation-only changes on master and PRs.
if [[ -z "${BUILDKITE_TAG:-}" ]]; then
  if [[ "${BUILDKITE_BRANCH}" == "master" ]]; then
    DIFF_BASE="HEAD~1"
  else
    DIFF_BASE="$(git merge-base --fork-point origin/master 2>/dev/null || echo HEAD~1)"
  fi

  CI_BYPASS=$(git diff --name-only "${DIFF_BASE}" \
    | sed -rn '/^(CODE_OF_CONDUCT\.md|CONTRIBUTING\.md|README\.md|SECURITY\.md|LICENSE|\.editorconfig|\.github\/.*|docs\/.*)/!{q1}' \
    && echo true || echo false)

  if [[ "${CI_BYPASS}" == "true" ]]; then
    buildkite-agent annotate --style "info" --context "ctx-info" < .buildkite/annotations/bypass
  fi
fi

if [[ "${BUILDKITE_PULL_REQUEST_DRAFT:-false}" == "true" ]] && [[ "${BUILDKITE_BRANCH}" =~ ^(dependabot|renovate) ]]; then
  CI_BYPASS="true"
  buildkite-agent annotate --style "info" --context "ctx-info" < .buildkite/annotations/draft
fi

if [[ "${BUILDKITE_BRANCH}" =~ ^gh-readonly-queue/.* ]]; then
  CI_BYPASS="true"
  CI_MERGE_QUEUE="true"
  CI_MERGE_QUEUE_BYPASS=$(git diff --name-only "$(git merge-base origin/master HEAD)" \
    | sed -rn '/^(CODE_OF_CONDUCT\.md|CONTRIBUTING\.md|README\.md|SECURITY\.md|LICENSE|\.editorconfig|\.github\/.*|docs\/.*)/!{q1}' \
    && echo true || echo false)
  buildkite-agent annotate --style "info" --context "ctx-info" < .buildkite/annotations/merge-queue
fi

cat << EOF
env:
  CI_BYPASS: ${CI_BYPASS}
  CI_MERGE_QUEUE: ${CI_MERGE_QUEUE}
  CI_MERGE_QUEUE_BYPASS: ${CI_MERGE_QUEUE_BYPASS}

steps:
  - label: ":service_dog: Linting"
    command: "lint.sh"
    if: build.branch !~ /^(v[0-9]+\.[0-9]+\.[0-9]+)\$\$/ && build.message !~ /\[(skip test|test skip)\]/

  - label: ":hammer_and_wrench: Build & Test"
    command: "build.sh"
    agents:
      build: "unit-test"
    artifact_paths:
      - "*.tar.gz"
      - "*.deb"
      - "checksums*"
      - "*.{c,sp}dx.json"
    key: "build"
    if: build.env("CI_BYPASS") != "true"
EOF

if [[ -n "${BUILDKITE_TAG:-}" ]]; then
cat << EOF

  - label: ":github: Deploy Artifacts"
    command: "ghartifacts.sh"
    depends_on:
      - "build"
    retry:
      automatic: true
    agents:
      upload: "fast"
    key: "artifacts"
    if: build.tag != null && build.env("CI_BYPASS") != "true"

  - label: ":linux: Deploy AUR"
    command: "aurpackages.sh | buildkite-agent pipeline upload"
    if: build.tag != null && build.env("CI_BYPASS") != "true"

  - label: ":debian: :fedora: :ubuntu: Deploy APT"
    command: "aptdeploy.sh"
    depends_on:
      - "artifacts"
    retry:
      automatic: true
    agents:
      upload: "fast"
    if: build.tag != null && build.env("CI_BYPASS") != "true"
EOF
fi

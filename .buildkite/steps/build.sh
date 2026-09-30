#!/usr/bin/env bash

set -euo pipefail

echo "--- :go: Running unit tests"
go test -race ./...

SNAPSHOT_FLAG=""
if [[ -z "${BUILDKITE_TAG:-}" ]]; then
  SNAPSHOT_FLAG="--snapshot"
fi

echo "--- :goreleaser: Building pam_authelia via authelia/crossbuild"
docker run --rm \
  --user 1000:1000 \
  -e GOPATH=/tmp/go \
  -e GOCACHE=/tmp/go-build \
  -e GPG_PASSWORD="${GPG_PASSWORD:-}" \
  -e GPG_KEY_PATH="${GPG_KEY_PATH:-}" \
  -e HOME=/tmp \
  -e NFPM_DEBIAN_PASSPHRASE="${GPG_PASSWORD:-}" \
  -v "$(pwd):/workdir" \
  -v "/buildkite/.gnupg:/tmp/.gnupg" \
  -v "/buildkite/.go:/tmp/go" \
  -v "/buildkite/.sign:/tmp/sign" \
  -v "/buildkite/.tools/go:/usr/local/go" \
  -v "/buildkite/.tools/include:/usr/local/include" \
  -v "/buildkite/.tools/bin/goreleaser:/usr/local/bin/goreleaser" \
  -v "/buildkite/.tools/bin/grype:/usr/local/bin/grype" \
  -v "/buildkite/.tools/bin/syft:/usr/local/bin/syft" \
  authelia/crossbuild \
  goreleaser release --clean --skip=publish,validate ${SNAPSHOT_FLAG}

#!/usr/bin/env bash

set -euo pipefail

if [[ -z "${BUILDKITE_TAG:-}" ]]; then
  echo "BUILDKITE_TAG is empty; nothing to deploy." >&2
  exit 1
fi

gh release create "${BUILDKITE_TAG}" \
  --repo authelia/pam \
  --title "${BUILDKITE_TAG}" \
  --generate-notes \
  pam_authelia*.tar.gz \
  pam_authelia*.tar.gz.cdx.json \
  pam_authelia*.tar.gz.spdx.json \
  pam_authelia*.deb \
  checksums*

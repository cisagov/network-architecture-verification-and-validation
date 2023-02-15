#!/usr/bin/env bash

# Copyright 2023 Battelle Energy Alliance, LLC

set -e
set -o pipefail
set -u

ENCODING="utf-8"

# image name (can be overriden via NAVV_DOCKER_IMAGE env. var.)
NAVV_DOCKER_IMAGE="${NAVV_DOCKER_IMAGE:-ghcr.io/cisagov/network-architecture-verification-and-validation:latest}"
# container engine (docker vs. podman, can be overriden via CONTAINER_ENGINE env. var.)
CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"

[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME" && type $CONTAINER_ENGINE) > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $CONTAINER_ENGINE, $REALPATH and $DIRNAME"
  exit 1
fi
export SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"

pushd "$SCRIPT_PATH"/.. >/dev/null 2>&1

$CONTAINER_ENGINE build -f docker/Dockerfile -t ghcr.io/cisagov/network-architecture-verification-and-validation:latest "$@" .

popd >/dev/null 2>&1

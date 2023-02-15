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
if ! (type "$REALPATH" && type "$DIRNAME" && type "$CONTAINER_ENGINE") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $CONTAINER_ENGINE, $REALPATH and $DIRNAME"
  exit 1
fi
export SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"

# save tarball with image creation date and sha
DOCKER_BACKUP_FILENAME=navv-$CONTAINER_ENGINE-$(date -d "$($CONTAINER_ENGINE inspect --format='{{.Created}}' "$NAVV_DOCKER_IMAGE" | sed "s/ /T/" | sed "s/ +0000 UTC/Z/")" +"%Y%m%d_%H%M%S")_$($CONTAINER_ENGINE images --no-trunc --quiet "$NAVV_DOCKER_IMAGE" | cut -d: -f2 | cut -c 1-12).tar.gz

# backup image and navv-docker.sh
if [[ "$CONTAINER_ENGINE" == "podman" ]]; then
  $CONTAINER_ENGINE save --format oci-archive "$NAVV_DOCKER_IMAGE" | gzip > "$DOCKER_BACKUP_FILENAME"
else
  $CONTAINER_ENGINE save "$NAVV_DOCKER_IMAGE" | gzip > "$DOCKER_BACKUP_FILENAME"
fi
[[ ! -r navv-docker.sh ]] && cp "$SCRIPT_PATH"/navv-docker.sh ./

echo "Transfer $DOCKER_BACKUP_FILENAME and navv-docker.sh to destination host" | tee ./navv_export.txt
echo "Import $NAVV_DOCKER_IMAGE with $CONTAINER_ENGINE load -i $DOCKER_BACKUP_FILENAME" | tee -a ./navv_export.txt
echo "Run with navv-docker.sh" | tee -a ./navv_export.txt

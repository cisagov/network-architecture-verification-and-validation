#!/usr/bin/env bash

# Copyright 2021 Battelle Energy Alliance, LLC

set -e
set -o pipefail
set -u

ENCODING="utf-8"

[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME" && type docker) > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires docker, $REALPATH and $DIRNAME"
  exit 1
fi
export SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"

# default docker image name (can be overriden via NAVV_DOCKER_IMAGE env. var.)
NAVV_DOCKER_IMAGE="${NAVV_DOCKER_IMAGE:-ghcr.io/cisagov/network-architecture-verification-and-validation:latest}"

# save tarball with image creation date and sha
DOCKER_BACKUP_FILENAME=navv-docker_$(date -d "$(docker inspect --format='{{.Created}}' "$NAVV_DOCKER_IMAGE")" +"%Y%m%d_%H%M%S")_$(docker images --no-trunc --quiet "$NAVV_DOCKER_IMAGE" | cut -d: -f2 | cut -c 1-12).tar.gz

# backup docker image and navv-docker.sh
docker save "$NAVV_DOCKER_IMAGE" | gzip > "$DOCKER_BACKUP_FILENAME"
[[ ! -r navv-docker.sh ]] && cp "$SCRIPT_PATH"/navv-docker.sh ./

echo "Transfer $DOCKER_BACKUP_FILENAME and navv-docker.sh to destination host" | tee ./navv_export.txt
echo "Import $NAVV_DOCKER_IMAGE with docker load -i $DOCKER_BACKUP_FILENAME" | tee -a ./navv_export.txt
echo "Run with navv-docker.sh" | tee -a ./navv_export.txt

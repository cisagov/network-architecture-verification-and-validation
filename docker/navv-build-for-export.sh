#!/usr/bin/env bash

set -o pipefail
set -u
set -e
shopt -s nullglob

ENCODING="utf-8"

# install the PyPA build module
python3 -m pip install --no-cache-dir --user -U build

# copy the NAVV source code to a temporary directory and build it there
TEMP_SRC_DIR="$(mktemp -d)"
cp -vr /usr/local/src/navv/* "$TEMP_SRC_DIR"/
pushd "$TEMP_SRC_DIR"/ >/dev/null 2>&1
python3 -m build

# archive the build artifacts to /build and clean up the temporary diractory
cp -vr ./dist/* /build
popd >/dev/null 2>&1
rm -rf "$TEMP_SRC_DIR"

# also download the dependencies into /build
pushd /build >/dev/null 2>&1
python3 -m pip download lxml netaddr openpyxl tqdm
popd >/dev/null 2>&1

ls -lh /build
#!/bin/bash

set -e
set +x

# parameters
export version=$1
export arch=$2
export binfile=$3
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# constants
if [[ -z "$BUILD_DIR" ]]; then
    BUILD_DIR=/tmp/build
fi

# prepare build dir
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# prepare control
mkdir -p "$BUILD_DIR/nftables-blocklist/DEBIAN"
envsubst < "$SCRIPT_DIR/control" > "$BUILD_DIR/nftables-blocklist/DEBIAN/control"

# prepare data
mkdir -p "$BUILD_DIR/nftables-blocklist/usr/bin"
cp "$binfile" "$BUILD_DIR/nftables-blocklist/usr/bin/"

# create deb file
cd "$BUILD_DIR"
dpkg-deb --root-owner-group --build nftables-blocklist nftables-blocklist_"$version"_"$arch".deb

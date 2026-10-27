#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 George Kottler <mail@kottlerg.com>

# .github/scripts/qemu-packages.sh

# QEMU and firmware packages for the CI jobs that boot under QEMU: the
# install list, the cache key, the bounded download, and the offline
# install. The mechanism is specified in docs/build-system.md
# § Continuous Integration.
#
# Usage: qemu-packages.sh key | download <dir> | install <dir>

set -eu

PACKAGES="qemu-system-x86 qemu-system-riscv ovmf qemu-efi-riscv64"

download()
{
    mkdir -p "$1/partial"
    debs=$(realpath "$1")
    fetch="apt-get update && apt-get install -y --download-only \
        --no-install-recommends -o Dir::Cache::Archives=$debs $PACKAGES"
    # Download-only under the timeout: killing apt mid-dpkg would leave the
    # package database half-configured.
    if ! sudo timeout 120 sh -c "$fetch"; then
        echo "::warning::apt fetch from the image's mirror failed or exceeded 120 s; retrying on archive.ubuntu.com"
        sudo grep -rlI 'azure\.archive\.ubuntu\.com' /etc/apt |
            xargs -r sudo sed -i 's|azure\.archive\.ubuntu\.com|archive.ubuntu.com|g'
        sudo timeout 1200 sh -c "$fetch"
    fi
    sudo rm -rf "$debs/partial" "$debs/lock"
    ls -l "$debs"/*.deb
}

install_offline()
{
    ls "$1"/*.deb > /dev/null 2>&1 &&
        sudo apt-get install -y --no-install-recommends \
            -o Dir::Etc::SourceList=/dev/null -o Dir::Etc::SourceParts=- \
            "$(realpath "$1")"/*.deb
}

case "${1:-}" in
key)
    : "${ImageOS:?}" "${ImageVersion:?}"
    # This file holds the install list and the apt flags; its hash covers both.
    echo "qemu-debs-$ImageOS-$ImageVersion-$(sha256sum < "$0" | cut -c1-16)"
    ;;
download)
    download "$2"
    ;;
install)
    if ! install_offline "$2"; then
        echo "::warning::offline install from $2 failed; downloading from the network"
        sudo rm -rf "$2"
        download "$2"
        install_offline "$2"
    fi
    ;;
*)
    echo "usage: $0 key | download <dir> | install <dir>" >&2
    exit 2
    ;;
esac

#!/bin/sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -f "$repo_dir/build/build.ninja" ]; then
    meson setup --reconfigure "$repo_dir/build" "$repo_dir" -Ddrivers=egismoc -Dintrospection=false -Ddoc=false -Dgtk-examples=false -Dinstalled-tests=false -Dudev_rules=disabled -Dudev_hwdb=disabled
else
    meson setup "$repo_dir/build" "$repo_dir" -Ddrivers=egismoc -Dintrospection=false -Ddoc=false -Dgtk-examples=false -Dinstalled-tests=false -Dudev_rules=disabled -Dudev_hwdb=disabled
fi
meson compile -C "$repo_dir/build"
meson test -C "$repo_dir/build" --suite unit-tests --print-errorlogs
sha256sum "$repo_dir/build/libfprint/libfprint-2.so.2.0.0"

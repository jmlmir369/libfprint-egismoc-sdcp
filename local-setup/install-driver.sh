#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ]
[ "$#" -eq 2 ] || { echo "Usage: $0 /absolute/path/to/libfprint-2.so.2.0.0 SHA256" >&2; exit 2; }
[ "${#2}" -eq 64 ] || exit 2
case "$2" in *[!0-9a-fA-F]*) exit 2 ;; esac
driver_src=$(readlink -f -- "$1")
expected_sha=$2
driver_dir=/usr/local/lib/fprint-egismoc-sdcp
dropin=/etc/systemd/system/fprintd.service.d/50-egismoc-sdcp.conf
[ ! -e "$driver_dir" ]
[ ! -e "$dropin" ]
printf '%s  %s\n' "$expected_sha" "$driver_src" | sha256sum -c -
install -d -o root -g root -m 0755 "$driver_dir" /etc/systemd/system/fprintd.service.d
install -o root -g root -m 0644 "$driver_src" "$driver_dir/libfprint-2.so.2.0.0"
ln -s libfprint-2.so.2.0.0 "$driver_dir/libfprint-2.so.2"
printf '%s  libfprint-2.so.2.0.0\n' "$expected_sha" > "$driver_dir/SHA256SUMS"
cat > "$driver_dir/SOURCE.txt" <<'EOF'
Source: https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/547
Base commit: 2d7c5277de08c6b29b3fac7447f17a516fbc4d1c (SDCP v2 development proposal)
Local security patch SHA256: b50e00a15c8638ca2188106ed0473d6ca072389e2a976f2698742a97714fa4be
Built 2026-11-16 for Egis USB 1c7a:05a1 on Ubuntu 26.04.
Changes: real certificate/signature verification; fresh authentication keys;
bounded response parsing; error cleanup; no secret debug dumps.
Only fprintd uses this library through a service-specific LD_LIBRARY_PATH.
Ubuntu package libraries and shared authentication settings are unmodified.
This is a locally tested development driver, not an official Ubuntu release.
EOF
cat > "$driver_dir/rollback.sh" <<'EOF'
#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ]
driver_dir=/usr/local/lib/fprint-egismoc-sdcp
if [ -f "$driver_dir/xfce4-screensaver.pam.before" ]; then
    install -o root -g root -m 0644 "$driver_dir/xfce4-screensaver.pam.before" /etc/pam.d/xfce4-screensaver
fi
rm -f /etc/systemd/system/fprintd.service.d/50-egismoc-sdcp.conf
systemctl daemon-reload
systemctl restart fprintd
echo 'Restored packaged fingerprint driver and original screen-lock authentication.'
EOF
chmod 0755 "$driver_dir/rollback.sh"
cat > "$dropin" <<'EOF'
[Service]
Environment=LD_LIBRARY_PATH=/usr/local/lib/fprint-egismoc-sdcp
UnsetEnvironment=FP_DEVICE_EMULATION G_MESSAGES_DEBUG
EOF
systemctl daemon-reload
if ! systemctl restart fprintd; then
    rm -f "$dropin"
    systemctl daemon-reload
    systemctl restart fprintd
    exit 1
fi
systemctl show fprintd --property=ActiveState --property=Environment
echo 'Installed isolated fingerprint driver. Screen-lock authentication has not yet changed.'

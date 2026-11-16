#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ]
driver_dir=/usr/local/lib/fprint-egismoc-sdcp
pam_file=/etc/pam.d/xfce4-screensaver
[ -f "$driver_dir/rollback.sh" ]
[ -f "$pam_file" ]
if grep -Fq 'pam_fprintd.so' "$pam_file"; then
    echo 'Fingerprint authentication is already configured for the screen locker.'
    exit 0
fi
[ ! -e "$driver_dir/xfce4-screensaver.pam.before" ]
cp -p "$pam_file" "$driver_dir/xfce4-screensaver.pam.before"
pam_tmp=$(mktemp /etc/pam.d/.xfce4-screensaver.XXXXXX)
trap 'rm -f "$pam_tmp"' EXIT HUP INT TERM
{
    printf '%s\n' 'auth sufficient pam_fprintd.so max-tries=3 timeout=10'
    cat "$pam_file"
} > "$pam_tmp"
chown root:root "$pam_tmp"
chmod 0644 "$pam_tmp"
mv "$pam_tmp" "$pam_file"
echo 'Enabled fingerprint first, with the existing password authentication as fallback.'

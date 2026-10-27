#!/bin/bash
# This opt-in setup targets the existing nybo / Cinnamon / seat0 service.
# It never restarts LightDM or terminates the current desktop.
set -euo pipefail
cd -- "$(dirname -- "$0")"
self=$PWD/$(basename -- "$0")
if [[ $EUID != 0 ]]; then
    # Run as the login user: sudo's own prompt goes through PAM, where the
    # rdesk-nthash hook stores the NT hash NLA needs. On a first install the
    # hook only exists afterwards, so sudo asks once more.
    sudo bash "$self" "$@"
    if [[ ${1:-} != --rollback && ! -s $HOME/.config/rdesk/nthash ]]; then
        echo 'Once more, so remote login (NLA) can use your password (first install only):'
        sudo -k
        sudo -v || echo 'Skipped; it is picked up at the next login, unlock or sudo.' >&2
    fi
    exit 0
fi
backup=/var/lib/rdesk-cold-boot
dropin=/etc/systemd/system/rdesk-rdp.service.d/20-cold-boot.conf
dmconf=/etc/lightdm/lightdm.conf.d/95-rdesk-cold-boot.conf
if [[ ${1:-} == --rollback ]]; then
    test -x "$backup/rdesk-rdp.previous"
    if [[ -e $dmconf ]]; then mv -- "$dmconf" "$dmconf.disabled"; fi
    cat > "$dropin" <<'EOF'
[Service]
ExecStart=
ExecStart=/var/lib/rdesk-cold-boot/rdesk-rdp.previous --bind 0.0.0.0:3390
EOF
    rm -f /usr/share/pam-configs/rdesk-nthash
    pam-auth-update --package --remove rdesk-nthash
    systemctl daemon-reload
    systemctl restart rdesk-rdp
    echo 'Previous RDP binary restored. Stock greeter returns on the next boot.'
    exit 0
fi
if [[ $# != 0 ]]; then echo 'Only --rollback is supported' >&2; exit 1; fi
test -x target/release/rdesk-rdp
test -x target/release/rdesk-nthash
test -x /usr/sbin/slick-greeter
test -f /usr/share/xsessions/cinnamon.desktop
getent passwd lightdm >/dev/null
getent passwd nybo >/dev/null
if [[ -e /home/nybo/.config/rdesk/password ]]; then
    echo 'Cold-boot mode requires TLS/system credentials; an NLA password file exists. No changes made.' >&2
    exit 1
fi
install -d -m 0755 "$backup" /usr/local/libexec /etc/systemd/system/rdesk-rdp.service.d
if [[ ! -e $backup/rdesk-rdp.previous ]]; then
    pid=$(systemctl show rdesk-rdp --property=MainPID --value)
    if [[ ! $pid =~ ^[1-9][0-9]*$ ]]; then
        echo 'Start the existing rdesk-rdp service first so its binary can be backed up.' >&2
        exit 1
    fi
    install -m 0755 "/proc/$pid/exe" "$backup/rdesk-rdp.previous"
fi
install -m 0755 target/release/rdesk-rdp /usr/local/libexec/rdesk-rdp.new
mv -f /usr/local/libexec/rdesk-rdp.new /usr/local/libexec/rdesk-rdp
install -m 0755 greeter_bridge.py /usr/local/libexec/rdesk-greeter
# NLA needs the NT hash of the Linux password; this optional PAM hook stores it
# whenever the password is typed (login screen, unlock, sudo). Never blocks a login.
install -m 0755 target/release/rdesk-nthash /usr/local/libexec/rdesk-nthash
install -m 0644 rdesk-nthash.pam-config /usr/share/pam-configs/rdesk-nthash
pam-auth-update --package
install -m 0644 rdesk-greeter.desktop /usr/share/xgreeters/rdesk.desktop
install -m 0644 rdesk-login.tmpfiles /etc/tmpfiles.d/rdesk-login.conf
systemd-tmpfiles --create /etc/tmpfiles.d/rdesk-login.conf
install -m 0644 rdesk-cold-boot.override.conf "$dropin"
# Activate the greeter only once its executable and runtime directory exist.
install -m 0644 rdesk-cold-boot.conf "$dmconf"
systemctl daemon-reload
systemctl restart rdesk-rdp
if ! systemctl is-active --quiet rdesk-rdp; then
    echo 'RDP failed to start; use --rollback and inspect journalctl -u rdesk-rdp.' >&2
    exit 1
fi
echo 'Installed. Current desktop retained; the login bridge starts at the next boot.'

#!/bin/sh
# sudo ./install.sh [--remove]
#
# rdesk-rdpc as a system service for the user running sudo, from boot on,
# and rdesk-greeter (greeter.c) around LightDM's Slick Greeter, so an RDP
# login at the login screen starts that user's session, as on Windows.
# The greeter change takes effect the next time the login screen starts.
set -e
cd "$(dirname "$0")"
u=${SUDO_USER:?run it with sudo}
h=$(getent passwd "$u" | cut -d: -f6)
lib=/usr/local/libexec
dm=/etc/lightdm/lightdm.conf.d/95-rdesk.conf
unit=/etc/systemd/system/rdesk-rdp.service

if [ "$1" = --remove ]; then
	rm -f "$dm" /usr/share/xgreeters/rdesk.desktop /etc/tmpfiles.d/rdesk-login.conf
	systemctl disable --now rdesk-rdp 2>/dev/null || true
	rm -rf "$unit" "$unit.d"
	systemctl daemon-reload
	echo "removed; the stock login screen is back from its next start"
	exit 0
fi

test -x rdesk-rdpc -a -x rdesk-greeter || { echo "make first" >&2; exit 1; }
test -x /usr/sbin/slick-greeter || { echo "no /usr/sbin/slick-greeter" >&2; exit 1; }
install -d "$lib"
install -m755 rdesk-rdpc "$lib/rdesk-rdpc.new" && mv -f "$lib/rdesk-rdpc.new" "$lib/rdesk-rdpc"
install -m755 rdesk-greeter "$lib/rdesk-greeter.new" && mv -f "$lib/rdesk-greeter.new" "$lib/rdesk-greeter"

echo 'd /run/rdesk-login 0755 lightdm lightdm -' >/etc/tmpfiles.d/rdesk-login.conf
systemd-tmpfiles --create /etc/tmpfiles.d/rdesk-login.conf

cat >/usr/share/xgreeters/rdesk.desktop <<EOF
[Desktop Entry]
Name=Slick Greeter, with RDP login
Exec=$lib/rdesk-greeter --user $u -- /usr/sbin/slick-greeter
Type=Application
EOF

# earlier versions' drop-ins (the Rust server) would override this
rm -rf "$unit.d"
cat >"$unit" <<EOF
[Unit]
Description=rdesk-rdpc: RDP server for :0, from the login screen on
After=display-manager.service

[Service]
User=$u
Environment=DISPLAY=:0 XAUTHORITY=$h/.Xauthority HOME=$h USER=$u
ExecStart=$lib/rdesk-rdpc --bind 0.0.0.0:3390
Restart=always
RestartSec=5
LimitCORE=0

[Install]
WantedBy=graphical.target
EOF
systemctl daemon-reload
systemctl enable rdesk-rdp
systemctl restart rdesk-rdp

# last: LightDM picks the wrapper only once everything it needs is there
printf '[Seat:*]\ngreeter-session=rdesk\n' >"$dm"
echo "installed for $u; the login screen takes it from its next start (reboot or logout)"

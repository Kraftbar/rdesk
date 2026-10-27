rdesk
=====

RDP server for a live X11 desktop. H.264 (NVENC) to mstsc, 1:1 window
for phones. Built on IronRDP. See WORKNOTES.md.

    rdp.rs      rdesk-rdp, the server
    x11cap.rs   capture, cursor, ffmpeg
    server.rs   rdesk-server, older custom protocol
    client.rs   client for rdesk-server
    proto.rs    its wire format

Build
-----

    cargo build --release

Needs ffmpeg, openssl, DISPLAY. NVENC, or --cpu for libx264.

Usage
-----

    rdesk-rdp [options]

    --bind ADDR:PORT    default 0.0.0.0:3390
    --fps N             default 30
    --bitrate RATE      default 12M
    --cpu               libx264 instead of NVENC
    --pass PASSWORD     NLA with this password
    --pass-file FILE    same, from a file (default ~/.config/rdesk/password)
    --set-password      store the NT hash of your Linux password, then exit
    --viewport          1:1 window for every smaller client
    --certdir DIR       default ~/.config/rdesk
    --cold-boot         single LightDM login, desktop sized to the client

User is the Linux user running it. Login is the Linux password with NLA:
mstsc prompts like it does for Windows, nothing saved. NLA needs the
password's NT hash (~/.config/rdesk/nthash); install-cold-boot.sh adds an
optional PAM hook that stores it whenever you type the password (login
screen, unlock, sudo), so it also follows password changes; run as
yourself, the installer's sudo prompt stores it. The server
switches to NLA by itself once the file appears. Before that: TLS, mstsc
must have the password saved (or run --set-password). With --pass: NLA with
that fixed password.

Client bugs
-----------

iOS Windows app: Ctrl + "+" is never sent. Use Ctrl + "=" to zoom in
(rdesk maps it), Ctrl + "-" to zoom out.

Service
-------

    sudo cp rdesk-rdp.service /etc/systemd/system/
    sudo systemctl enable --now rdesk-rdp

Starts as root to read LightDM's X cookie, then drops to USER; serves the
login screen after a reboot and the session that follows. Edit USER/HOME in
the unit.

Cold-boot experiment (this Mint/Cinnamon host)
--------------------------------------------

    cargo build --release --bin rdesk-rdp
    bash install-cold-boot.sh    # as yourself; sudo asks for your password

Installs a LightDM wrapper around Slick Greeter, a protected local login socket,
and an RDP service override with --cold-boot. It restarts only RDP; the wrapper
takes effect on the next boot. A copy of the previously running server is kept
for rollback. The supplied configuration selects nybo on seat0.

Test from a LAN laptop: reboot the host, leave it at the login screen, and use
mstsc at 1920x1080 and the **Linux** password (see above). LightDM authenticates those credentials with PAM and
starts Cinnamon; RDP waits for the desktop, switches the monitor to the client's
size if it has that mode (else the largest mode that fits; phones keep the
monitor's own mode), and begins streaming. The physical monitor changes too. No password is saved by
the bridge. Normal local login remains available through Slick Greeter.

Existing Cinnamon sessions keep their resolution. This first version supports
one unrotated monitor, the normal password PAM
conversation, and the system password (TLS or nthash NLA). NLA password files and additional PAM
prompts (OTP/password changes) are not supported by --cold-boot. A locked existing
session is outside this boot-login experiment. The selected display mode is not
automatically restored on disconnect.

The server follows X screen-size changes without reconnecting, keeping the RDP
surface fixed and rebuilding capture/encoding as needed. This does not implement
client Display Control/window-resize negotiation.

    journalctl -u rdesk-rdp -b --no-pager
    sudo bash install-cold-boot.sh --rollback

Rollback restarts the saved RDP binary and restores the stock greeter at the next
boot; it does not interrupt the current local desktop.

Checks: `python3 -B -m unittest -v test_greeter_bridge` exercises local/remote
authentication routing, failure recovery and the installed liblightdm against a
simulated daemon. `cargo test --bin rdesk-rdp` checks sizing and input mapping.
The ignored `live_capture_tracks_resize` test requires a disposable Xephyr server
specified by RDESK_TEST_DISPLAY. A real cold boot + mstsc remains the acceptance
test; these component checks do not establish end-to-end login success. The user
confirmed successful LAN remote login on 2026-09-17, followed by a remote
disconnect and local logout/login that restored the normal display setup.

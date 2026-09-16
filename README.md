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
    --viewport          1:1 window for every smaller client
    --certdir DIR       default ~/.config/rdesk

User is the Linux user running it. Without --pass: TLS, system password,
mstsc must have it saved. With: NLA, mstsc prompts.

Service
-------

    sudo cp rdesk-rdp.service /etc/systemd/system/
    sudo systemctl enable --now rdesk-rdp

Starts as root to read LightDM's X cookie, then drops to USER; serves the
login screen after a reboot and the session that follows. Edit USER/HOME in
the unit.

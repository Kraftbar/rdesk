rdesk
=====

RDP server for a live X11 desktop. Streams the screen as H.264 (NVENC via
ffmpeg) to plain mstsc; phones get a 1:1 window onto the screen. Built on
IronRDP.

Files
-----

    rdp.rs       rdesk-rdp, the RDP server (use this)
    x11cap.rs    XShm capture, cursor overlay, ffmpeg spawn
    server.rs    rdesk-server, older custom protocol (Noise over TCP)
    client.rs    rdesk-client for rdesk-server
    proto.rs     wire format for server/client
    rdesk-rdp.service   systemd user unit
    WORKNOTES.md        design notes, gotchas, roadmap

Build
-----

    cargo build --release

Needs ffmpeg and openssl on PATH, an NVIDIA card for NVENC (--cpu for
libx264), DISPLAY set.

Usage
-----

    rdesk-rdp [--bind 0.0.0.0:3390] [--fps 30] [--bitrate 12M] [--cpu]
              [--pass PASSWORD | --pass-file FILE] [--viewport]
              [--certdir ~/.config/rdesk]

Log in as the Linux user running the server.

Default: TLS, system password (checked with unix_chkpwd, nothing stored).
mstsc only sends a password it has saved, so tick "Allow me to save
credentials".

--pass / --pass-file: NLA with a dedicated password; mstsc prompts each
time. ~/.config/rdesk/password (mode 600) is picked up automatically.

A self-signed certificate is written to --certdir on first run.

Display: the session takes the client's desktop size and the screen is
scaled to fit. A client that would shrink it below 45 % (a phone held
upright) gets a 1:1 window instead, panned by pushing the pointer against
the edge; --viewport forces that for every smaller client.

Codecs: H.264 AVC420 over GFX for mstsc; planar dirty rectangles over GFX
for clients that refuse H.264 (iOS); IronRDP bitmap updates for clients
without GFX.

Service
-------

    cp rdesk-rdp.service ~/.config/systemd/user/
    systemctl --user enable --now rdesk-rdp
    journalctl --user -u rdesk-rdp

rdesk-server / rdesk-client
---------------------------

    rdesk-server [--bind 0.0.0.0:7000] [--fps 30] [--bitrate 12M] [--cpu]
    rdesk-client HOST:7000

No auth, no encryption beyond Noise; LAN or SSH tunnel only. Superseded by
rdesk-rdp.

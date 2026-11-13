rdesk
=====

RDP server for a live X11 desktop, and an RDP client for X11, in C with
no RDP libraries. (The earlier Rust version, rdesk-rdp on IronRDP, with
the cold-boot LightDM login, is in the history before this layout.)

    rdp.c rdp.h       wire format: buffers, TPKT/fast-path, BER/PER, MCS, channels
    nla.c             CredSSP v2-6, NTLMv2 (MIC, key exchange), SPNEGO, MD4/RC4
    planar.c          RDP 6.0 planar codec
    clip.c            text clipboard, cliprdr <-> X11 CLIPBOARD, either side
    server.c          rdesk-rdpc, the server
    gfx.c, rfx.c      its graphics pipeline: H.264 (x264), RemoteFX (Progressive)
    client.c          rdesk-rdpc-client, the client
    gfxc.c, gfxdec.c  its graphics pipeline: H.264 (libavcodec), Progressive,
                      ClearCodec; display control (resizing)
    gfxreplay.c       decodes a recorded graphics session without a server
    greeter.c         rdesk-greeter: LightDM's greeter, wrapped, for RDP logins
    install.sh        the service and the greeter, system-wide (sudo)

Build: `make` (and `make gfxreplay`). Needs libssl, Xlib, Xext, Xfixes,
Xdamage, Xrandr, Xcursor, libXtst.so.6, libx264, libavcodec.

Server
------

    rdesk-rdpc [--bind ADDR:PORT] [--fps N] [--pass PW] [--certdir DIR]
               [--no-nla] [--set-password] [-v|-vv]

Needs DISPLAY (and XAUTHORITY when started outside the desktop). Default
port 3390, certdir ~/.config/rdesk (cert.pem, key.pem, nthash). NLA when
the nthash file exists or with --pass; the password the client delegates
is then checked with unix_chkpwd as well. Otherwise TLS, password from the
client info. A successful Linux-password login stores the nthash, so NLA
turns on by itself.

Frames go as H.264 to clients that take it (mstsc), RemoteFX Progressive
to those that don't (the iOS app), else planar bitmaps. A phone gets the
real session reshaped to its size (xrandr, text scaling), put back when
it leaves. RDESK_OFF=phone,gfx,avc,... switches parts off.

From boot, as on Windows: `sudo ./install.sh` runs the server as a
system service for you, and wraps Slick Greeter in rdesk-greeter. At the
login screen an NLA login then starts your session, no login screen to
type into; the connection stays up through it. The greeter lets you onto
the login screen's X server (xhost localuser) so the server needs no
root. `sudo ./install.sh --remove` undoes it.

Client
------

    rdesk-rdpc-client [-u USER] [-d DOMAIN] [-p PW] [-g WxH] [--no-nla]
                      [--type TEXT] [--dump FILE.ppm [--dump-ms N]] HOST[:PORT]

Password also from $RDP_PASSWORD, else prompted. With the graphics
pipeline (Windows, rdesk-rdpc) the window is resizable and the desktop
follows it. RDESK_OFF=gfx for bitmaps only; RDESK_GFX_RECORD=FILE saves
the graphics for gfxreplay.

Tested against
--------------

Server: mstsc, the iOS Windows App, xfreerdp3, the client.
Client: Windows 11 (NLA, ClearCodec, Progressive, H.264, resizing,
clipboard), the server.

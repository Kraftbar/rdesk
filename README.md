# rdesk

Remote desktop for an X11 box with NVENC-encoded H.264 instead of xrdp's
zlib tiles. Flat layout, ffmpeg does the codec work.

    rdp.rs      rdesk-rdp: native RDP server on IronRDP. Plain mstsc connects;
                video is H.264 AVC420 over the GFX pipeline, legacy RemoteFX for
                clients without H.264. Login as the Linux user (TLS) or NLA with --pass.
    server.rs   rdesk-server: the earlier custom protocol (Noise-encrypted TCP)
    client.rs   rdesk-client: custom client for rdesk-server (Linux/Windows)
    x11cap.rs   XShm grab, cursor overlay, ffmpeg spawn, shared by both servers
    proto.rs    wire format for server/client

## rdesk-rdp (use this one)

    ./target/release/rdesk-rdp [--bind 0.0.0.0:3390] [--fps 30] [--bitrate 12M] [--cpu] [--pass FIXED] [--viewport]

Two login modes:

- default: TLS without NLA, like xrdp. Log in as the Linux user running the
  server with that user's system password, checked through PAM's `unix_chkpwd`
  (nothing stored). mstsc only sends a password it has *saved* to a non-NLA
  server, so tick "Allow me to save credentials" or it will just reprompt.
- `--pass FIXED`: NLA (CredSSP/NTLM) with a fixed password; mstsc prompts each
  time. NTLM needs the password on the server, which is why the system
  password can't be used here.

First run writes a self-signed cert to `~/.config/rdesk/`; mstsc warns about it
once. Needs `ffmpeg` and `openssl` on PATH, `DISPLAY` set.

The session is negotiated at the client's own desktop size and the screen is
scaled into it, letterboxed (3440x1440 on a 1920x1080 laptop shows as
1920x802 with black bars); mouse coordinates are mapped back. Same-size
clients get the screen 1:1.

A client that would have to shrink the screen below 45 % (a phone held
upright) instead gets a 1:1 window onto it (992x1850 phone → 992x1440 of the
screen, opened around the pointer). Pushing the pointer into a 48 px border
pans the window; pinch-zoom in the RD app then enlarges real pixels. A
laptop, or a phone on its side, stays scaled. `--viewport` forces the window
for every smaller client. `rdesk-rdp.service` is a systemd user unit for it (`cp` to `~/.config/systemd/user/`, `systemctl --user enable --now rdesk-rdp`).

Input arrives as scancodes and is injected as X keycodes, so the server's
keyboard layout applies (æøå fine). Frames: XShm grab -> ffmpeg h264_nvenc
(AVI-framed so each frame is exact) -> AVC420 WireToSurface. Client frame
acks throttle capture, so a slow link lowers fps instead of adding lag.
Clients with GFX but no H.264 (FreeRDP built without it) fall back to
IronRDP's bitmap updates.

IronRDP serves one client at a time; the listener sets `TCP_USER_TIMEOUT`
(20 s) so a peer that vanishes mid-handshake can't hold the door.

Diagnostics: `RUST_LOG=info,ironrdp_acceptor=debug,ironrdp_server=debug` logs
every PDU of the handshake; `RDESK_TRACE=1` logs each GFX flush;
`RDESK_TEST=uncompressed` sends a raw test bitmap instead of H.264 to tell
GFX plumbing problems from codec problems.

Gotcha found the hard way: ironrdp-egfx 0.3 takes `Avc420Region` bounds as
inclusive and derives the WireToSurface destRect as right+1/bottom+1. Pass
`w-1`/`h-1`; with `w`/`h` the rect overshoots the surface by a pixel and mstsc
silently resets the pipeline (re-advertises caps) on the first frame, then
disconnects.

## rdesk-server / rdesk-client

    cargo build --release
    ./target/release/rdesk-server [--bind 0.0.0.0:7000] [--fps 30] [--bitrate 12M] [--cpu]
    ./target/release/rdesk-client HOST:7000

Both need `ffmpeg` on PATH. Server needs `DISPLAY` set (run it inside the session
you want to see). Client window is resizable; the image is aspect-fit.

## Known gaps (v0)

- No auth, no encryption. LAN or SSH tunnel only:
  `ssh -L 7000:127.0.0.1:7000 host` then connect to `127.0.0.1:7000`.
- Keys go over as US keysyms: letters/digits/F-keys/modifiers work, æøå and
  most punctuation on a Norwegian layout do not (minifb has no names for them).
- 4:2:0 chroma, so small coloured text is a bit soft. `-pix_fmt yuv444p` is a
  one-line change if the client CPU can take it.
- One decoded frame of latency from the h264 parser, plus whatever the pipes
  buffer if the client decodes slower than the server sends.
- One client at a time. Capture is fixed-rate, no damage tracking.
- Decoder is `ffmpeg -threads 1` software; 3440x1440 at 30 fps is fine on a
  desktop CPU, a weak laptop may want `--fps 20` on the server.

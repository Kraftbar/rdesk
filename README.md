# rdesk

Remote desktop for an X11 box with NVENC-encoded H.264 instead of xrdp's
zlib tiles. Flat layout, ffmpeg does the codec work.

    rdp.rs      rdesk-rdp: native RDP server on IronRDP. Plain mstsc connects;
                video is H.264 AVC420 over the GFX pipeline, legacy RemoteFX for
                clients without H.264. NLA login with --user/--pass.
    server.rs   rdesk-server: the earlier custom protocol (Noise-encrypted TCP)
    client.rs   rdesk-client: custom client for rdesk-server (Linux/Windows)
    x11cap.rs   XShm grab, cursor overlay, ffmpeg spawn, shared by both servers
    proto.rs    wire format for server/client

## rdesk-rdp (use this one)

    ./target/release/rdesk-rdp --user na --pass SECRET [--bind 0.0.0.0:3390] [--fps 30] [--bitrate 12M]

First run writes a self-signed cert to `~/.config/rdesk/`; mstsc will warn
about it once. Log in with the --user/--pass values (they are rdesk's own, not
the Linux account). Needs `ffmpeg` and `openssl` on PATH, `DISPLAY` set.

Input arrives as scancodes and is injected as X keycodes, so the server's
keyboard layout applies (æøå fine). Frames: XShm grab -> ffmpeg h264_nvenc
(AVI-framed so each frame is exact) -> AVC420 WireToSurface. Client frame
acks throttle capture, so a slow link lowers fps instead of adding lag.

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

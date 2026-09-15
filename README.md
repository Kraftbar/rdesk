# rdesk

Tiny remote desktop for an X11 box: NVENC-encoded H.264 over TCP instead of
xrdp's zlib tiles. Two binaries, flat layout, ffmpeg does the codec work.

    server.rs   XShm screen grab + cursor overlay -> ffmpeg (h264_nvenc, libx264 fallback) -> TCP
                client input -> XTest
    client.rs   TCP -> ffmpeg decode -> minifb window; mouse/keys -> server
    proto.rs    the 5-message wire format

## Run

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

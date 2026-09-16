Work notes
==========

How it works
------------

Capture: XShm grab of the root window at --fps, XFIXES cursor blended in.
Encode: raw BGRA piped to ffmpeg h264_nvenc (constrained baseline, no
B-frames, VBR-capped so no filler NALs), AVI-framed so each access unit
comes back with an exact size. Send: AVC420 WireToSurface over the GFX
pipeline. The client's frame acks throttle capture, so a slow link lowers
fps instead of adding lag.

Input: scancodes are injected as X keycodes (evdev + 8), so the server's
keyboard layout applies. Unicode key events (on-screen keyboards) are typed
through the X keymap; characters the layout lacks get bound to a spare
keycode on the fly.

Session size: negotiated at the client's size (with_honor_client_desktop_size)
and the screen scaled into it, letterboxed, mouse mapped back. Window mode
for small clients: a client-sized 1:1 crop that pans when the pointer is
pushed into a 48 px border. The encoder is fed the cropped frame so the
window moves per frame.

Clients that refuse H.264 (the iOS Windows app sets AVC_DISABLED) still get
GFX: the client-sized frame is diffed in 64 px tiles, changed spans are sent
as planar (raw planes) WireToSurface rectangles, at most ~1 MB per frame,
two frames in flight, paced by frame acks. Clients without GFX fall back to
IronRDP's bitmap updates (NSCodec, RemoteFX, or raw, whatever they offer).

IronRDP serves one client at a time. rdesk owns the accept loop and sets
TCP_USER_TIMEOUT (20 s) on the listener, otherwise a peer that vanishes
mid-handshake holds the loop for the kernel's 15 minutes of retransmits
while new clients queue up unanswered.

Login: TLS mode validates the ClientInfo password with PAM's unix_chkpwd.
NLA mode (--pass, --pass-file) needs the password on the server because NTLM
does, so it is a dedicated password, not the Linux one.

Gotchas
-------

ironrdp-egfx 0.3 takes Avc420Region bounds as inclusive and derives the
WireToSurface destRect as right+1/bottom+1. Pass w-1/h-1; with w/h the rect
overshoots the surface by a pixel and mstsc silently resets the pipeline
(re-advertises caps) on the first frame, then disconnects. Cost an afternoon.

ironrdp intersects GFX caps flags with AND, so a client's AVC_DISABLED is
lost unless the server sets it too. Confirming AVC to a client that disabled
it makes the iOS app close the channel (error 0x200d).

Every GFX PDU on the wire is inside a ZGFX segment. ironrdp wraps its own
queue in drain_output; PDUs built by hand must go through
ironrdp_graphics::zgfx::wrap_uncompressed or the client drops the channel.
Looks exactly like a codec problem.

The iOS app rejects ironrdp's planar RLE (channel close) but takes raw
planes. Not investigated which side is wrong.

The iOS app never sends Display Control layout changes on rotation, so
server-side resize handling does nothing for it. Tried twice, reverted.

mstsc without NLA never sends a typed password, only a saved one.

A Windows-style per-client virtual desktop (headless Xorg + XFCE per
client) was built and rejected: the point is the live desktop with its open
windows. Patch not kept.

Diagnostics
-----------

    RUST_LOG=info,ironrdp_acceptor=debug,ironrdp_server=debug   every handshake PDU
    RDESK_TRACE=1            log each GFX flush
    RDESK_TEST=uncompressed  raw test bitmap instead of any codec
    RDESK_PLANAR=rle|raw|off planar RLE / raw planes / uncompressed
    RDESK_BUDGET=BYTES       planar bytes per frame (default 1 MiB)
    RDESK_INFLIGHT=N         planar frames in flight (default 2)

When a client connects then drops: look for a second "client gfx caps" in
the log (client reset the pipeline) and for a wedged flow with
ss -tan '( sport = :3390 )' before touching code.

Limits and roadmap
------------------

Against a Windows host, in order of how much you feel it:

1. Cursor is baked into the video and trails by a frame or two. Windows
   sends the pointer shape; IronRDP has the pointer updates. Small.
2. Fixed-rate full-frame capture, 30 encodes/s even when idle. XDamage
   would make idle free and motion faster.
3. 4:2:0 chroma, coloured small text is soft. mstsc takes AVC444 (two H.264
   streams); the chroma packing is the work.
4. No clipboard, no sound. IronRDP has both channels.
5. Phone bandwidth: raw planes are 3 B/px; a spec-correct RLE would cut
   that ~5x on mobile data.
6. One client at a time, one monitor, no dynamic resize. Structural.

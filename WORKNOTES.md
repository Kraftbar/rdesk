Work notes
==========

How it works
------------

Codecs: H.264 AVC420 over GFX for mstsc; planar dirty rectangles over GFX
for clients that refuse H.264 (iOS); IronRDP bitmap updates for clients
without GFX. A self-signed certificate is written to --certdir on first run.

Old rdesk-server/rdesk-client: `rdesk-server [--bind 0.0.0.0:7000] [--fps
30] [--bitrate 12M] [--cpu]`, `rdesk-client HOST:7000`. Noise over TCP, no
auth; LAN or SSH tunnel only. Superseded by rdesk-rdp.

Capture: XShm grab of the root window at --fps; the pointer goes as its own shape.
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
and the screen scaled into it, letterboxed, mouse mapped back. A client that
would shrink the screen below 45 % (a phone held upright) gets a client-sized
1:1 crop instead, panned when the pointer is pushed into a 48 px border;
--viewport forces that for every smaller client. The encoder is fed the
cropped frame so the window moves per frame.

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

Dynamic resize: neither client sent a Display Control layout change in
practice — the iOS app never does on rotation, and mstsc did not on window
resize either (its default smart-sizing scales locally instead). Handling
was implemented three times and rolled back three times. Don't again unless
the log shows a layout PDU arriving (ironrdp_server=debug: "Requesting
layout").

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

2026-09-17 cold-boot experiment: --cold-boot plus install-cold-boot.sh routes
saved TLS RDP credentials through greeter_bridge.py. It proxies the real
LightDM pipes while Slick Greeter remains the local UI; remote PAM conversations
have distinct sequence numbers, one secret response, a 20s deadline, and UID
checks on both ends of the local socket. PAM success is acknowledged before
START_SESSION because LightDM may terminate the greeter while handling START.
The RDP side still requires Cinnamon's actual WM to appear before accepting the
connection, then applies 1920x1080 and waits 3s for that mode to settle. Existing
sessions are authenticated normally without resizing. Passwords are neither
typed into X nor saved. No root network/session-launch helper was added.

Capture now queries live root geometry and replaces its locked SHM allocation
on mode changes. AVC restarts ffmpeg on the same RDP surface; planar/legacy
frames use the new geometry directly. Source size is even-aligned, preserving
1080 rows (old startup code rounded down to 1072). Fit's native fast path now
requires equal source/output dimensions, not just equal aspect ratio.

Verified: bridge state/failure tests and real installed liblightdm with a fake
daemon; sizing/input unit tests; three shrink/grow cycles on disposable Xephyr
using real SHM and RandR; NVENC output reports 1920x1080. User confirmed the LAN
remote-login test worked on 2026-09-17. After closing the remote connection,
logging out and back in locally returned the display to its normal setup.
See README for setup/rollback.

Login after a reboot: rdesk runs as a system service started as root with
LightDM's cookie (XAUTHORITY=/var/run/lightdm/root/:0, USER=nybo), connects
to :0, then drops to USER before opening the network, so it mirrors the
login screen and the session that follows on the same X server. RDP
in, type the password into Mint's login screen, Cinnamon starts. LightDM
restarts X on logout; a watchdog exits on a dead X connection and systemd
starts a fresh one. Done 2026-09-16; a per-user unit only works once someone
has logged in at the keyboard.

NLA with the Linux password (2026-09-23): ~/.config/rdesk/nthash holds
MD4(UTF-16LE(password)). shadow's SHA-512 crypt can't be converted, so the
hash is caught when the password is typed: rdesk-nthash (pam_exec
expose_authtok, optional, via pam-auth-update into common-auth after
pam_permit; drops to the user, rechecks with unix_chkpwd), every successful
RDP login, or --set-password. The server polls the file while idle and exits
on change; systemd restarts it in the new mode. sspi takes "$NTLM$:<hex>" as the server password, so NTLM needs no
plaintext. After NTLM, mstsc delegates the plain password (TSPasswordCreds);
stock ironrdp-acceptor drops it, vendor/ironrdp-acceptor passes it on as
AcceptorResult.credentials, so the TLS-mode validator (unix_chkpwd, or the
cold-boot LightDM bridge) runs unchanged. A stale hash just fails NTLM; a hash
that matches an old password still fails unix_chkpwd.

Stale sessions (2026-09-23): a client that vanished without FIN (laptop
asleep) held the single IronRDP slot for 68 min, since TCP_USER_TIMEOUT only
fires with unacked data; new connects queued and failed. Now the accept loop
keeps accepting during a session: a newcomer replaces a connection still in
the handshake (mstsc's abandoned pre-prompt one, which had also delayed the
real one by up to 15 s) or one with no frame ack/input for 10 s; a live one
refuses it instead of letting it queue. Plus TCP keepalive (10 s + 3x5 s).

Against a Windows host, in order of how much you feel it:

1. Cursor (done 2026-09-23, confirmed on mstsc): the client draws the pointer.
   Updates polls XFIXES every 16 ms and sends a 32 bpp NewPointer (cache 0,
   straight alpha, bottom-up, cropped to 96x96, no AND mask) when the serial
   changes; frames no longer carry it. RDESK_CURSOR=video restores the old
   baked-in cursor. Not scaled with the picture.
2. Fixed-rate full-frame capture, 30 encodes/s even when idle. XDamage
   would make idle free and motion faster. Also: scaling for the laptop runs
   in swscale (~1.5 cores at 3440x1440→1920x802). hwupload_cuda,scale_cuda
   cuts ffmpeg from 182 % to 34 % CPU (input must be bgr0, not bgra), but
   sending the scaled frame as a smaller surface mapped at the letterbox
   offset rendered wrong in mstsc (tried, reverted). Untried safe variant:
   GPU scale, hwdownload, pad on the CPU at the small size, full-size
   surface as today.
3. 4:2:0 chroma, coloured small text is soft. mstsc takes AVC444 (two H.264
   streams); the chroma packing is the work.
4. No sound (IronRDP has rdpsnd). Clipboard: text both ways since 2026-09-28
   (clip.rs, own X connection opened before the root drop); no images/files.
5. Phone bandwidth: raw planes are 3 B/px; a spec-correct RLE would cut
   that ~5x on mobile data.
6. One client at a time, one monitor, no dynamic resize. Structural.

Phone keys (iOS Windows app): Ctrl combos go out as US-layout scancodes; Ctrl+"+"
is never sent, "=" and "-" arrive as numpad plus/minus. rdesk turns Ctrl + numpad
+/- into the layout's main-row +/- (browser zoom). Key logging for debugging:
touch ~/.config/rdesk/keylog (logs everything typed; remove after).


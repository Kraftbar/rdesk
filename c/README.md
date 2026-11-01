rdesk in C
==========

From-scratch port of rdesk-rdp, no RDP libraries. Takes over the
rdesk-rdp / rdesk names once it matches the Rust version.

    rdp.c rdp.h   wire format: buffers, TPKT/fast-path, BER/PER, MCS, channels
    nla.c         CredSSP v2-6, NTLMv2 (MIC, key exchange), SPNEGO, MD4/RC4
    planar.c      RDP 6.0 planar codec (decoder)
    clip.c        text clipboard, cliprdr <-> X11 CLIPBOARD, either side
    server.c      rdesk-rdpc, the server
    client.c      rdesk-rdpc-client, the client

Build: `make`. Needs libssl, Xlib, Xext, Xfixes, Xcursor, libXtst.so.6.

Server
------

    rdesk-rdpc [--bind ADDR:PORT] [--fps N] [--pass PW] [--certdir DIR]
               [--no-nla] [--set-password] [-v|-vv]

Default port 3390, certdir ~/.config/rdesk (cert.pem, key.pem, nthash,
shared with the Rust version). NLA when the nthash file exists or with
--pass; the password the client delegates is then checked with unix_chkpwd
as well. Otherwise TLS, password from the client info. A successful
Linux-password login stores the nthash, so NLA turns on by itself.

Milestone 1: raw 32 bpp tiles (64x64, changed only), LAN bandwidth.

Client
------

    rdesk-rdpc-client [-u USER] [-d DOMAIN] [-p PW] [-g WxH] [--no-nla]
                      [--type TEXT] [--dump FILE.ppm [--dump-ms N]] HOST[:PORT]

Password also from $RDP_PASSWORD, else prompted. Sends raw NTLMSSP in
CredSSP like mstsc does without Kerberos; RDESK_SPNEGO=1 wraps it in SPNEGO.
Decodes raw and planar bitmaps; no interleaved RLE, no GFX yet.

Tested against
--------------

xfreerdp3 3.32 -> server: TLS, NLA, wrong password (LOGON_FAILURE), clipboard.
rdesk-rdp (IronRDP, sspi-rs) -> client: NLA, planar, clipboard.
Not yet: mstsc, the iOS app, Windows hosts.

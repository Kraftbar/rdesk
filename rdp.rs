//! rdesk-rdp: a native RDP server for the local X11 desktop, so plain mstsc
//! can connect. Built on IronRDP; frames go out as H.264 (AVC420) over the
//! graphics pipeline, encoded by NVENC through ffmpeg. Input comes back as
//! scancodes and is injected with XTest, so the server's keyboard layout applies.

mod x11cap;

use anyhow::Context as _;
use ironrdp_egfx::pdu::{Avc420Region, CapabilitiesAdvertisePdu, CapabilitySet};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_server::{
    CredentialDecision, CredentialValidationError, CredentialValidator, Credentials, DesktopSize, DisplayUpdate,
    EgfxServerMessage, GfxDvcBridge, GfxServerFactory, GfxServerHandle, KeyboardEvent, MouseEvent, RdpServer,
    RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler, ServerEvent, ServerEventSender, TlsIdentityCtx,
};
use ironrdp_svc::ChannelFlags;
use core::num::{NonZeroU16, NonZeroUsize};
use ironrdp_server::PixelFormat;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info, warn};
use x11cap::*;
use x11rb::connection::Connection;
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xproto::{self, ImageFormat};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

struct Opts {
    bind: String,
    fps: u32,
    bitrate: String,
    cpu: bool,
    user: String,
    pass: String,
    certdir: PathBuf,
}

fn parse_args() -> Opts {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let mut o = Opts {
        bind: "0.0.0.0:3390".into(), fps: 30, bitrate: "12M".into(), cpu: false,
        user: String::new(), pass: String::new(), certdir: PathBuf::from(format!("{}/.config/rdesk", home)),
    };
    let mut a = std::env::args().skip(1);
    while let Some(k) = a.next() {
        match k.as_str() {
            "--bind" => o.bind = a.next().expect("--bind ADDR:PORT"),
            "--fps" => o.fps = a.next().expect("--fps N").parse().expect("fps"),
            "--bitrate" => o.bitrate = a.next().expect("--bitrate 12M"),
            "--cpu" => o.cpu = true,
            "--pass" => o.pass = a.next().expect("--pass PASSWORD"),
            "--certdir" => o.certdir = a.next().expect("--certdir DIR").into(),
            _ => {
                eprintln!("usage: rdesk-rdp [--bind 0.0.0.0:3390] [--fps 30] [--bitrate 12M] [--cpu] [--certdir ~/.config/rdesk] [--pass STATIC]");
                eprintln!("login is the Linux user running the server + their password (via unix_chkpwd); --pass replaces that with a fixed one");
                std::process::exit(2);
            }
        }
    }
    o.user = std::env::var("USER").unwrap_or_default();
    if o.user.is_empty() { eprintln!("USER not set"); std::process::exit(2); }
    o
}

/// Everything the per-connection pieces need about the machine.
struct Ctx {
    conn: Arc<RustConnection>,
    root: xproto::Window,
    w: u16,
    h: u16,
    shm: Arc<Shm>,
    fps: u32,
    bitrate: String,
    nvenc: bool,
    /// How frames reach the current client; decided once the GFX channel negotiates.
    mode: Mutex<Mode>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Unknown,
    /// H.264 over the graphics pipeline (mstsc, H.264-capable FreeRDP).
    Avc,
    /// Plain bitmap updates through the display handler; IronRDP encodes (RemoteFX/RLE).
    Legacy,
}

// ---------------------------------------------------------------- login

/// Accepts the Linux user running the server with their system password, checked
/// by PAM's own setgid helper (unix_chkpwd only verifies the calling user, which
/// is exactly the scope we want). `--pass` swaps in a fixed password instead.
struct Login {
    user: String,
    fixed: Option<String>,
}

fn unix_chkpwd(user: &str, pass: &str) -> bool {
    let mut child = match Command::new("/sbin/unix_chkpwd")
        .args([user, "nullok"])
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .spawn() { Ok(c) => c, Err(e) => { error!("unix_chkpwd: {}", e); return false } };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(pass.as_bytes());
        let _ = si.write_all(&[0]);
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

#[async_trait::async_trait]
impl CredentialValidator for Login {
    async fn validate(&self, c: &Credentials) -> Result<CredentialDecision, CredentialValidationError> {
        // mstsc may send DOMAIN\user or user@domain; only the user part matters here.
        let user = c.username.rsplit('\\').next().unwrap_or("").split('@').next().unwrap_or("").to_lowercase();
        let ok = if user != self.user.to_lowercase() {
            false
        } else if let Some(fixed) = &self.fixed {
            c.password == *fixed
        } else {
            let (u, p) = (self.user.clone(), c.password.clone());
            tokio::task::spawn_blocking(move || unix_chkpwd(&u, &p)).await.unwrap_or(false)
        };
        info!(user = %c.username, ok, "login");
        Ok(if ok { CredentialDecision::Accept } else { CredentialDecision::Reject })
    }
}

// ---------------------------------------------------------------- input

struct Input {
    ctx: Arc<Ctx>,
}

impl Input {
    fn fake(&self, t: u8, detail: u8, x: i16, y: i16) {
        let _ = self.ctx.conn.xtest_fake_input(t, detail, x11rb::CURRENT_TIME, self.ctx.root, x, y, 0);
        let _ = self.ctx.conn.flush();
    }
    fn button(&self, b: u8, pressed: bool) {
        self.fake(if pressed { xproto::BUTTON_PRESS_EVENT } else { xproto::BUTTON_RELEASE_EVENT }, b, 0, 0);
    }
    fn click(&self, b: u8, n: i32) {
        for _ in 0..n.max(1) { self.button(b, true); self.button(b, false); }
    }
    fn key(&self, code: u8, extended: bool, pressed: bool) {
        match keycode(code, extended) {
            Some(kc) => self.fake(if pressed { xproto::KEY_PRESS_EVENT } else { xproto::KEY_RELEASE_EVENT }, kc, 0, 0),
            None => warn!(code, extended, "unmapped scancode"),
        }
    }
}

/// RDP scancode (PC/AT set 1, `extended` = E0 prefix) -> X keycode.
/// Linux evdev keycodes equal set-1 scancodes for the non-extended range, and
/// X keycode = evdev + 8, so only the E0 keys need a table.
fn keycode(code: u8, extended: bool) -> Option<u8> {
    let ev: u16 = if !extended {
        match code { 0 => return None, c => c as u16 }
    } else {
        match code {
            0x1c => 96,  // KP_Enter
            0x1d => 97,  // Control_R
            0x35 => 98,  // KP_Divide
            0x37 => 99,  // Print
            0x38 => 100, // Alt_R / AltGr
            0x46 => 119, // Pause (Ctrl+Break form)
            0x47 => 102, 0x48 => 103, 0x49 => 104, // Home Up PgUp
            0x4b => 105, 0x4d => 106,              // Left Right
            0x4f => 107, 0x50 => 108, 0x51 => 109, // End Down PgDn
            0x52 => 110, 0x53 => 111,              // Insert Delete
            0x5b => 125, 0x5c => 126, 0x5d => 127, // Super_L Super_R Menu
            0x20 => 113, 0x2e => 114, 0x30 => 115, // Mute VolDown VolUp
            0x22 => 164, 0x24 => 166, 0x19 => 163, 0x10 => 165, // Play Stop Next Prev
            _ => return None,
        }
    };
    u8::try_from(ev + 8).ok()
}

impl RdpServerInputHandler for Input {
    fn keyboard(&mut self, e: KeyboardEvent) {
        match e {
            KeyboardEvent::Pressed { code, extended } => self.key(code, extended, true),
            KeyboardEvent::Released { code, extended } => self.key(code, extended, false),
            KeyboardEvent::UnicodePressed(u) | KeyboardEvent::UnicodeReleased(u) => warn!(u, "unicode key ignored"),
            KeyboardEvent::Synchronize(_) => {}
        }
    }
    fn mouse(&mut self, e: MouseEvent) {
        use MouseEvent::*;
        match e {
            Move { x, y } => self.fake(xproto::MOTION_NOTIFY_EVENT, 0, x as i16, y as i16),
            LeftPressed => self.button(1, true), LeftReleased => self.button(1, false),
            MiddlePressed => self.button(2, true), MiddleReleased => self.button(2, false),
            RightPressed => self.button(3, true), RightReleased => self.button(3, false),
            Button4Pressed => self.button(8, true), Button4Released => self.button(8, false),
            Button5Pressed => self.button(9, true), Button5Released => self.button(9, false),
            VerticalScroll { value } => self.click(if value > 0 { 4 } else { 5 }, (value.abs() as i32 / 120).max(1)),
            Scroll { x, y } => {
                if y != 0 { self.click(if y > 0 { 4 } else { 5 }, (y.abs() / 120).max(1)); }
                if x != 0 { self.click(if x > 0 { 7 } else { 6 }, (x.abs() / 120).max(1)); }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- display

struct Display {
    ctx: Arc<Ctx>,
}

/// Legacy-path frame source. Idle while the GFX/H.264 pipeline owns the screen.
struct Updates {
    ctx: Arc<Ctx>,
    started: Instant,
    next: tokio::time::Instant,
}

const LEGACY_FPS: u32 = 15;

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
        loop {
            let mode = *self.ctx.mode.lock().unwrap();
            match mode {
                // GFX path owns the screen; keep polling in case it collapses into Legacy.
                Mode::Avc => tokio::time::sleep(Duration::from_millis(100)).await,
                Mode::Legacy => break,
                Mode::Unknown if self.started.elapsed() > Duration::from_secs(3) => {
                    info!("no GFX channel from client, using legacy bitmap updates");
                    *self.ctx.mode.lock().unwrap() = Mode::Legacy;
                    break;
                }
                Mode::Unknown => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        tokio::time::sleep_until(self.next).await;
        self.next = tokio::time::Instant::now() + Duration::from_secs_f64(1.0 / LEGACY_FPS as f64);
        let ctx = self.ctx.clone();
        let data = tokio::task::spawn_blocking(move || grab(&ctx).map(|()| ctx.shm.buf().to_vec())).await??;
        let (w, h) = (self.ctx.w, self.ctx.h);
        Ok(Some(DisplayUpdate::Bitmap(ironrdp_server::BitmapUpdate {
            x: 0,
            y: 0,
            width: NonZeroU16::new(w).unwrap(),
            height: NonZeroU16::new(h).unwrap(),
            format: PixelFormat::BgrX32,
            data: data.into(),
            stride: NonZeroUsize::new(w as usize * 4).unwrap(),
        })))
    }
}

/// Screen + cursor into the shm buffer.
fn grab(ctx: &Ctx) -> anyhow::Result<()> {
    ctx.conn.shm_get_image(ctx.root, 0, 0, ctx.w, ctx.h, !0, ImageFormat::Z_PIXMAP.into(), ctx.shm.seg, 0)?.reply()?;
    if let Some(cur) = ctx.conn.xfixes_get_cursor_image().ok().and_then(|c| c.reply().ok()) {
        draw_cursor(ctx.shm.buf(), ctx.w as usize, ctx.h as usize, &cur);
    }
    Ok(())
}

#[async_trait::async_trait]
impl RdpServerDisplay for Display {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize { width: self.ctx.w, height: self.ctx.h }
    }
    async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
        *self.ctx.mode.lock().unwrap() = Mode::Unknown;
        Ok(Box::new(Updates { ctx: self.ctx.clone(), started: Instant::now(), next: tokio::time::Instant::now() }))
    }
}

// ---------------------------------------------------------------- GFX / H.264

type EvSender = Arc<Mutex<Option<UnboundedSender<ServerEvent>>>>;

struct GfxFactory {
    ctx: Arc<Ctx>,
    ev: EvSender,
}

impl ServerEventSender for GfxFactory {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self.ev.lock().unwrap() = Some(sender);
    }
}

impl GfxServerFactory for GfxFactory {
    fn build_gfx_handler(&self) -> Box<dyn GraphicsPipelineHandler> {
        // Only used if build_server_with_handle returned None, which it never does.
        Box::new(Gfx { ctx: self.ctx.clone(), ev: self.ev.clone(), handle: Default::default(), stop: Default::default() })
    }
    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        let slot: Arc<Mutex<Option<GfxServerHandle>>> = Default::default();
        let handler = Gfx { ctx: self.ctx.clone(), ev: self.ev.clone(), handle: slot.clone(), stop: Default::default() };
        let handle: GfxServerHandle = Arc::new(Mutex::new(GraphicsPipelineServer::new(Box::new(handler))));
        *slot.lock().unwrap() = Some(handle.clone());
        Some((GfxDvcBridge::new(handle.clone()), handle))
    }
}

struct Gfx {
    ctx: Arc<Ctx>,
    ev: EvSender,
    handle: Arc<Mutex<Option<GfxServerHandle>>>,
    stop: Arc<AtomicBool>,
}

impl GraphicsPipelineHandler for Gfx {
    fn capabilities_advertise(&mut self, pdu: &CapabilitiesAdvertisePdu) {
        info!(n = pdu.0.len(), "client gfx caps");
    }
    fn on_ready(&mut self, negotiated: &CapabilitySet) {
        info!(?negotiated, "gfx ready");
        let Some(handle) = self.handle.lock().unwrap().clone() else { return };
        self.stop = Arc::new(AtomicBool::new(false));
        let (ctx, ev, stop) = (self.ctx.clone(), self.ev.clone(), self.stop.clone());
        thread::spawn(move || {
            if let Err(e) = stream(ctx, ev, handle, stop) { error!("stream: {:#}", e); }
        });
    }
    fn on_close(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // A client that accepts AVC420 in caps but cannot decode it closes the
        // channel after the first frame (FreeRDP built without H.264 does this).
        // FreeRDP then stays black anyway (its GDI is already in GFX mode), but
        // other clients may pick the legacy updates up.
        let mut m = self.ctx.mode.lock().unwrap();
        if *m == Mode::Avc {
            warn!("client closed the GFX channel, falling back to legacy bitmap updates");
            *m = Mode::Legacy;
        }
    }
}

/// Push queued GFX PDUs to the wire through the server event loop.
fn flush(g: &mut GraphicsPipelineServer, ev: &EvSender) -> anyhow::Result<()> {
    let msgs = g.drain_output();
    if msgs.is_empty() { return Ok(()); }
    let ch = g.channel_id().context("gfx channel not open")?;
    let svc = ironrdp_dvc::encode_dvc_messages(ch, msgs, ChannelFlags::SHOW_PROTOCOL)?;
    let guard = ev.lock().unwrap();
    let tx = guard.as_ref().context("no event sender")?;
    tx.send(ServerEvent::Egfx(EgfxServerMessage::SendMessages { messages: svc })).ok();
    Ok(())
}

/// Per-connection pipeline: capture -> ffmpeg (AVI-framed H.264) -> AVC420 frames.
fn stream(ctx: Arc<Ctx>, ev: EvSender, handle: GfxServerHandle, stop: Arc<AtomicBool>) -> anyhow::Result<()> {
    let (w, h) = (ctx.w, ctx.h);
    let surface = {
        let mut g = handle.lock().unwrap();
        if !g.supports_avc420() {
            info!("client has GFX but no AVC420, using legacy bitmap updates");
            *ctx.mode.lock().unwrap() = Mode::Legacy;
            return Ok(());
        }
        let sid = g.create_surface(w, h).context("create_surface")?;
        g.map_surface_to_output(sid, 0, 0);
        flush(&mut g, &ev)?;
        *ctx.mode.lock().unwrap() = Mode::Avc;
        sid
    };
    info!(surface, "streaming {}x{}", w, h);

    let mut enc = spawn_encoder(w, h, ctx.fps, &ctx.bitrate, ctx.nvenc, "avi");
    let mut enc_in = enc.stdin.take().unwrap();
    let mut enc_out = enc.stdout.take().unwrap();

    // Capture thread. Skips ticks while the client has too many frames un-acked,
    // so a slow link just lowers the frame rate instead of building a queue.
    let cap = {
        let (ctx, handle, stop) = (ctx.clone(), handle.clone(), stop.clone());
        let period = Duration::from_secs_f64(1.0 / ctx.fps as f64);
        thread::spawn(move || {
            let mut next = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                next += period;
                let busy = handle.lock().unwrap().should_backpressure();
                if !busy {
                    if grab(&ctx).is_err() { break; }
                    if enc_in.write_all(ctx.shm.buf()).is_err() { break; }
                }
                let now = Instant::now();
                if next > now { thread::sleep(next - now); } else { next = now; }
            }
            stop.store(true, Ordering::Relaxed);
        })
    };

    // This thread: AVI chunks -> AVC420 frames.
    let t0 = Instant::now();
    let region = Avc420Region { left: 0, top: 0, right: w, bottom: h, quantization_parameter: 23, quality: 100 };
    let mut frames = 0u64;
    let mut t_stat = Instant::now();
    let r = (|| -> anyhow::Result<()> {
        let mut avi = Avi::new(&mut enc_out)?;
        while !stop.load(Ordering::Relaxed) {
            let Some(frame) = avi.next_frame()? else { break };
            let ms = t0.elapsed().as_millis() as u32;
            loop {
                let mut g = handle.lock().unwrap();
                if !g.is_ready() { anyhow::bail!("gfx channel closed"); }
                if g.should_backpressure() { drop(g); thread::sleep(Duration::from_millis(1)); continue; }
                g.send_avc420_frame(surface, &frame, std::slice::from_ref(&region), ms).context("send_avc420_frame")?;
                flush(&mut g, &ev)?;
                break;
            }
            frames += 1;
            if t_stat.elapsed() >= Duration::from_secs(5) {
                info!("sent {:.1} fps", frames as f64 / t_stat.elapsed().as_secs_f64());
                frames = 0; t_stat = Instant::now();
            }
        }
        Ok(())
    })();
    stop.store(true, Ordering::Relaxed);
    enc.kill().ok();
    enc.wait().ok();
    cap.join().ok();
    info!("stream ended");
    r
}

/// Minimal reader for ffmpeg's streamed AVI: yields each `00dc` chunk (one H.264 access unit).
struct Avi<'a> {
    r: &'a mut dyn Read,
}

impl<'a> Avi<'a> {
    fn new(r: &'a mut dyn Read) -> anyhow::Result<Self> {
        let mut hdr = [0u8; 12];
        r.read_exact(&mut hdr)?;
        anyhow::ensure!(&hdr[0..4] == b"RIFF" && &hdr[8..12] == b"AVI ", "not an AVI stream");
        Ok(Avi { r })
    }
    fn next_frame(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        loop {
            let mut ch = [0u8; 8];
            if self.r.read_exact(&mut ch).is_err() { return Ok(None); }
            let size = u32::from_le_bytes([ch[4], ch[5], ch[6], ch[7]]) as usize;
            if &ch[0..4] == b"LIST" {
                let mut kind = [0u8; 4];
                self.r.read_exact(&mut kind)?;
                if &kind == b"movi" { continue; }          // chunks follow inline
                self.skip(size - 4)?;
            } else if &ch[0..4] == b"00dc" {
                let mut data = vec![0u8; size];
                self.r.read_exact(&mut data)?;
                if size & 1 == 1 { self.skip(1)?; }
                return Ok(Some(data));
            } else {
                self.skip(size + (size & 1))?;
            }
        }
    }
    fn skip(&mut self, n: usize) -> anyhow::Result<()> {
        std::io::copy(&mut (&mut *self.r).take(n as u64), &mut std::io::sink())?;
        Ok(())
    }
}

// ---------------------------------------------------------------- main

fn ensure_cert(dir: &PathBuf) -> anyhow::Result<(PathBuf, PathBuf)> {
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    if !cert.exists() || !key.exists() {
        std::fs::create_dir_all(dir)?;
        let st = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-subj", "/CN=rdesk"])
            .arg("-keyout").arg(&key).arg("-out").arg(&cert)
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .status().context("run openssl")?;
        anyhow::ensure!(st.success(), "openssl failed");
        info!("generated self-signed cert in {}", dir.display());
    }
    Ok((cert, key))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,ironrdp_server::encoder=error".into()))
        .compact().init();
    let o = parse_args();

    let (conn, screen_num) = x11rb::connect(None).context("connect to X (DISPLAY set?)")?;
    let conn = Arc::new(conn);
    let screen = &conn.setup().roots[screen_num];
    let root = screen.root;
    // AVC420 wants 16-aligned dimensions.
    let (w, h) = (screen.width_in_pixels & !15, screen.height_in_pixels & !15);
    conn.shm_query_version()?.reply().context("MIT-SHM missing")?;
    conn.xfixes_query_version(5, 0)?.reply().context("XFIXES missing")?;
    let shm = Arc::new(Shm::new(&conn, w as usize * h as usize * 4));
    let nvenc = !o.cpu && probe_nvenc();
    let ctx = Arc::new(Ctx { conn, root, w, h, shm, fps: o.fps, bitrate: o.bitrate.clone(), nvenc, mode: Mutex::new(Mode::Unknown) });

    let (cert, key) = ensure_cert(&o.certdir)?;
    let identity = TlsIdentityCtx::init_from_paths(&cert, &key).context("TLS identity")?;
    let acceptor = identity.make_acceptor().context("TLS acceptor")?;

    let ev: EvSender = Default::default();
    let addr: std::net::SocketAddr = o.bind.parse().context("--bind")?;
    let login = Login { user: o.user.clone(), fixed: if o.pass.is_empty() { None } else { Some(o.pass.clone()) } };
    // TLS without NLA, like xrdp: mstsc sends the typed credentials in ClientInfo
    // and we check them against the system password. NLA would need the password
    // stored on the server (NTLM), which is why it is not used here.
    let mut server = RdpServer::builder()
        .with_addr(addr)
        .with_tls(acceptor)
        .with_input_handler(Input { ctx: ctx.clone() })
        .with_display_handler(Display { ctx: ctx.clone() })
        .with_gfx_factory(Some(Box::new(GfxFactory { ctx: ctx.clone(), ev })))
        .with_credential_validator(Some(Arc::new(login)))
        .build();

    info!("rdesk-rdp: {}x{} @{}fps {} encoder={} login={} ({}) listening on {}",
          w, h, o.fps, o.bitrate, if nvenc { "h264_nvenc" } else { "libx264" }, o.user,
          if o.pass.is_empty() { "system password" } else { "--pass" }, o.bind);
    server.run().await?;
    Ok(())
}

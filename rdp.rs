//! rdesk-rdp: a native RDP server for the local X11 desktop, so plain mstsc
//! can connect. Built on IronRDP; frames go out as H.264 (AVC420) over the
//! graphics pipeline, encoded by NVENC through ffmpeg. Input comes back as
//! scancodes and is injected with XTest, so the server's keyboard layout applies.

mod x11cap;

use anyhow::Context as _;
use ironrdp_egfx::pdu::{
    Avc420Region, CapabilitiesAdvertisePdu, CapabilitiesV103Flags, CapabilitiesV104Flags, CapabilitiesV107Flags,
    CapabilitiesV10Flags, CapabilitiesV81Flags, CapabilitiesV8Flags, CapabilitySet,
};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_server::{
    CredentialDecision, CredentialValidationError, CredentialValidator, Credentials, DesktopSize, DisplayUpdate,
    EgfxServerMessage, GfxDvcBridge, GfxServerFactory, GfxServerHandle, KeyboardEvent, MouseEvent, RdpServer,
    RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler, ServerEvent, ServerEventSender, TlsIdentityCtx,
};
use ironrdp_pdu::gcc::{Monitor, MonitorFlags};
use ironrdp_svc::ChannelFlags;
use core::num::{NonZeroU16, NonZeroUsize};
use ironrdp_server::PixelFormat;
use std::collections::HashMap;
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
use x11rb::protocol::xproto::{self, ConnectionExt as _, ImageFormat};
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
    /// Force the 1:1 window for every client smaller than the screen; by
    /// default only clients that would have to shrink it below 45 % get it.
    viewport: bool,
}

fn parse_args() -> Opts {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let mut o = Opts {
        bind: "0.0.0.0:3390".into(), fps: 30, bitrate: "12M".into(), cpu: false,
        user: String::new(), pass: String::new(), certdir: PathBuf::from(format!("{}/.config/rdesk", home)),
        viewport: false,
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
            "--viewport" => o.viewport = true,
            _ => {
                eprintln!("usage: rdesk-rdp [--bind 0.0.0.0:3390] [--fps 30] [--bitrate 12M] [--cpu] [--certdir ~/.config/rdesk] [--pass STATIC] [--viewport]");
                eprintln!("--viewport: every smaller client gets the 1:1 window onto the screen (default: only when it would shrink below 45 %, i.e. phones)");
                eprintln!("login: Linux user running the server + system password (mstsc must have the credentials saved),");
                eprintln!("       or --pass PASSWORD for NLA with a fixed password (mstsc prompts each time)");
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
    /// Desktop size negotiated with the current client (its own size, see `Fit`).
    out: Mutex<(u16, u16)>,
    /// --viewport: force the window for every smaller client (default: below 45 % scale).
    viewport: bool,
    /// Top-left screen coordinate of that window.
    view: Mutex<(u16, u16)>,
}

impl Ctx {
    fn fit(&self) -> Fit {
        let (ow, oh) = *self.out.lock().unwrap();
        let scale = (ow as f64 / self.w as f64).min(oh as f64 / self.h as f64);
        // A phone held upright would shrink the screen to ~0.3; a laptop or a
        // phone on its side sits above 0.5 and reads fine scaled.
        if scale < 1.0 && (self.viewport || scale < 0.45) {
            let (vx, vy) = *self.view.lock().unwrap();
            return Fit::window(self.w, self.h, ow, oh, vx, vy);
        }
        Fit::new(self.w, self.h, ow, oh)
    }
    /// Move the viewport so that (vx, vy) is its top-left, clamped to the screen.
    fn pan_to(&self, vx: i32, vy: i32) {
        let f = self.fit();
        let (mx, my) = (self.w.saturating_sub(f.fw) as i32, self.h.saturating_sub(f.fh) as i32);
        *self.view.lock().unwrap() = (vx.clamp(0, mx) as u16, vy.clamp(0, my) as u16);
    }
}

/// Where the screen lands inside the client's desktop. mstsc keeps its own
/// desktop size and drops a session whose surface is bigger than that, so the
/// session is negotiated at the client's size and the screen is scaled to fit,
/// letterboxed and centred. Identity when the sizes match.
#[derive(Clone, Copy, Debug)]
struct Fit {
    /// Client desktop (= surface) size.
    ow: u16, oh: u16,
    /// Screen rectangle inside it (scaled, or 1:1 in window mode), even-aligned for 4:2:0.
    fx: u16, fy: u16, fw: u16, fh: u16,
    /// Window mode (--viewport): the client shows the fw x fh screen region at (vx, vy) 1:1.
    win: Option<(u16, u16)>,
}

impl Fit {
    fn new(w: u16, h: u16, ow: u16, oh: u16) -> Fit {
        if (w, h) == (ow, oh) {
            return Fit { ow, oh, fx: 0, fy: 0, fw: w, fh: h, win: None };
        }
        let s = (ow as f64 / w as f64).min(oh as f64 / h as f64);
        let fw = ((w as f64 * s) as u16).max(2) & !1;
        let fh = ((h as f64 * s) as u16).max(2) & !1;
        Fit { ow, oh, fx: (ow - fw) / 2 & !1, fy: (oh - fh) / 2 & !1, fw, fh, win: None }
    }
    /// A client-sized window onto the screen at (vx, vy); black where the client is larger.
    fn window(w: u16, h: u16, ow: u16, oh: u16, vx: u16, vy: u16) -> Fit {
        let (fw, fh) = (ow.min(w), oh.min(h));
        Fit { ow, oh, fx: 0, fy: 0, fw, fh, win: Some((vx.min(w - fw), vy.min(h - fh))) }
    }
    fn identity(&self) -> bool {
        self.win.is_none() && self.fx == 0 && self.fy == 0 && (self.fw, self.fh) == (self.ow, self.oh)
    }
    /// ffmpeg filter producing the client-sized picture, or None when nothing to do.
    /// Window mode crops in `bitmap` instead, so the encoder sees client-sized frames.
    fn vf(&self) -> Option<String> {
        if self.identity() || self.win.is_some() { return None; }
        Some(format!("scale={}:{}:flags=fast_bilinear,pad={}:{}:{}:{}", self.fw, self.fh, self.ow, self.oh, self.fx, self.fy))
    }
    /// Client desktop coordinates -> screen coordinates.
    fn to_screen(&self, x: u16, y: u16, w: u16, h: u16) -> (i16, i16) {
        if let Some((vx, vy)) = self.win {
            return ((vx + x.min(self.fw - 1)).min(w - 1) as i16, (vy + y.min(self.fh - 1)).min(h - 1) as i16);
        }
        if self.identity() { return (x as i16, y as i16); }
        let sx = (x.saturating_sub(self.fx).min(self.fw - 1) as u32 * w as u32 / self.fw as u32) as i16;
        let sy = (y.saturating_sub(self.fy).min(self.fh - 1) as u32 * h as u32 / self.fh as u32) as i16;
        (sx, sy)
    }
    /// The client-sized BGRX frame for a screen frame: a copy, a 1:1 window, or
    /// (legacy path only, the encoder scales otherwise) a nearest-neighbour fit.
    fn bitmap(&self, src: &[u8], w: u16, h: u16) -> Vec<u8> {
        if self.identity() { return src.to_vec(); }
        let (ow, fw, fh) = (self.ow as usize, self.fw as usize, self.fh as usize);
        let (w, h) = (w as usize, h as usize);
        let mut dst = vec![0u8; ow * self.oh as usize * 4];
        if let Some((vx, vy)) = self.win {
            for y in 0..fh {
                let si = ((vy as usize + y) * w + vx as usize) * 4;
                dst[y * ow * 4..y * ow * 4 + fw * 4].copy_from_slice(&src[si..si + fw * 4]);
            }
            return dst;
        }
        for y in 0..fh {
            let srow = (y * h / fh) * w * 4;
            let drow = ((self.fy as usize + y) * ow + self.fx as usize) * 4;
            for x in 0..fw {
                let si = srow + (x * w / fw) * 4;
                dst[drow + x * 4..drow + x * 4 + 4].copy_from_slice(&src[si..si + 4]);
            }
        }
        dst
    }
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

/// TLS-mode login: the Linux user running the server with their system password,
/// checked by PAM's own setgid helper (unix_chkpwd only verifies the calling
/// user, which is exactly the scope we want).
struct Login {
    user: String,
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
        if c.password.is_empty() {
            warn!(user = %c.username, "client sent no password: in mstsc tick 'Allow me to save credentials' and save them, or run with --pass");
            return Ok(CredentialDecision::Reject);
        }
        let ok = if user != self.user.to_lowercase() {
            false
        } else {
            let (u, p) = (self.user.clone(), c.password.clone());
            tokio::task::spawn_blocking(move || unix_chkpwd(&u, &p)).await.unwrap_or(false)
        };
        info!(user = %c.username, domain = ?c.domain, ok, "login");
        Ok(if ok { CredentialDecision::Accept } else { CredentialDecision::Reject })
    }
}

// ---------------------------------------------------------------- input

struct Input {
    ctx: Arc<Ctx>,
    /// keysym -> (keycode, needs Shift), built from the X keymap on first use.
    keysyms: Option<HashMap<u32, (u8, bool)>>,
    /// A keycode with no keysyms, temporarily bound to characters the layout
    /// lacks (emoji etc.), the way xdotool types them.
    spare: Option<(u8, u32)>,
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
    /// Unicode keyboard events (on-screen keyboards, mstsc's Unicode input):
    /// type the character through the server's own layout, Shift if needed;
    /// characters the layout lacks are bound to a spare keycode on the fly.
    fn unicode(&mut self, u: u16, pressed: bool) {
        let ks = match u as u32 { c @ 0x20..=0xff => c, c => 0x0100_0000 | c };
        if self.keysyms.is_none() { self.keysyms = Some(self.build_keysyms()); }
        let kc = match self.keysyms.as_ref().unwrap().get(&ks) {
            Some(&(kc, shift)) => {
                if shift { self.fake(if pressed { xproto::KEY_PRESS_EVENT } else { xproto::KEY_RELEASE_EVENT }, 50, 0, 0); }
                kc
            }
            None => match self.bind_spare(ks) {
                Some(kc) => kc,
                None => { warn!(u, "no keycode for unicode key"); return; }
            },
        };
        self.fake(if pressed { xproto::KEY_PRESS_EVENT } else { xproto::KEY_RELEASE_EVENT }, kc, 0, 0);
    }
    fn build_keysyms(&mut self) -> HashMap<u32, (u8, bool)> {
        let conn = &self.ctx.conn;
        let (min, max) = (conn.setup().min_keycode, conn.setup().max_keycode);
        let mut m = HashMap::new();
        let Ok(r) = conn.get_keyboard_mapping(min, max - min + 1).and_then(|c| Ok(c.reply())) else { return m };
        let Ok(r) = r else { return m };
        let per = r.keysyms_per_keycode as usize;
        // Column 0 = plain, 1 = Shift; prefer plain, remember the first free keycode.
        for (col, shift) in [(0usize, false), (1, true)] {
            for (i, kc) in (min..=max).enumerate() {
                let ks = r.keysyms[i * per + col];
                if ks != 0 { m.entry(ks).or_insert((kc, shift)); }
            }
        }
        if self.spare.is_none() {
            let free = (min..=max).enumerate().find(|(i, _)| r.keysyms[i * per..(i + 1) * per].iter().all(|&k| k == 0));
            self.spare = free.map(|(_, kc)| (kc, 0));
        }
        m
    }
    fn bind_spare(&mut self, ks: u32) -> Option<u8> {
        let (kc, bound) = self.spare?;
        if bound != ks {
            let conn = &self.ctx.conn;
            conn.change_keyboard_mapping(1, kc, 2, &[ks, ks]).ok()?.check().ok()?;
            let _ = conn.flush();
            self.spare = Some((kc, ks));
            // Give clients a moment to pick up the MappingNotify.
            thread::sleep(Duration::from_millis(20));
        }
        Some(kc)
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
            KeyboardEvent::UnicodePressed(u) => self.unicode(u, true),
            KeyboardEvent::UnicodeReleased(u) => self.unicode(u, false),
            KeyboardEvent::Synchronize(_) => {}
        }
    }
    fn mouse(&mut self, e: MouseEvent) {
        use MouseEvent::*;
        match e {
            Move { x, y } => {
                let f = self.ctx.fit();
                if let Some((vx, vy)) = f.win {
                    // Pushing the pointer into a 48 px border pans the window 32 px per event.
                    const M: u16 = 48; const S: i32 = 32;
                    let dx = if x < M { -S } else if x + M > f.fw { S } else { 0 };
                    let dy = if y < M { -S } else if y + M > f.fh { S } else { 0 };
                    if dx != 0 || dy != 0 { self.ctx.pan_to(vx as i32 + dx, vy as i32 + dy); }
                }
                let (sx, sy) = self.ctx.fit().to_screen(x, y, self.ctx.w, self.ctx.h);
                self.fake(xproto::MOTION_NOTIFY_EVENT, 0, sx, sy)
            }
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
        let fit = self.ctx.fit();
        let data = tokio::task::spawn_blocking(move || grab(&ctx).map(|()| fit.bitmap(ctx.shm.buf(), ctx.w, ctx.h))).await??;
        Ok(Some(DisplayUpdate::Bitmap(ironrdp_server::BitmapUpdate {
            x: 0,
            y: 0,
            width: NonZeroU16::new(fit.ow).unwrap(),
            height: NonZeroU16::new(fit.oh).unwrap(),
            format: PixelFormat::BgrX32,
            data: data.into(),
            stride: NonZeroUsize::new(fit.ow as usize * 4).unwrap(),
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
        let (w, h) = *self.ctx.out.lock().unwrap();
        DesktopSize { width: w, height: h }
    }
    /// Adopt the client's desktop size (with_honor_client_desktop_size); the
    /// screen is scaled into it, see `Fit`.
    async fn request_initial_size(&mut self, client: DesktopSize) -> DesktopSize {
        let (w, h) = (client.width & !1, client.height & !1);
        *self.ctx.out.lock().unwrap() = (w, h);
        let fit = self.ctx.fit();
        if let Some(_) = fit.win {
            // Start with the window centred on the pointer.
            let p = self.ctx.conn.query_pointer(self.ctx.root).ok().and_then(|c| c.reply().ok());
            let (px, py) = p.map(|p| (p.root_x as i32, p.root_y as i32)).unwrap_or((self.ctx.w as i32 / 2, self.ctx.h as i32 / 2));
            self.ctx.pan_to(px - fit.fw as i32 / 2, py - fit.fh as i32 / 2);
            let (vx, vy) = *self.ctx.view.lock().unwrap();
            info!("client desktop {}x{}, screen {}x{} shown as a {}x{} window at {},{}", w, h, self.ctx.w, self.ctx.h, fit.fw, fit.fh, vx, vy);
        } else {
            info!("client desktop {}x{}, screen {}x{} shown as {}x{} at {},{}", w, h, self.ctx.w, self.ctx.h, fit.fw, fit.fh, fit.fx, fit.fy);
        }
        DesktopSize { width: w, height: h }
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
        Box::new(Gfx { ctx: self.ctx.clone(), ev: self.ev.clone(), handle: Default::default(), stop: Default::default(), avc_off: false })
    }
    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        let slot: Arc<Mutex<Option<GfxServerHandle>>> = Default::default();
        let handler = Gfx { ctx: self.ctx.clone(), ev: self.ev.clone(), handle: slot.clone(), stop: Default::default(), avc_off: false };
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
    /// The client set AVC_DISABLED (iOS/macOS clients do). ironrdp intersects
    /// flags with AND, which drops a negative flag unless we set it too; a
    /// CapsConfirm that re-enables AVC makes those clients close the channel.
    avc_off: bool,
}

impl GraphicsPipelineHandler for Gfx {
    fn capabilities_advertise(&mut self, pdu: &CapabilitiesAdvertisePdu) {
        info!(n = pdu.0.len(), caps = ?pdu.0, "client gfx caps");
        self.avc_off = pdu.0.iter().filter_map(|raw| raw.parsed().ok().flatten()).any(|c| match c {
            CapabilitySet::V10 { flags } | CapabilitySet::V10_2 { flags } => flags.contains(CapabilitiesV10Flags::AVC_DISABLED),
            CapabilitySet::V10_3 { flags } => flags.contains(CapabilitiesV103Flags::AVC_DISABLED),
            CapabilitySet::V10_4 { flags } | CapabilitySet::V10_5 { flags } | CapabilitySet::V10_6 { flags }
            | CapabilitySet::V10_6Err { flags } => flags.contains(CapabilitiesV104Flags::AVC_DISABLED),
            CapabilitySet::V10_7 { flags } => flags.contains(CapabilitiesV107Flags::AVC_DISABLED),
            _ => false,
        });
        if self.avc_off { info!("client has AVC disabled"); }
    }
    /// Full version ladder, highest first, so we confirm the client's newest
    /// version the way xrdp/FreeRDP do. The crate default only lists 10.7/10/8.1/8,
    /// which makes a Windows client without 10.7 land on plain V10.
    fn preferred_capabilities(&self) -> Vec<CapabilitySet> {
        let off = self.avc_off;
        let v10 = |f: CapabilitiesV10Flags| if off { f | CapabilitiesV10Flags::AVC_DISABLED } else { f };
        let v103 = |f: CapabilitiesV103Flags| if off { f | CapabilitiesV103Flags::AVC_DISABLED } else { f };
        let v104 = |f: CapabilitiesV104Flags| if off { f | CapabilitiesV104Flags::AVC_DISABLED } else { f };
        let v107 = |f: CapabilitiesV107Flags| if off { f | CapabilitiesV107Flags::AVC_DISABLED } else { f };
        let v81 = if off { CapabilitiesV81Flags::SMALL_CACHE } else { CapabilitiesV81Flags::AVC420_ENABLED | CapabilitiesV81Flags::SMALL_CACHE };
        // V10.1 has no flags field, so AVC cannot be disabled in it: skip it for such clients.
        let mut caps = vec![
            CapabilitySet::V10_7 { flags: v107(CapabilitiesV107Flags::SMALL_CACHE) },
            CapabilitySet::V10_6Err { flags: v104(CapabilitiesV104Flags::SMALL_CACHE) },
            CapabilitySet::V10_6 { flags: v104(CapabilitiesV104Flags::SMALL_CACHE) },
            CapabilitySet::V10_5 { flags: v104(CapabilitiesV104Flags::SMALL_CACHE) },
            CapabilitySet::V10_4 { flags: v104(CapabilitiesV104Flags::SMALL_CACHE) },
            CapabilitySet::V10_3 { flags: v103(CapabilitiesV103Flags::empty()) },
            CapabilitySet::V10_2 { flags: v10(CapabilitiesV10Flags::SMALL_CACHE) },
            CapabilitySet::V10_1,
            CapabilitySet::V10 { flags: v10(CapabilitiesV10Flags::SMALL_CACHE) },
            CapabilitySet::V8_1 { flags: v81 },
            CapabilitySet::V8 { flags: CapabilitiesV8Flags::SMALL_CACHE },
        ];
        if off { caps.retain(|c| !matches!(c, CapabilitySet::V10_1)); }
        caps
    }
    fn on_frame_ack(&mut self, frame_id: u32, queue_depth: u32, total_frames_decoded: u32) {
        info!(frame_id, queue_depth, total_frames_decoded, "frame ack");
    }
    fn on_qoe_metrics(&mut self, m: ironrdp_egfx::server::QoeMetrics) {
        info!(?m, "qoe");
    }
    fn on_ready(&mut self, negotiated: &CapabilitySet) {
        info!(?negotiated, "gfx ready");
        let Some(handle) = self.handle.lock().unwrap().clone() else { return };
        // mstsc re-advertises caps when it resets the channel; end the old stream first.
        self.stop.store(true, Ordering::Relaxed);
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
    if std::env::var_os("RDESK_TRACE").is_some() {
        let desc: Vec<String> = msgs.iter().map(|m| format!("{}:{}", m.name(), m.size())).collect();
        info!(pdus = ?desc, "gfx flush");
    }
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
    let fit = ctx.fit();
    let (sw, sh) = (fit.ow, fit.oh);
    let surface = {
        let mut g = handle.lock().unwrap();
        if !g.supports_avc420() {
            info!("client has GFX but no AVC420, using legacy bitmap updates");
            *ctx.mode.lock().unwrap() = Mode::Legacy;
            return Ok(());
        }
        // ResetGraphics with a real monitor definition; the bare one create_surface
        // would send has none, and mstsc is stricter than FreeRDP about that.
        g.resize_with_monitors(sw, sh, vec![Monitor {
            left: 0, top: 0, right: sw as i32 - 1, bottom: sh as i32 - 1, flags: MonitorFlags::PRIMARY,
        }]);
        let sid = g.create_surface(sw, sh).context("create_surface")?;
        g.map_surface_to_output(sid, 0, 0);
        flush(&mut g, &ev)?;
        *ctx.mode.lock().unwrap() = Mode::Avc;
        sid
    };
    info!(surface, "streaming {}x{} as {}x{}", w, h, sw, sh);

    // RDESK_TEST=uncompressed: skip H.264 entirely and push a small raw bitmap
    // every 500 ms, to tell GFX plumbing problems apart from codec problems.
    if std::env::var("RDESK_TEST").as_deref() == Ok("uncompressed") {
        let t0 = Instant::now();
        let mut n = 0u32;
        while !stop.load(Ordering::Relaxed) {
            let shade = (n * 16 % 256) as u8;
            let px: Vec<u8> = (0..256 * 256).flat_map(|_| [shade, 0, 255 - shade, 0xff]).collect();
            {
                let mut g = handle.lock().unwrap();
                if !g.is_ready() { anyhow::bail!("gfx channel closed"); }
                let id = g.send_uncompressed_frame(surface, &px, 256, 256, t0.elapsed().as_millis() as u32);
                info!(?id, "test frame");
                flush(&mut g, &ev)?;
            }
            n += 1;
            thread::sleep(Duration::from_millis(500));
        }
        return Ok(());
    }

    let win = fit.win.is_some();
    let (ew, eh) = if win { (sw, sh) } else { (w, h) };
    let mut enc = spawn_encoder(ew, eh, ctx.fps, &ctx.bitrate, ctx.nvenc, "avi", fit.vf().as_deref());
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
                    // Window mode: crop per frame, the window moves while panning.
                    let r = if win { enc_in.write_all(&ctx.fit().bitmap(ctx.shm.buf(), w, h)) } else { enc_in.write_all(ctx.shm.buf()) };
                    if r.is_err() { break; }
                }
                let now = Instant::now();
                if next > now { thread::sleep(next - now); } else { next = now; }
            }
            stop.store(true, Ordering::Relaxed);
        })
    };

    // This thread: AVI chunks -> AVC420 frames.
    let t0 = Instant::now();
    // ironrdp-egfx 0.3 takes these bounds as inclusive and derives the
    // WireToSurface destRect as right+1/bottom+1; with right=sw the dest rect
    // overshoots the surface by a pixel and mstsc resets the pipeline
    // (re-advertises caps) on the first frame. The metablock rects it writes
    // end up one short of the spec's exclusive form, which the spec says
    // clients must not use for decoding anyway.
    let region = Avc420Region { left: 0, top: 0, right: sw - 1, bottom: sh - 1, quantization_parameter: 23, quality: 100 };
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
    let ctx = Arc::new(Ctx { conn, root, w, h, shm, fps: o.fps, bitrate: o.bitrate.clone(), nvenc, mode: Mutex::new(Mode::Unknown), out: Mutex::new((w, h)),
                             viewport: o.viewport, view: Mutex::new((0, 0)) });

    let (cert, key) = ensure_cert(&o.certdir)?;
    let identity = TlsIdentityCtx::init_from_paths(&cert, &key).context("TLS identity")?;
    let acceptor = identity.make_acceptor().context("TLS acceptor")?;

    let ev: EvSender = Default::default();
    let addr: std::net::SocketAddr = o.bind.parse().context("--bind")?;
    // Two login modes:
    //  - system password: TLS without NLA, like xrdp. mstsc only forwards a password
    //    it has *saved* ("Allow me to save credentials"); it never sends a typed one
    //    to a non-NLA server. We check it with unix_chkpwd.
    //  - --pass: NLA (CredSSP/NTLM) with a fixed password. NTLM needs the password on
    //    the server, which is why the system password cannot be used here.
    let builder = RdpServer::builder().with_addr(addr);
    let builder = if o.pass.is_empty() {
        builder.with_tls(acceptor)
    } else {
        builder.with_hybrid(acceptor, identity.pub_key.clone())
    };
    let mut server = builder
        .with_input_handler(Input { ctx: ctx.clone(), keysyms: None, spare: None })
        .with_display_handler(Display { ctx: ctx.clone() })
        .with_gfx_factory(Some(Box::new(GfxFactory { ctx: ctx.clone(), ev })))
        .with_honor_client_desktop_size(true)
        .with_credential_validator(Some(Arc::new(Login { user: o.user.clone() })))
        .build();
    if !o.pass.is_empty() {
        server.set_credentials(Some(Credentials { username: o.user.clone(), password: o.pass.clone(), domain: None }));
    }

    info!("rdesk-rdp: {}x{}{} @{}fps {} encoder={} login={} ({}) listening on {}",
          w, h, if o.viewport { " (window for every smaller client)" } else { "" }, o.fps, o.bitrate, if nvenc { "h264_nvenc" } else { "libx264" }, o.user,
          if o.pass.is_empty() { "TLS, system password from saved mstsc credentials" } else { "NLA, --pass" }, o.bind);
    // Own accept loop instead of server.run(): IronRDP serves one client at a
    // time, so a peer that vanishes mid-handshake (NAT dropping the flow) would
    // otherwise hold the loop for the kernel's ~15 min of retransmits while new
    // clients queue up unanswered. TCP_USER_TIMEOUT on the listener is inherited
    // by accepted sockets and ends such a connection after 20 s of no ACKs.
    let listener = std::net::TcpListener::bind(addr).with_context(|| format!("bind {}", addr))?;
    {
        use std::os::fd::AsRawFd;
        let ms: libc::c_uint = 20_000;
        let r = unsafe {
            libc::setsockopt(listener.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT,
                             &ms as *const _ as *const libc::c_void, std::mem::size_of_val(&ms) as libc::socklen_t)
        };
        if r != 0 { warn!("TCP_USER_TIMEOUT: {}", std::io::Error::last_os_error()); }
    }
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    loop {
        let (stream, peer) = listener.accept().await?;
        info!(%peer, "connection");
        let t = Instant::now();
        match server.run_connection(stream).await {
            Ok(()) => info!(%peer, "disconnected after {:.0?}", t.elapsed()),
            Err(e) => error!(%peer, "connection failed after {:.0?}: {:#}", t.elapsed(), e),
        }
    }
}

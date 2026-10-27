//! rdesk-rdp: a native RDP server for the local X11 desktop, so plain mstsc
//! can connect. Built on IronRDP; frames go out as H.264 (AVC420) over the
//! graphics pipeline, encoded by NVENC through ffmpeg. Input comes back as
//! scancodes and is injected with XTest, so the server's keyboard layout applies.

mod x11cap;
mod nthash;
mod session;
mod portrait;
mod clip;

use anyhow::Context as _;
use ironrdp_egfx::pdu::{
    Avc420Region, CapabilitiesAdvertisePdu, CapabilitiesV103Flags, CapabilitiesV104Flags, CapabilitiesV107Flags,
    CapabilitiesV10Flags, CapabilitiesV81Flags, CapabilitiesV8Flags, CapabilitySet, Codec1Type, EndFramePdu, GfxPdu,
    PixelFormat as GfxPixelFormat, StartFramePdu, Timestamp, WireToSurface1Pdu,
};
use ironrdp_graphics::rdp6::{BgrAChannels, BitmapStreamEncoder};
use ironrdp_pdu::geometry::ExclusiveRectangle;
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_server::{
    CredentialDecision, CredentialValidationError, CredentialValidator, Credentials, DesktopSize, DisplayUpdate, RGBAPointer,
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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
    /// NT hash of the Linux password (hex, from ~/.config/rdesk/nthash): NLA
    /// with the system password, mstsc prompts like it does for Windows.
    nthash: Option<String>,
    certdir: PathBuf,
    /// Force the 1:1 window for every client smaller than the screen; by
    /// default only clients that would have to shrink it below 45 % get it.
    viewport: bool,
    cold_boot: bool,
    phone_res: bool,
}

fn parse_args() -> Opts {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let mut o = Opts {
        bind: "0.0.0.0:3390".into(), fps: 30, bitrate: "12M".into(), cpu: false,
        user: String::new(), pass: String::new(), nthash: None, certdir: PathBuf::from(format!("{}/.config/rdesk", home)),
        viewport: false, cold_boot: false, phone_res: false,
    };
    let mut pass_file: Option<PathBuf> = None;
    let mut set_password = false;
    let mut a = std::env::args().skip(1);
    while let Some(k) = a.next() {
        match k.as_str() {
            "--bind" => o.bind = a.next().expect("--bind ADDR:PORT"),
            "--fps" => o.fps = a.next().expect("--fps N").parse().expect("fps"),
            "--bitrate" => o.bitrate = a.next().expect("--bitrate 12M"),
            "--cpu" => o.cpu = true,
            "--pass" => o.pass = a.next().expect("--pass PASSWORD"),
            "--pass-file" => pass_file = Some(PathBuf::from(a.next().expect("--pass-file PATH"))),
            "--certdir" => o.certdir = a.next().expect("--certdir DIR").into(),
            "--viewport" => o.viewport = true,
            "--cold-boot" => o.cold_boot = true,
            "--phone-res" => o.phone_res = true,
            "--set-password" => set_password = true,
            _ => {
                eprintln!("usage: rdesk-rdp [--bind 0.0.0.0:3390] [--fps 30] [--bitrate 12M] [--cpu] [--certdir ~/.config/rdesk] [--pass STATIC | --pass-file PATH] [--viewport]");
                eprintln!("       --pass-file defaults to ~/.config/rdesk/password when that file exists (mode 600); NLA, mstsc prompts each time");
                eprintln!("--viewport: every smaller client gets the 1:1 window onto the screen (default: only when it would shrink below 45 %, i.e. phones)");
                eprintln!("--cold-boot: log in through the rdesk LightDM bridge and set the new desktop to 1920x1080 (TLS/system password only)");
                eprintln!("--phone-res: temporarily resize the shared desktop for portrait clients; restore it on disconnect");
                eprintln!("--set-password: store the NT hash of your Linux password in ~/.config/rdesk/nthash now");
                eprintln!("login: Linux user running the server + system password. NLA (mstsc prompts) once ~/.config/rdesk/nthash");
                eprintln!("       exists: the rdesk-nthash PAM hook and successful logins keep it current; until then TLS, saved credentials;");
                eprintln!("       or --pass PASSWORD for NLA with a fixed password (mstsc prompts each time)");
                std::process::exit(2);
            }
        }
    }
    o.user = std::env::var("USER").unwrap_or_default();
    if o.user.is_empty() { eprintln!("USER not set"); std::process::exit(2); }
    let hash_file = o.certdir.join("nthash");
    if set_password {
        match store_nthash(&o.user, &hash_file) {
            Ok(()) => { println!("wrote {}; a running rdesk-rdp switches to NLA once idle", hash_file.display()); std::process::exit(0) }
            Err(e) => { eprintln!("--set-password: {:#}", e); std::process::exit(1) }
        }
    }
    // A dedicated rdesk password in a file gives the Windows experience: NLA,
    // mstsc asks every time, nothing has to be saved on the client. (NTLM needs
    // the password server-side, so this is not the Linux password.)
    let default_file = o.certdir.join("password");
    if o.pass.is_empty() {
        if let Some(f) = pass_file.or_else(|| default_file.exists().then_some(default_file)) {
            match std::fs::read_to_string(&f) {
                Ok(p) => {
                    o.pass = p.trim_end_matches(['\r', '\n']).to_string();
                    if o.pass.is_empty() { eprintln!("{} is empty", f.display()); std::process::exit(2); }
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(m) = std::fs::metadata(&f) {
                        if m.permissions().mode() & 0o077 != 0 { eprintln!("warning: {} is readable by others (chmod 600)", f.display()); }
                    }
                }
                Err(e) => { eprintln!("{}: {}", f.display(), e); std::process::exit(2); }
            }
        }
    }
    if o.pass.is_empty() && hash_file.exists() {
        o.nthash = nthash::read(&hash_file);
        if o.nthash.is_none() { eprintln!("{}: unreadable or not 32 hex digits, ignored", hash_file.display()); }
    }
    if o.cold_boot && !o.pass.is_empty() {
        eprintln!("--cold-boot requires the Linux password via TLS; remove --pass/--pass-file and the default password file");
        std::process::exit(2);
    }
    o
}

/// Everything the per-connection pieces need about the machine.
/// A connection that is still handshaking, or that stopped acking frames and
/// sending input, gives way to a new one; a live, logged-in one never does
/// (internet scanners must not be able to kick a session).
#[derive(Clone, Copy, Debug)]
enum Activity {
    Handshake,
    Authenticating,
    /// Logged in; last time the client acked a frame or sent input.
    Active(Instant),
}

/// How long a logged-in client may be silent before a new connection replaces it.
const STALE: Duration = Duration::from_secs(10);

struct Ctx {
    conn: Arc<RustConnection>,
    root: xproto::Window,
    capture: Mutex<Capture>,
    fps: u32,
    bitrate: String,
    /// Cleared when NVENC stops working (driver updated under a running X).
    nvenc: AtomicBool,
    /// How frames reach the current client; decided once the GFX channel negotiates.
    mode: Mutex<Mode>,
    /// Desktop size negotiated with the current client (its own size, see `Fit`).
    out: Mutex<(u16, u16)>,
    /// --viewport: force the window for every smaller client (default: below 45 % scale).
    viewport: bool,
    /// Top-left screen coordinate of that window.
    view: Mutex<(u16, u16)>,
    /// Last frame id the client acknowledged (planar path paces on this),
    /// u32::MAX = none yet; `acked_suspended` once it said it will stop acking.
    acked: AtomicU32,
    acked_suspended: AtomicBool,
    phone_res: bool,
    phone_desktop: Mutex<Option<portrait::PhoneDesktop>>,
    /// The client draws the pointer from shapes we send (no trailing cursor);
    /// RDESK_CURSOR=video bakes it into the frames instead.
    client_cursor: bool,
    /// Where the current connection is; decides whether a newer one may replace it.
    activity: Mutex<Activity>,
    streams: Mutex<Vec<(Arc<AtomicBool>, thread::JoinHandle<()>)>>,
    /// Set by a greeter login: the desktop is fresh, size it to the client in
    /// request_initial_size (the client's size is not known during login).
    fresh_login: AtomicBool,
}

impl Ctx {
    fn end_connection(&self) {
        // Stop every generation, including ones replaced by GFX renegotiation,
        // before restoring the display or allowing a new client to start.
        let streams = std::mem::take(&mut *self.streams.lock().unwrap());
        for (stop, _) in &streams { stop.store(true, Ordering::Relaxed); }
        for (_, task) in streams { let _ = task.join(); }
        let saved = self.phone_desktop.lock().unwrap().take();
        let _capture = self.capture.lock().unwrap();
        drop(saved); // restores through the already authenticated X connection
    }
    fn set_activity(&self, a: Activity) {
        *self.activity.lock().unwrap() = a;
    }
    /// Frame acks and input only arrive after login (also --pass, which has no validator).
    fn seen(&self) {
        self.set_activity(Activity::Active(Instant::now()));
    }
    /// Whether a new connection should take over from the current one.
    fn replaceable(&self) -> bool {
        match *self.activity.lock().unwrap() {
            Activity::Handshake => true,
            Activity::Authenticating => false,
            Activity::Active(t) => t.elapsed() > STALE && !self.acked_suspended.load(Ordering::Relaxed),
        }
    }
    fn dimensions(&self) -> (u16, u16) {
        let c = self.capture.lock().unwrap();
        (c.w, c.h)
    }
    fn fit(&self) -> Fit {
        let (w, h) = self.dimensions();
        self.fit_for(w, h)
    }
    fn fit_for(&self, w: u16, h: u16) -> Fit {
        let (ow, oh) = *self.out.lock().unwrap();
        let scale = (ow as f64 / w as f64).min(oh as f64 / h as f64);
        // A phone held upright would shrink the screen to ~0.3; a laptop or a
        // phone on its side sits above 0.5 and reads fine scaled.
        if scale < 1.0 && (self.viewport || scale < 0.45) {
            let (vx, vy) = *self.view.lock().unwrap();
            return Fit::window(w, h, ow, oh, vx, vy);
        }
        Fit::new(w, h, ow, oh)
    }
    /// Move the viewport so that (vx, vy) is its top-left, clamped to the screen.
    fn pan_to(&self, vx: i32, vy: i32) {
        let f = self.fit();
        let (w, h) = self.dimensions();
        let (mx, my) = (w.saturating_sub(f.fw) as i32, h.saturating_sub(f.fh) as i32);
        *self.view.lock().unwrap() = (vx.clamp(0, mx) as u16, vy.clamp(0, my) as u16);
    }
}

/// Where the screen lands inside the client's desktop. mstsc keeps its own
/// desktop size and drops a session whose surface is bigger than that, so the
/// session is negotiated at the client's size and the screen is scaled to fit,
/// letterboxed and centred. Identity when the sizes match.
#[derive(Clone, Copy, Debug)]
struct Fit {
    /// A full output rectangle alone does not imply 1:1 pixels: a 720p source
    /// also fills 1080p. Only skip scaling when source and output sizes match.
    native: bool,
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
            return Fit { native: true, ow, oh, fx: 0, fy: 0, fw: w, fh: h, win: None };
        }
        let s = (ow as f64 / w as f64).min(oh as f64 / h as f64);
        let fw = ((w as f64 * s) as u16).max(2) & !1;
        let fh = ((h as f64 * s) as u16).max(2) & !1;
        Fit { native: false, ow, oh, fx: (ow - fw) / 2 & !1, fy: (oh - fh) / 2 & !1, fw, fh, win: None }
    }
    /// A client-sized window onto the screen at (vx, vy); black where the client is larger.
    fn window(w: u16, h: u16, ow: u16, oh: u16, vx: u16, vy: u16) -> Fit {
        let (fw, fh) = (ow.min(w), oh.min(h));
        Fit { native: false, ow, oh, fx: 0, fy: 0, fw, fh, win: Some((vx.min(w - fw), vy.min(h - fh))) }
    }
    fn identity(&self) -> bool {
        self.native
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

/// System-password login (TLS, or the password delegated after NLA): the Linux
/// user running the server, checked by PAM's own setgid helper (unix_chkpwd only
/// verifies the calling user, which is exactly the scope we want).
struct Login {
    user: String,
    cold_boot: bool,
    hash_file: PathBuf,
    ctx: Arc<Ctx>,
}

/// Find a vanished client within ~25 s even when nothing is in flight
/// (TCP_USER_TIMEOUT only covers unacked data).
fn keepalive(stream: &tokio::net::TcpStream) {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    for (level, opt, val) in [(libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1), (libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 10),
                              (libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 5), (libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 3)] {
        let v: libc::c_int = val;
        let r = unsafe { libc::setsockopt(fd, level, opt, &v as *const _ as *const libc::c_void, std::mem::size_of_val(&v) as libc::socklen_t) };
        if r != 0 { warn!("keepalive option {}: {}", opt, std::io::Error::last_os_error()); }
    }
}

/// Asks for the Linux password, checks it, and stores its NT hash.
fn store_nthash(user: &str, path: &std::path::Path) -> anyhow::Result<()> {
    let pass = read_password(&format!("Linux password for {}: ", user))?;
    anyhow::ensure!(nthash::check(user, &pass), "wrong password for {} (run this as {})", user, user);
    nthash::store(path, &pass)?;
    Ok(())
}

fn read_password(prompt: &str) -> anyhow::Result<String> {
    eprint!("{}", prompt);
    let fd = libc::STDIN_FILENO;
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty = unsafe { libc::tcgetattr(fd, &mut old) } == 0;
    if tty {
        let mut t = old;
        t.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) };
    }
    let mut line = String::new();
    let r = std::io::stdin().read_line(&mut line);
    if tty { unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) }; eprintln!(); }
    r?;
    let pass = line.trim_end_matches(['\r', '\n']).to_string();
    anyhow::ensure!(!pass.is_empty(), "empty password");
    Ok(pass)
}

#[async_trait::async_trait]
impl CredentialValidator for Login {
    async fn validate(&self, c: &Credentials) -> Result<CredentialDecision, CredentialValidationError> {
        // mstsc may send DOMAIN\user or user@domain; only the user part matters here.
        self.ctx.set_activity(Activity::Authenticating);
        let user = c.username.rsplit('\\').next().unwrap_or("").split('@').next().unwrap_or("").to_lowercase();
        if c.password.is_empty() {
            warn!(user = %c.username, "client sent no password: run rdesk-rdp --set-password for NLA, or save the credentials in mstsc");
            return Ok(CredentialDecision::Reject);
        }
        let ok = if user != self.user.to_lowercase() {
            false
        } else {
            let (u, p, ctx, cold_boot) = (self.user.clone(), c.password.clone(), self.ctx.clone(), self.cold_boot);
            tokio::task::spawn_blocking(move || {
                if cold_boot {
                    match session::login(&u, &p) {
                        Ok(Some(())) => {
                            info!("LightDM accepted remote login; waiting for the desktop");
                            if let Err(e) = session::prepare_desktop(&ctx.conn, ctx.root) {
                                error!("cold-boot desktop: {:#}", e);
                                return false;
                            }
                            ctx.fresh_login.store(true, Ordering::Relaxed);
                            return true;
                        }
                        Ok(None) => {
                            if !session::desktop_ready(&ctx.conn, ctx.root).unwrap_or(false) {
                                warn!("cold-boot login unavailable: no bridge and no Cinnamon desktop");
                                return false;
                            }
                            info!("no greeter bridge; authenticating existing desktop");
                        }
                        Err(e) => { warn!("LightDM login: {:#}", e); return false; }
                    }
                }
                nthash::check(&u, &p)
            }).await.unwrap_or(false)
        };
        info!(user = %c.username, domain = ?c.domain, ok, "login");
        self.ctx.set_activity(if ok { Activity::Active(Instant::now()) } else { Activity::Handshake });
        if ok {
            match nthash::store(&self.hash_file, &c.password) {
                Ok(true) => info!("stored the NT hash for NLA; the server switches to NLA once idle"),
                Ok(false) => {}
                Err(e) => warn!("{}: {}", self.hash_file.display(), e),
            }
        }
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
    /// Ctrl held (either side), for the phone zoom mapping in `key`.
    ctrl: bool,
    /// Keycodes that numpad +/- presses were remapped to, so releases match.
    remapped: HashMap<u8, u8>,
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
    fn key(&mut self, code: u8, extended: bool, pressed: bool) {
        if code == 0x1d { self.ctrl = pressed; }
        // The iOS Windows app sends Ctrl + '+' / '-' as Ctrl + numpad plus/minus,
        // which browsers here ignore for zoom. With Ctrl held, type the layout's
        // main-row '+' / '-' keys instead (zoom in / out from a phone).
        if !extended && (code == 0x4e || code == 0x4a) {
            let kc = if pressed && self.ctrl {
                if self.keysyms.is_none() { self.keysyms = Some(self.build_keysyms()); }
                let ks = if code == 0x4e { 0x2b } else { 0x2d };
                self.keysyms.as_ref().unwrap().get(&ks).filter(|&&(_, shift)| !shift).map(|&(kc, _)| kc)
            } else if !pressed { self.remapped.remove(&code) } else { None };
            if let Some(kc) = kc {
                if pressed { self.remapped.insert(code, kc); }
                self.fake(if pressed { xproto::KEY_PRESS_EVENT } else { xproto::KEY_RELEASE_EVENT }, kc, 0, 0);
                return;
            }
        }
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
        self.ctx.seen();
        // Key diagnostics only while ~/.config/rdesk/keylog exists: it records
        // everything typed, passwords included, so it is never on by default.
        if std::path::Path::new(&std::env::var("HOME").unwrap_or_default()).join(".config/rdesk/keylog").exists() {
            info!(?e, "key");
        }
        match e {
            KeyboardEvent::Pressed { code, extended } => self.key(code, extended, true),
            KeyboardEvent::Released { code, extended } => self.key(code, extended, false),
            KeyboardEvent::UnicodePressed(u) => self.unicode(u, true),
            KeyboardEvent::UnicodeReleased(u) => self.unicode(u, false),
            KeyboardEvent::Synchronize(_) => {}
        }
    }
    fn mouse(&mut self, e: MouseEvent) {
        self.ctx.seen();
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
                let (w, h) = self.ctx.dimensions();
                let (sx, sy) = self.ctx.fit_for(w, h).to_screen(x, y, w, h);
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
    /// XFIXES serial of the last pointer shape sent to the client.
    cursor_serial: Option<u32>,
}

const LEGACY_FPS: u32 = 15;
/// How often the pointer shape is polled (it goes out only when it changes).
const CURSOR_POLL: Duration = Duration::from_millis(16);
/// Largest pointer without the large-pointer capability (MS-RDPBCGR 2.2.9.1.1.4.4).
const MAX_POINTER: usize = 96;

/// X cursor (premultiplied ARGB, top-down) as an RDP 32 bpp pointer: straight
/// alpha BGRA, bottom-up rows, cropped to 96x96 around the hotspot's corner.
fn rdp_pointer(cur: &x11rb::protocol::xfixes::GetCursorImageReply) -> RGBAPointer {
    let (cw, ch) = (cur.width as usize, cur.height as usize);
    let (w, h) = (cw.clamp(1, MAX_POINTER), ch.clamp(1, MAX_POINTER));
    let mut data = Vec::with_capacity(w * h * 4);
    for y in (0..h).rev() {
        for x in 0..w {
            let px = if x < cw && y < ch { cur.cursor_image[y * cw + x] } else { 0 };
            let a = px >> 24;
            let un = |c: u32| if a == 0 { 0 } else { ((c * 255 + a / 2) / a).min(255) as u8 };
            data.extend_from_slice(&[un(px & 0xff), un((px >> 8) & 0xff), un((px >> 16) & 0xff), a as u8]);
        }
    }
    RGBAPointer {
        cache_index: 0,
        width: w as u16,
        height: h as u16,
        hot_x: cur.xhot.min(w as u16 - 1),
        hot_y: cur.yhot.min(h as u16 - 1),
        data,
    }
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
        loop {
            if self.ctx.client_cursor {
                let cur = self.ctx.conn.xfixes_get_cursor_image().ok().and_then(|c| c.reply().ok());
                if let Some(cur) = cur.filter(|c| Some(c.cursor_serial) != self.cursor_serial) {
                    self.cursor_serial = Some(cur.cursor_serial);
                    return Ok(Some(DisplayUpdate::RGBAPointer(rdp_pointer(&cur))));
                }
            }
            let mode = *self.ctx.mode.lock().unwrap();
            let wait = match mode {
                // GFX path owns the screen; keep polling in case it collapses into Legacy.
                Mode::Avc => CURSOR_POLL,
                Mode::Legacy => {
                    let now = tokio::time::Instant::now();
                    if now >= self.next { break }
                    (self.next - now).min(CURSOR_POLL)
                }
                Mode::Unknown if self.started.elapsed() > Duration::from_secs(3) => {
                    info!("no GFX channel from client, using legacy bitmap updates");
                    *self.ctx.mode.lock().unwrap() = Mode::Legacy;
                    continue;
                }
                Mode::Unknown => CURSOR_POLL,
            };
            tokio::time::sleep(if self.ctx.client_cursor { wait } else { wait.max(Duration::from_millis(50)) }).await;
        }
        self.next = tokio::time::Instant::now() + Duration::from_secs_f64(1.0 / LEGACY_FPS as f64);
        let ctx = self.ctx.clone();
        let (fit, data) = tokio::task::spawn_blocking(move || bitmap(&ctx)).await??;
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

struct Capture {
    w: u16,
    h: u16,
    shm: Shm,
}

/// Query live geometry, including the greeter -> Cinnamon mode change. Keep
/// the SHM buffer locked until its consumer has copied/written the frame.
fn grab<'a>(ctx: &'a Ctx) -> anyhow::Result<std::sync::MutexGuard<'a, Capture>> {
    let mut c = ctx.capture.lock().unwrap();
    let geo = ctx.conn.get_geometry(ctx.root)?.reply()?;
    let (w, h) = (geo.width & !1, geo.height & !1);
    anyhow::ensure!(w >= 2 && h >= 2, "empty X screen");
    if (c.w, c.h) != (w, h) {
        info!("X screen changed: {}x{} -> {}x{}", c.w, c.h, w, h);
        // Detach before dropping the old mapping; Shm is also used by the
        // older binaries, so lifecycle changes remain local here.
        let shm = Shm::new(&ctx.conn, w as usize * h as usize * 4);
        ctx.conn.shm_detach(c.shm.seg)?.check()?;
        unsafe { libc::shmdt(c.shm.ptr as *const libc::c_void); }
        *c = Capture { w, h, shm };
    }
    ctx.conn.shm_get_image(ctx.root, 0, 0, c.w, c.h, !0, ImageFormat::Z_PIXMAP.into(), c.shm.seg, 0)?.reply()?;
    if !ctx.client_cursor {
        if let Some(cur) = ctx.conn.xfixes_get_cursor_image().ok().and_then(|c| c.reply().ok()) {
            draw_cursor(c.shm.buf(), c.w as usize, c.h as usize, &cur);
        }
    }
    Ok(c)
}

fn bitmap(ctx: &Ctx) -> anyhow::Result<(Fit, Vec<u8>)> {
    let c = grab(ctx)?;
    let fit = ctx.fit_for(c.w, c.h);
    Ok((fit, fit.bitmap(c.shm.buf(), c.w, c.h)))
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
        let (w, h) = ((client.width & !1).max(2), (client.height & !1).max(2));
        // After a greeter login the desktop takes the client's size when the
        // monitor has that mode (else the largest that fits). Phones keep the
        // monitor's own mode; they get the window/portrait handling below.
        if self.ctx.fresh_login.swap(false, Ordering::Relaxed) && !portrait::phone_size(w, h) {
            let ctx = self.ctx.clone();
            let r = tokio::task::spawn_blocking(move || session::settle_mode(&ctx.conn, ctx.root, w, h)).await;
            if let Ok(Err(e)) = r { warn!("cold-boot mode for {}x{}: {:#}", w, h, e); }
        }
        if self.ctx.phone_res && portrait::phone_size(w, h) {
            let mut saved = self.ctx.phone_desktop.lock().unwrap();
            // Initial size can be requested again during RDP reactivation.
            // Keep the original restore point for this entire connection.
            if saved.is_none() {
                match portrait::PhoneDesktop::start(self.ctx.conn.clone(), self.ctx.root, w, h) {
                    Ok(desktop) => *saved = desktop,
                    Err(e) => warn!("portrait desktop unavailable, retaining scaled view: {:#}", e),
                }
            }
        }
        // Authentication may have started Cinnamon and changed the X mode.
        if let Err(e) = grab(&self.ctx) { warn!("initial capture: {:#}", e); }
        let (screen_w, screen_h) = self.ctx.dimensions();
        *self.ctx.out.lock().unwrap() = (w, h);
        let fit = self.ctx.fit();
        if let Some(_) = fit.win {
            // Start with the window centred on the pointer.
            let p = self.ctx.conn.query_pointer(self.ctx.root).ok().and_then(|c| c.reply().ok());
            let (px, py) = p.map(|p| (p.root_x as i32, p.root_y as i32)).unwrap_or((screen_w as i32 / 2, screen_h as i32 / 2));
            self.ctx.pan_to(px - fit.fw as i32 / 2, py - fit.fh as i32 / 2);
            let (vx, vy) = *self.ctx.view.lock().unwrap();
            info!("client desktop {}x{}, screen {}x{} shown as a {}x{} window at {},{}", w, h, screen_w, screen_h, fit.fw, fit.fh, vx, vy);
        } else {
            info!("client desktop {}x{}, screen {}x{} shown as {}x{} at {},{}", w, h, screen_w, screen_h, fit.fw, fit.fh, fit.fx, fit.fy);
        }
        DesktopSize { width: w, height: h }
    }
    async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
        *self.ctx.mode.lock().unwrap() = Mode::Unknown;
        Ok(Box::new(Updates { ctx: self.ctx.clone(), started: Instant::now(), next: tokio::time::Instant::now(), cursor_serial: None }))
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
        tracing::debug!(frame_id, queue_depth, total_frames_decoded, "frame ack");
        // 0xFFFFFFFF = SUSPEND_FRAME_ACKNOWLEDGEMENT: no more acks are coming.
        if queue_depth == u32::MAX { self.ctx.acked_suspended.store(true, Ordering::Relaxed); }
        self.ctx.acked.store(frame_id, Ordering::Relaxed);
        self.ctx.seen();
    }
    fn on_qoe_metrics(&mut self, m: ironrdp_egfx::server::QoeMetrics) {
        tracing::debug!(?m, "qoe");
    }
    fn on_ready(&mut self, negotiated: &CapabilitySet) {
        info!(?negotiated, "gfx ready");
        let Some(handle) = self.handle.lock().unwrap().clone() else { return };
        // mstsc re-advertises caps when it resets the channel; end the old stream first.
        self.stop.store(true, Ordering::Relaxed);
        self.stop = Arc::new(AtomicBool::new(false));
        let (ctx, ev, stop) = (self.ctx.clone(), self.ev.clone(), self.stop.clone());
        let task = thread::spawn(move || {
            if let Err(e) = stream(ctx, ev, handle, stop) { error!("stream: {:#}", e); }
        });
        self.ctx.streams.lock().unwrap().push((self.stop.clone(), task));
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
    let (w, h) = ctx.dimensions();
    let fit = ctx.fit();
    let (sw, sh) = (fit.ow, fit.oh);
    let (surface, avc) = {
        let mut g = handle.lock().unwrap();
        // ResetGraphics with a real monitor definition; the bare one create_surface
        // would send has none, and mstsc is stricter than FreeRDP about that.
        g.resize_with_monitors(sw, sh, vec![Monitor {
            left: 0, top: 0, right: sw as i32 - 1, bottom: sh as i32 - 1, flags: MonitorFlags::PRIMARY,
        }]);
        let sid = g.create_surface(sw, sh).context("create_surface")?;
        g.map_surface_to_output(sid, 0, 0);
        flush(&mut g, &ev)?;
        *ctx.mode.lock().unwrap() = Mode::Avc;
        (sid, g.supports_avc420())
    };
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
    if !avc {
        info!(surface, "client has GFX but no AVC420: planar dirty rectangles, {}x{} as {}x{}", w, h, sw, sh);
        ctx.acked.store(u32::MAX, Ordering::Relaxed);
        ctx.acked_suspended.store(false, Ordering::Relaxed);
        return stream_planar(ctx, ev, handle, stop, surface);
    }
    info!(surface, "streaming {}x{} as {}x{}", w, h, sw, sh);


    // The RDP surface stays fixed. Restart only ffmpeg when X changes size;
    // the next encoder emits new SPS/PPS and an IDR on the same surface.
    let started = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) { return Ok(()); }
        match stream_avc(&ctx, &ev, &handle, &stop, surface, started) {
            Ok(false) => return Ok(()),
            Ok(true) => info!("restarting encoder for new X geometry"),
            // An NVIDIA driver update leaves the loaded kernel module and the new
            // libraries mismatched until reboot: NVENC fails, the client stays black.
            Err(e) if ctx.nvenc.load(Ordering::Relaxed) && !probe_nvenc() => {
                warn!("NVENC unavailable ({:#}); encoding with libx264 until restart (reboot after a driver update)", e);
                ctx.nvenc.store(false, Ordering::Relaxed);
            }
            Err(e) => return Err(e),
        }
    }
}

fn stream_avc(ctx: &Arc<Ctx>, ev: &EvSender, handle: &GfxServerHandle, stop: &Arc<AtomicBool>, surface: u16, t0: Instant) -> anyhow::Result<bool> {
    let (w, h) = ctx.dimensions();
    let fit = ctx.fit_for(w, h);
    let (sw, sh) = (fit.ow, fit.oh);
    let resized = Arc::new(AtomicBool::new(false));
    let cap_stop = Arc::new(AtomicBool::new(false));
    let win = fit.win.is_some();
    let (ew, eh) = if win { (sw, sh) } else { (w, h) };
    let mut enc = spawn_encoder(ew, eh, ctx.fps, &ctx.bitrate, ctx.nvenc.load(Ordering::Relaxed), "avi", fit.vf().as_deref());
    let mut enc_in = enc.stdin.take().unwrap();
    let mut enc_out = enc.stdout.take().unwrap();

    // Capture thread. Skips ticks while the client has too many frames un-acked,
    // so a slow link just lowers the frame rate instead of building a queue.
    let cap = {
        let (ctx, handle, stop, resized, cap_stop) = (ctx.clone(), handle.clone(), stop.clone(), resized.clone(), cap_stop.clone());
        let period = Duration::from_secs_f64(1.0 / ctx.fps as f64);
        thread::spawn(move || {
            let mut next = Instant::now();
            while !stop.load(Ordering::Relaxed) && !cap_stop.load(Ordering::Relaxed) {
                next += period;
                let busy = handle.lock().unwrap().should_backpressure();
                if !busy {
                    let c = match grab(&ctx) {
                        Ok(c) => c,
                        Err(e) => { warn!("capture: {:#}", e); thread::sleep(period); continue; }
                    };
                    if (c.w, c.h) != (w, h) {
                        resized.store(true, Ordering::Relaxed);
                        break;
                    }
                    // Window mode: crop per frame, the window moves while panning.
                    let r = if win { enc_in.write_all(&ctx.fit_for(w, h).bitmap(c.shm.buf(), w, h)) } else { enc_in.write_all(c.shm.buf()) };
                    if r.is_err() { break; }
                }
                let now = Instant::now();
                if next > now { thread::sleep(next - now); } else { next = now; }
            }
            // Closing stdin lets AVI drain and EOF; a resize is not a disconnect.
        })
    };

    // This thread: AVI chunks -> AVC420 frames.
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
                if stop.load(Ordering::Relaxed) { return Ok(()); }
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
    cap_stop.store(true, Ordering::Relaxed);
    enc.kill().ok();
    enc.wait().ok();
    cap.join().ok();
    let changed = resized.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed);
    // A resize before the first captured frame can give ffmpeg an empty
    // input (no AVI header). It still needs a fresh encoder, not a disconnect.
    if changed { return Ok(true); }
    r?;
    Ok(false)
}

/// A GFX PDU encoded and wrapped in a ZGFX segment, ready for the DVC. Every
/// GFX PDU on the wire is inside RDP_SEGMENTED_DATA; ironrdp does this in
/// drain_output for its own queue, this is the same for PDUs we build ourselves.
struct Zgfx(Vec<u8>);

impl ironrdp_pdu::ironrdp_core::Encode for Zgfx {
    fn encode(&self, dst: &mut ironrdp_pdu::ironrdp_core::WriteCursor<'_>) -> ironrdp_pdu::ironrdp_core::EncodeResult<()> {
        dst.write_slice(&self.0);
        Ok(())
    }
    fn name(&self) -> &'static str { "ZGFX" }
    fn size(&self) -> usize { self.0.len() }
}
impl ironrdp_dvc::DvcEncode for Zgfx {}

fn zgfx(pdu: GfxPdu) -> ironrdp_dvc::DvcMessage {
    use ironrdp_pdu::ironrdp_core::{Encode as _, WriteCursor};
    let mut bytes = vec![0u8; pdu.size()];
    pdu.encode(&mut WriteCursor::new(&mut bytes)).expect("GfxPdu encode");
    Box::new(Zgfx(ironrdp_graphics::zgfx::wrap_uncompressed(&bytes)))
}

/// GFX for clients that refuse H.264 (the iOS Windows app): the client-sized
/// frame is diffed against the previous one in 64 px tiles and the changed
/// spans go out as RDP6 planar (RLE) WireToSurface rectangles, at most two
/// frames in flight so the client's decode speed sets the pace.
fn stream_planar(ctx: Arc<Ctx>, ev: EvSender, handle: GfxServerHandle, stop: Arc<AtomicBool>, surface: u16) -> anyhow::Result<()> {
    const T: usize = 64;
    let period = Duration::from_secs_f64(1.0 / ctx.fps as f64);
    let t0 = Instant::now();
    let mut prev: Option<(Vec<u8>, u16, u16)> = None;
    // Rectangles not yet sent because a frame was full (see BUDGET).
    let mut pending: Vec<(usize, usize, usize, usize)> = Vec::new();
    let mut frame_id = 0u32;
    let mut next = Instant::now();
    let mut stats = (0u64, 0usize, Instant::now());
    // Knobs kept from the bring-up: RDESK_PLANAR=rle|raw|off (ironrdp's RLE
    // planes, raw planes, uncompressed), RDESK_BUDGET bytes per frame,
    // RDESK_INFLIGHT unacked frames.
    let mode = std::env::var("RDESK_PLANAR").unwrap_or_else(|_| "raw".into());
    let budget: usize = std::env::var("RDESK_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(1 << 20);
    let inflight: u32 = std::env::var("RDESK_INFLIGHT").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    while !stop.load(Ordering::Relaxed) {
        // Wait for acks (unless the client suspended them) before the next frame.
        loop {
            if stop.load(Ordering::Relaxed) { return Ok(()); }
            let acked = ctx.acked.load(Ordering::Relaxed);
            // frame_id = frames sent so far; acked = last acked id (u32::MAX = none yet / suspended).
            let unacked = if acked == u32::MAX { frame_id } else { frame_id.saturating_sub(acked + 1) };
            if ctx.acked_suspended.load(Ordering::Relaxed) || unacked < inflight { break; }
            thread::sleep(Duration::from_millis(1));
        }
        let (fit, cur) = match bitmap(&ctx) {
            Ok(frame) => frame,
            Err(e) => { warn!("capture: {:#}", e); thread::sleep(period); continue; }
        };
        let (ow, oh) = (fit.ow as usize, fit.oh as usize);
        // Dirty spans: runs of changed 64x64 tiles per tile row (whole frame the first time
        // or when the client size changed).
        let mut rects: Vec<(usize, usize, usize, usize)> = std::mem::take(&mut pending);
        match &prev {
            Some((p, pw, ph)) if (*pw as usize, *ph as usize) == (ow, oh) => {
                for ty in (0..oh).step_by(T) {
                    let th = T.min(oh - ty);
                    let mut run: Option<usize> = None;
                    for tx in (0..ow + T).step_by(T) {
                        let dirty = tx < ow && (0..th).any(|r| {
                            let o = ((ty + r) * ow + tx) * 4;
                            let n = T.min(ow - tx) * 4;
                            cur[o..o + n] != p[o..o + n]
                        });
                        match (dirty, run) {
                            (true, None) => run = Some(tx),
                            (false, Some(x0)) => { rects.push((x0, ty, tx.min(ow), ty + th)); run = None; }
                            _ => {}
                        }
                    }
                }
            }
            // First frame (or client size changed): the whole surface, in 64-row
            // bands so no single WireToSurface PDU gets into the megabytes.
            _ => { rects.clear(); for ty in (0..oh).step_by(T) { rects.push((0, ty, ow, (ty + T).min(oh))); } }
        }
        // The iOS app drops the connection on a multi-megabyte frame (a whole
        // 992x1850 surface is 5.5 MB raw), so a frame carries at most ~1 MB of
        // pixels and the rest follows in the next frames.
        let mut used = 0usize;
        let mut i = 0;
        while i < rects.len() {
            let (x0, y0, x1, y1) = rects[i];
            used += (x1 - x0) * (y1 - y0) * 4;
            i += 1;
            if used >= budget { break; }
        }
        pending = rects.split_off(i);
        if !rects.is_empty() {
            let ms = t0.elapsed().as_millis() as u32;
            let ts = Timestamp { milliseconds: (ms % 1000) as u16, seconds: ((ms / 1000) % 60) as u8,
                                 minutes: ((ms / 60000) % 60) as u8, hours: ((ms / 3600000) % 24) as u16 };
            let mut msgs: Vec<ironrdp_dvc::DvcMessage> = vec![zgfx(GfxPdu::StartFrame(StartFramePdu { timestamp: ts, frame_id }))];
            let mut bytes = 0usize;
            for &(x0, y0, x1, y1) in &rects {
                let (rw, rh) = (x1 - x0, y1 - y0);
                let mut px = Vec::with_capacity(rw * rh * 4);
                for y in y0..y1 { px.extend_from_slice(&cur[(y * ow + x0) * 4..(y * ow + x1) * 4]); }
                let (codec, out) = if mode == "off" {
                    (Codec1Type::Uncompressed, px)
                } else {
                    let mut out = vec![0u8; rw * rh * 4 + 64];
                    let mut enc = BitmapStreamEncoder::new(rw, rh);
                    let n = match enc.encode_bitmap::<BgrAChannels>(&px, &mut out, mode == "rle") {
                        Ok(n) => n,
                        Err(_) => enc.encode_bitmap::<BgrAChannels>(&px, &mut out, false).map_err(|e| anyhow::anyhow!("planar: {:?}", e))?,
                    };
                    out.truncate(n);
                    (Codec1Type::Planar, out)
                };
                bytes += out.len();
                msgs.push(zgfx(GfxPdu::WireToSurface1(WireToSurface1Pdu {
                    surface_id: surface, codec_id: codec, pixel_format: GfxPixelFormat::XRgb,
                    destination_rectangle: ExclusiveRectangle { left: x0 as u16, top: y0 as u16, right: x1 as u16, bottom: y1 as u16 },
                    bitmap_data: out,
                })));
            }
            msgs.push(zgfx(GfxPdu::EndFrame(EndFramePdu { frame_id })));
            frame_id += 1;
            {
                let g = handle.lock().unwrap();
                if !g.is_ready() { anyhow::bail!("gfx channel closed"); }
                let ch = g.channel_id().context("gfx channel not open")?;
                let svc = ironrdp_dvc::encode_dvc_messages(ch, msgs, ChannelFlags::SHOW_PROTOCOL)?;
                let guard = ev.lock().unwrap();
                guard.as_ref().context("no event sender")?.send(ServerEvent::Egfx(EgfxServerMessage::SendMessages { messages: svc })).ok();
            }
            stats.0 += 1; stats.1 += bytes;
            tracing::debug!(frame_id, rects = rects.len(), bytes, "planar frame");
        }
        prev = Some((cur, fit.ow, fit.oh));
        if stats.2.elapsed() >= Duration::from_secs(5) {
            info!("planar: {:.1} fps, {:.0} kB/s", stats.0 as f64 / stats.2.elapsed().as_secs_f64(), stats.1 as f64 / stats.2.elapsed().as_secs_f64() / 1000.0);
            stats = (0, 0, Instant::now());
        }
        next += period;
        let now = Instant::now();
        if next > now { thread::sleep(next - now); } else { next = now; }
    }
    Ok(())
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
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .compact().init();
    let o = parse_args();

    let (conn, screen_num) = x11rb::connect(None).context("connect to X (DISPLAY set?)")?;
    let conn = Arc::new(conn);
    let screen = &conn.setup().roots[screen_num];
    let root = screen.root;
    // H.264 describes non-macroblock dimensions through SPS cropping. Keep all
    // 1080 rows; truncating to 1072 makes native 1080p subtly scaled/letterboxed.
    let (w, h) = (screen.width_in_pixels & !1, screen.height_in_pixels & !1);
    conn.shm_query_version()?.reply().context("MIT-SHM missing")?;
    conn.xfixes_query_version(5, 0)?.reply().context("XFIXES missing")?;
    let shm = Shm::new(&conn, w as usize * h as usize * 4);
    let nvenc = !o.cpu && probe_nvenc();
    let ctx = Arc::new(Ctx { conn, root, capture: Mutex::new(Capture { w, h, shm }), fps: o.fps, bitrate: o.bitrate.clone(), nvenc: AtomicBool::new(nvenc), mode: Mutex::new(Mode::Unknown), out: Mutex::new((w, h)),
                             viewport: o.viewport, view: Mutex::new((0, 0)), acked: AtomicU32::new(u32::MAX), acked_suspended: AtomicBool::new(false),
                             phone_res: o.phone_res, phone_desktop: Mutex::new(None),
                             activity: Mutex::new(Activity::Handshake),
                             client_cursor: std::env::var("RDESK_CURSOR").map_or(true, |v| v != "video"), streams: Mutex::new(Vec::new()), fresh_login: AtomicBool::new(false) });

    // Clipboard needs its own X connection, opened while the cookie is readable.
    let clip = match clip::ClipFactory::start(None) {
        Ok(c) => Some(c),
        Err(e) => { warn!("clipboard unavailable: {:#}", e); None }
    };

    // Started as root (system service) only to read LightDM's X cookie: the X
    // connection and its shm are set up now, so become the login user before
    // touching the network or the home directory.
    if unsafe { libc::getuid() } == 0 {
        let name = std::ffi::CString::new(o.user.as_str())?;
        let pw = unsafe { libc::getpwnam(name.as_ptr()) };
        anyhow::ensure!(!pw.is_null(), "no such user: {}", o.user);
        let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
        unsafe {
            anyhow::ensure!(libc::initgroups(name.as_ptr(), gid) == 0, "initgroups");
            anyhow::ensure!(libc::setgid(gid) == 0, "setgid");
            anyhow::ensure!(libc::setuid(uid) == 0, "setuid");
        }
        info!("dropped root, running as {} ({})", o.user, uid);
    }

    let (cert, key) = ensure_cert(&o.certdir)?;
    let identity = TlsIdentityCtx::init_from_paths(&cert, &key).context("TLS identity")?;
    let acceptor = identity.make_acceptor().context("TLS acceptor")?;

    let ev: EvSender = Default::default();
    let addr: std::net::SocketAddr = o.bind.parse().context("--bind")?;
    // Three login modes:
    //  - nthash: NLA (CredSSP/NTLM) against the stored NT hash of the Linux password;
    //    mstsc prompts like it does for Windows. After NTLM succeeds the client
    //    delegates the plain password (patched ironrdp-acceptor), which goes through
    //    the same validator as TLS below: unix_chkpwd or the cold-boot LightDM login.
    //  - system password: TLS without NLA, like xrdp. mstsc only forwards a password
    //    it has *saved* ("Allow me to save credentials"); it never sends a typed one
    //    to a non-NLA server. We check it with unix_chkpwd.
    //  - --pass: NLA with a fixed password; NTLM is the whole check.
    let nla_secret = if !o.pass.is_empty() {
        Some(o.pass.clone())
    } else {
        o.nthash.as_ref().map(|h| format!("$NTLM$:{}", h))
    };
    let builder = RdpServer::builder().with_addr(addr);
    let builder = if nla_secret.is_none() {
        builder.with_tls(acceptor)
    } else {
        builder.with_hybrid(acceptor, identity.pub_key.clone())
    };
    let validator: Option<Arc<dyn CredentialValidator>> = if o.pass.is_empty() {
        Some(Arc::new(Login { user: o.user.clone(), cold_boot: o.cold_boot, hash_file: o.certdir.join("nthash"), ctx: ctx.clone() }))
    } else {
        None
    };
    let mut server = builder
        .with_input_handler(Input { ctx: ctx.clone(), keysyms: None, spare: None, ctrl: false, remapped: HashMap::new() })
        .with_display_handler(Display { ctx: ctx.clone() })
        .with_gfx_factory(Some(Box::new(GfxFactory { ctx: ctx.clone(), ev })))
        .with_cliprdr_factory(clip.map(|c| Box::new(c) as Box<dyn ironrdp_server::CliprdrServerFactory>))
        .with_honor_client_desktop_size(true)
        .with_credential_validator(validator)
        .build();
    if let Some(password) = nla_secret {
        server.set_credentials(Some(Credentials { username: o.user.clone(), password, domain: None }));
    }

    info!("rdesk-rdp: {}x{}{} @{}fps {} encoder={} login={} ({}) listening on {}",
          w, h, if o.viewport { " (window for every smaller client)" } else { "" }, o.fps, o.bitrate, if nvenc { "h264_nvenc" } else { "libx264" }, o.user,
          if !o.pass.is_empty() { "NLA, --pass" } else if o.nthash.is_some() { "NLA, system password" } else { "TLS, system password from saved mstsc credentials" }, o.bind);
    // Own accept loop instead of server.run(): IronRDP serves one client at a
    // time, so a peer that vanishes mid-handshake (NAT dropping the flow) would
    // otherwise hold the loop for the kernel's ~15 min of retransmits while new
    // clients queue up unanswered. TCP_USER_TIMEOUT on the listener is inherited
    // by accepted sockets and ends such a connection after 20 s of no ACKs.
    // As a system service rdesk mirrors :0 from the login screen on. LightDM
    // restarts the X server on logout, which leaves us with a dead connection;
    // exit on that and let systemd start a fresh one.
    {
        let ctx = ctx.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(3));
            if ctx.conn.get_input_focus().and_then(|c| Ok(c.reply())).map(|r| r.is_err()).unwrap_or(true) {
                error!("X connection lost, exiting for a restart");
                std::process::exit(1);
            }
        });
    }
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
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let shutdown = async { tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} } };
    tokio::pin!(shutdown);
    // The login mode is fixed per server; when the PAM hook or a login stores a
    // new NT hash, exit between connections and let systemd start one with it.
    let hash_file = o.certdir.join("nthash");
    let mut hash_check = tokio::time::interval(Duration::from_secs(5));
    let mut next: Option<(tokio::net::TcpStream, std::net::SocketAddr)> = None;
    'serve: loop {
        let (stream, peer) = match next.take() {
            Some(c) => c,
            None => tokio::select! {
                accepted = listener.accept() => accepted?,
                _ = &mut shutdown => break,
                _ = hash_check.tick(), if o.pass.is_empty() => {
                    if nthash::read(&hash_file) != o.nthash {
                        info!("{} changed, restarting to use it", hash_file.display());
                        std::process::exit(0);
                    }
                    continue;
                }
            },
        };
        keepalive(&stream);
        info!(%peer, "connection");
        ctx.set_activity(Activity::Handshake);
        let t = Instant::now();
        // IronRDP serves one client at a time. Keep accepting meanwhile: a new
        // client replaces one that is still handshaking (mstsc abandons its
        // pre-prompt connection) or has gone silent (laptop asleep, NAT dropped
        // the flow); otherwise it is turned away instead of queueing behind it.
        let result = {
            let conn = server.run_connection(stream);
            tokio::pin!(conn);
            loop {
                tokio::select! {
                    result = &mut conn => break Some(result),
                    _ = &mut shutdown => break None,
                    accepted = listener.accept() => {
                        let (s2, p2) = accepted?;
                        if ctx.replaceable() {
                            info!(%peer, new = %p2, "replacing idle or unfinished connection");
                            next = Some((s2, p2));
                            break Some(Ok(()));
                        }
                        warn!(%peer, rejected = %p2, "busy with a live session, refusing new connection");
                    }
                }
            }
        };
        ctx.end_connection();
        ctx.set_activity(Activity::Handshake);
        match result {
            Some(Ok(())) if next.is_some() => info!(%peer, "dropped after {:.0?}", t.elapsed()),
            Some(Ok(())) => info!(%peer, "disconnected after {:.0?}", t.elapsed()),
            Some(Err(e)) => error!(%peer, "connection failed after {:.0?}: {:#}", t.elapsed(), e),
            None => break 'serve,
        }
    }
    info!("server stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_is_bottom_up_straight_alpha_bgra() {
        let cur = x11rb::protocol::xfixes::GetCursorImageReply {
            sequence: 0, length: 0, x: 0, y: 0, width: 1, height: 2, xhot: 3, yhot: 0, cursor_serial: 1,
            // top: half-transparent premultiplied red; bottom: opaque blue
            cursor_image: vec![0x8080_0000, 0xff00_00ff],
        };
        let p = rdp_pointer(&cur);
        assert_eq!((p.width, p.height, p.hot_x, p.hot_y), (1, 2, 0, 0));
        assert_eq!(p.data, vec![0xff, 0, 0, 0xff, 0, 0, 0xff, 0x80]);
    }

    #[test]
    fn nt_hash_matches_ntlm() {
        // MS-NLMP test vector: NTOWFv1("Password").
        assert_eq!(nthash::hash("Password"), "a4f49c406510bdcab6824ee7c30fd852");
    }

    #[test]
    fn native_1080p_keeps_every_row_and_pixel() {
        let fit = Fit::new(1920, 1080, 1920, 1080);
        assert!(fit.identity());
        assert_eq!((fit.fw, fit.fh, fit.fx, fit.fy), (1920, 1080, 0, 0));
        assert!(fit.vf().is_none());
        assert_eq!(fit.to_screen(1919, 1079, 1920, 1080), (1919, 1079));
    }

    #[test]
    fn native_portrait_pixels_and_pointer_have_identical_coordinates() {
        let (w, h) = (992u16, 1850u16);
        let fit = Fit::new(w, h, w, h);
        assert!(fit.identity());
        assert!(fit.vf().is_none());
        for (x, y) in [(0, 0), (496, 925), (991, 1849)] {
            assert_eq!(fit.to_screen(x, y, w, h), (x as i16, y as i16));
        }
        let mut pixels = vec![0; w as usize * h as usize * 4];
        let i = (1600 * w as usize + 800) * 4;
        pixels[i..i + 4].copy_from_slice(&[11, 22, 33, 255]);
        assert_eq!(fit.bitmap(&pixels, w, h), pixels);
    }

    #[test]
    fn same_aspect_ratio_still_scales_pixels_and_input() {
        let fit = Fit::new(1280, 720, 1920, 1080);
        assert!(!fit.identity());
        assert!(fit.vf().unwrap().starts_with("scale=1920:1080:"));
        assert_eq!(fit.to_screen(1919, 1079, 1280, 720), (1279, 719));
        let src = vec![7; 1280 * 720 * 4];
        let frame = fit.bitmap(&src, 1280, 720);
        assert_eq!(frame.len(), 1920 * 1080 * 4);
        assert!(frame.iter().all(|b| *b == 7));
    }

    #[test]
    fn ultrawide_letterbox_and_pointer_remain_consistent() {
        let fit = Fit::new(3440, 1440, 1920, 1080);
        assert_eq!((fit.fw, fit.fh, fit.fx, fit.fy), (1920, 802, 0, 138));
        assert_eq!(fit.to_screen(0, 0, 3440, 1440), (0, 0));
        assert_eq!(fit.to_screen(960, 539, 3440, 1440), (1720, 720));
    }

    #[test]
    #[ignore = "requires a disposable Xephyr display in RDESK_TEST_DISPLAY"]
    fn live_capture_tracks_resize() -> anyhow::Result<()> {
        let display = std::env::var("RDESK_TEST_DISPLAY")?;
        anyhow::ensure!(display != ":0" && display != ":0.0", "use a disposable X server");
        let (conn, sn) = x11rb::connect(Some(&display))?;
        let conn = Arc::new(conn);
        let s = &conn.setup().roots[sn];
        let (root, w, h) = (s.root, s.width_in_pixels, s.height_in_pixels);
        conn.shm_query_version()?.reply()?;
        conn.xfixes_query_version(5, 0)?.reply()?;
        let capture = Mutex::new(Capture { w, h, shm: Shm::new(&conn, w as usize * h as usize * 4) });
        let ctx = Ctx { conn, root, capture, fps: 30, bitrate: "12M".into(), nvenc: AtomicBool::new(false),
            mode: Mutex::new(Mode::Unknown), out: Mutex::new((1920, 1080)), viewport: false,
            view: Mutex::new((0, 0)), acked: AtomicU32::new(u32::MAX), acked_suspended: AtomicBool::new(false),
            phone_res: false, phone_desktop: Mutex::new(None), client_cursor: false, activity: Mutex::new(Activity::Handshake), streams: Mutex::new(Vec::new()), fresh_login: AtomicBool::new(false) };
        for _ in 0..3 {
            let status = Command::new("xrandr").args(["--display", &display, "--output", "default", "--mode", "1280x960"]).status()?;
            anyhow::ensure!(status.success(), "nested xrandr resize failed");
            let (fit, pixels) = bitmap(&ctx)?;
            assert_eq!(ctx.dimensions(), (1280, 960));
            assert!(!fit.identity());
            assert_eq!(pixels.len(), 1920 * 1080 * 4);
            session::set_1080p(&ctx.conn, root)?;
            let (fit, pixels) = bitmap(&ctx)?;
            assert_eq!(ctx.dimensions(), (1920, 1080));
            assert!(fit.identity());
            assert_eq!(pixels.len(), 1920 * 1080 * 4);
        }
        Ok(())
    }
}

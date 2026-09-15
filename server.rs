//! rdesk-server: grab the X11 root window via XShm, overlay the cursor, encode
//! with ffmpeg (h264_nvenc, libx264 fallback), stream over TCP, and inject
//! mouse/keyboard from the client via XTest.

mod proto;

use proto::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::shm::{self, ConnectionExt as _};
use x11rb::protocol::xfixes::{ConnectionExt as _, GetCursorImageReply};
use x11rb::protocol::xproto::{self, ConnectionExt as _, ImageFormat};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

struct Opts {
    bind: String,
    fps: u32,
    bitrate: String,
    cpu: bool,
}

fn parse_args() -> Opts {
    let mut o = Opts { bind: "0.0.0.0:7000".into(), fps: 30, bitrate: "12M".into(), cpu: false };
    let mut a = std::env::args().skip(1);
    while let Some(k) = a.next() {
        match k.as_str() {
            "--bind" => o.bind = a.next().expect("--bind ADDR:PORT"),
            "--fps" => o.fps = a.next().expect("--fps N").parse().expect("fps"),
            "--bitrate" => o.bitrate = a.next().expect("--bitrate 12M"),
            "--cpu" => o.cpu = true,
            _ => {
                eprintln!("usage: rdesk-server [--bind 0.0.0.0:7000] [--fps 30] [--bitrate 12M] [--cpu]");
                std::process::exit(2);
            }
        }
    }
    o
}

/// A SysV shared-memory segment attached to both us and the X server.
struct Shm {
    seg: shm::Seg,
    ptr: *mut u8,
    len: usize,
}
unsafe impl Send for Shm {}
unsafe impl Sync for Shm {}

impl Shm {
    fn new(conn: &RustConnection, len: usize) -> Shm {
        let shmid = unsafe { libc::shmget(libc::IPC_PRIVATE, len, libc::IPC_CREAT | 0o600) };
        assert!(shmid >= 0, "shmget failed");
        let ptr = unsafe { libc::shmat(shmid, std::ptr::null(), 0) } as *mut u8;
        assert!(ptr as isize != -1, "shmat failed");
        let seg = conn.generate_id().unwrap();
        conn.shm_attach(seg, shmid as u32, false).unwrap().check().expect("X shm attach");
        // Both sides are attached now; mark for removal so it dies with us.
        unsafe { libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut()) };
        Shm { seg, ptr, len }
    }
    fn buf(&self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

fn probe_nvenc() -> bool {
    Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", "color=size=256x256:rate=1",
               "-frames:v", "1", "-c:v", "h264_nvenc", "-f", "null", "-"])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

fn spawn_encoder(w: u16, h: u16, fps: u32, bitrate: &str, nvenc: bool) -> Child {
    let size = format!("{}x{}", w, h);
    let fps_s = fps.to_string();
    let mut c = Command::new("ffmpeg");
    c.args(["-hide_banner", "-loglevel", "error",
            "-f", "rawvideo", "-pix_fmt", "bgra", "-video_size", &size, "-framerate", &fps_s,
            "-i", "pipe:0", "-an"]);
    if nvenc {
        // bgra straight into NVENC: colour conversion happens on the GPU.
        c.args(["-c:v", "h264_nvenc", "-pix_fmt", "bgra", "-preset", "p1", "-tune", "ll",
                "-rc", "cbr", "-b:v", bitrate, "-maxrate", bitrate, "-bufsize", bitrate,
                "-g", "600", "-bf", "0", "-zerolatency", "1", "-delay", "0", "-aud", "1"]);
    } else {
        c.args(["-c:v", "libx264", "-pix_fmt", "yuv420p", "-preset", "ultrafast", "-tune", "zerolatency",
                "-b:v", bitrate, "-maxrate", bitrate, "-bufsize", bitrate,
                "-g", "600", "-bf", "0", "-aud", "1"]);
    }
    c.args(["-f", "h264", "-flush_packets", "1", "pipe:1"]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    c.spawn().expect("spawn ffmpeg")
}

/// Alpha-blend the (premultiplied ARGB) cursor image onto a BGRA frame.
fn draw_cursor(frame: &mut [u8], fw: usize, fh: usize, cur: &GetCursorImageReply) {
    let ox = cur.x as i32 - cur.xhot as i32;
    let oy = cur.y as i32 - cur.yhot as i32;
    let cw = cur.width as usize;
    for cy in 0..cur.height as usize {
        let y = oy + cy as i32;
        if y < 0 || y >= fh as i32 { continue; }
        for cx in 0..cw {
            let x = ox + cx as i32;
            if x < 0 || x >= fw as i32 { continue; }
            let px = cur.cursor_image[cy * cw + cx];
            let a = px >> 24;
            if a == 0 { continue; }
            let inv = 255 - a;
            let i = (y as usize * fw + x as usize) * 4;
            // frame is B,G,R,X; cursor is premultiplied so dst = src + dst*(1-a)
            frame[i]     = ((px & 255)        + frame[i]     as u32 * inv / 255).min(255) as u8;
            frame[i + 1] = ((px >> 8 & 255)   + frame[i + 1] as u32 * inv / 255).min(255) as u8;
            frame[i + 2] = ((px >> 16 & 255)  + frame[i + 2] as u32 * inv / 255).min(255) as u8;
        }
    }
}

/// keysym -> keycode, preferring the lowest column (unshifted) that yields it.
fn build_keymap(conn: &RustConnection) -> HashMap<u32, u8> {
    let setup = conn.setup();
    let (min, max) = (setup.min_keycode, setup.max_keycode);
    let r = conn.get_keyboard_mapping(min, max - min + 1).unwrap().reply().unwrap();
    let per = r.keysyms_per_keycode as usize;
    let mut m = HashMap::new();
    for col in 0..per {
        for (i, kc) in (min..=max).enumerate() {
            let ks = r.keysyms[i * per + col];
            if ks != 0 { m.entry(ks).or_insert(kc); }
        }
    }
    m
}

fn handle_input(conn: &RustConnection, root: xproto::Window, keymap: &HashMap<u32, u8>, mut rx: TcpStream) -> std::io::Result<()> {
    loop {
        match read_u8(&mut rx)? {
            MSG_MOUSE_MOVE => {
                let x = read_u16(&mut rx)? as i16;
                let y = read_u16(&mut rx)? as i16;
                conn.xtest_fake_input(xproto::MOTION_NOTIFY_EVENT, 0, x11rb::CURRENT_TIME, root, x, y, 0).ok();
            }
            MSG_MOUSE_BTN => {
                let b = read_u8(&mut rx)?;
                let pressed = read_u8(&mut rx)? != 0;
                let t = if pressed { xproto::BUTTON_PRESS_EVENT } else { xproto::BUTTON_RELEASE_EVENT };
                conn.xtest_fake_input(t, b, x11rb::CURRENT_TIME, root, 0, 0, 0).ok();
            }
            MSG_KEY => {
                let ks = read_u32(&mut rx)?;
                let pressed = read_u8(&mut rx)? != 0;
                if let Some(&kc) = keymap.get(&ks) {
                    let t = if pressed { xproto::KEY_PRESS_EVENT } else { xproto::KEY_RELEASE_EVENT };
                    conn.xtest_fake_input(t, kc, x11rb::CURRENT_TIME, root, 0, 0, 0).ok();
                } else {
                    eprintln!("no keycode for keysym 0x{:x}", ks);
                }
            }
            k => {
                eprintln!("bad message kind {}", k);
                return Ok(());
            }
        }
        conn.flush().ok();
    }
}

fn handle_client(o: &Opts, conn: &Arc<RustConnection>, root: xproto::Window, w: u16, h: u16,
                 shm: &Arc<Shm>, keymap: &Arc<HashMap<u32, u8>>, nvenc: bool, mut tx: TcpStream) {
    tx.set_nodelay(true).ok();
    let mut hello = Vec::new();
    hello.extend_from_slice(&w.to_be_bytes());
    hello.extend_from_slice(&h.to_be_bytes());
    if send_msg(&mut tx, MSG_HELLO, &hello).is_err() { return; }

    let mut enc = spawn_encoder(w, h, o.fps, &o.bitrate, nvenc);
    let mut enc_in = enc.stdin.take().unwrap();
    let mut enc_out = enc.stdout.take().unwrap();
    let stop = Arc::new(AtomicBool::new(false));

    // Capture thread: X screen -> shm -> cursor overlay -> ffmpeg stdin.
    let cap = {
        let (conn, shm, stop) = (conn.clone(), shm.clone(), stop.clone());
        let period = Duration::from_secs_f64(1.0 / o.fps as f64);
        thread::spawn(move || {
            let mut next = Instant::now();
            let mut frames = 0u64;
            let mut t0 = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                next += period;
                let r = conn.shm_get_image(root, 0, 0, w, h, !0, ImageFormat::Z_PIXMAP.into(), shm.seg, 0)
                    .and_then(|c| Ok(c.reply()));
                if r.is_err() { eprintln!("shm_get_image failed"); break; }
                if let Ok(cur) = conn.xfixes_get_cursor_image().and_then(|c| Ok(c.reply())) {
                    if let Ok(cur) = cur { draw_cursor(shm.buf(), w as usize, h as usize, &cur); }
                }
                if enc_in.write_all(shm.buf()).is_err() { break; }
                frames += 1;
                if t0.elapsed() >= Duration::from_secs(5) {
                    eprintln!("capture: {:.1} fps", frames as f64 / t0.elapsed().as_secs_f64());
                    frames = 0; t0 = Instant::now();
                }
                let now = Instant::now();
                if next > now { thread::sleep(next - now); } else { next = now; }
            }
            stop.store(true, Ordering::Relaxed);
        })
    };

    // Input thread: client events -> XTest.
    let inp = {
        let (conn, keymap, stop) = (conn.clone(), keymap.clone(), stop.clone());
        let rx = tx.try_clone().unwrap();
        thread::spawn(move || {
            let _ = handle_input(&conn, root, &keymap, rx);
            stop.store(true, Ordering::Relaxed);
        })
    };

    // This thread: ffmpeg stdout -> socket.
    let mut buf = vec![0u8; 256 * 1024];
    while !stop.load(Ordering::Relaxed) {
        let n = match enc_out.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => n };
        if send_video(&mut tx, &buf[..n]).is_err() { break; }
    }
    stop.store(true, Ordering::Relaxed);
    tx.shutdown(Shutdown::Both).ok();
    enc.kill().ok();
    enc.wait().ok();
    cap.join().ok();
    inp.join().ok();
}

fn main() {
    let o = parse_args();
    let (conn, screen_num) = x11rb::connect(None).expect("connect to X (DISPLAY set?)");
    let conn = Arc::new(conn);
    let screen = &conn.setup().roots[screen_num];
    let root = screen.root;
    // Encoders want even dimensions.
    let (w, h) = (screen.width_in_pixels & !1, screen.height_in_pixels & !1);
    conn.shm_query_version().unwrap().reply().expect("MIT-SHM missing");
    conn.xfixes_query_version(5, 0).unwrap().reply().expect("XFIXES missing");
    let shm = Arc::new(Shm::new(&conn, w as usize * h as usize * 4));
    let keymap = Arc::new(build_keymap(&conn));
    let nvenc = !o.cpu && probe_nvenc();

    let listener = TcpListener::bind(&o.bind).expect("bind");
    eprintln!("rdesk-server: {}x{} @{}fps {} encoder={} listening on {}",
              w, h, o.fps, o.bitrate, if nvenc { "h264_nvenc" } else { "libx264" }, o.bind);
    for s in listener.incoming() {
        let Ok(s) = s else { continue };
        eprintln!("client connected: {}", s.peer_addr().map(|a| a.to_string()).unwrap_or_default());
        handle_client(&o, &conn, root, w, h, &shm, &keymap, nvenc, s);
        eprintln!("client gone");
    }
}

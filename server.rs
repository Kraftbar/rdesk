//! rdesk-server: grab the X11 root window via XShm, overlay the cursor, encode
//! with ffmpeg (h264_nvenc, libx264 fallback), stream over TCP, and inject
//! mouse/keyboard from the client via XTest.

mod proto;
mod x11cap;

use proto::*;
use x11cap::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
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
            "--key" => { a.next(); }
            _ => {
                eprintln!("usage: rdesk-server --key PASSPHRASE [--bind 0.0.0.0:7000] [--fps 30] [--bitrate 12M] [--cpu]");
                std::process::exit(2);
            }
        }
    }
    o
}

fn handle_input(conn: &RustConnection, root: xproto::Window, keymap: &HashMap<u32, u8>,
                link: &Link, mut rx: TcpStream) -> std::io::Result<()> {
    loop {
        let m = link.recv(&mut rx)?;
        match (m[0], m.len()) {
            (MSG_MOUSE_MOVE, 5) => {
                let (x, y) = (u16_at(&m, 1) as i16, u16_at(&m, 3) as i16);
                conn.xtest_fake_input(xproto::MOTION_NOTIFY_EVENT, 0, x11rb::CURRENT_TIME, root, x, y, 0).ok();
            }
            (MSG_MOUSE_BTN, 3) => {
                let (b, pressed) = (m[1], m[2] != 0);
                let t = if pressed { xproto::BUTTON_PRESS_EVENT } else { xproto::BUTTON_RELEASE_EVENT };
                conn.xtest_fake_input(t, b, x11rb::CURRENT_TIME, root, 0, 0, 0).ok();
            }
            (MSG_KEY, 6) => {
                let (ks, pressed) = (u32_at(&m, 1), m[5] != 0);
                if let Some(&kc) = keymap.get(&ks) {
                    let t = if pressed { xproto::KEY_PRESS_EVENT } else { xproto::KEY_RELEASE_EVENT };
                    conn.xtest_fake_input(t, kc, x11rb::CURRENT_TIME, root, 0, 0, 0).ok();
                } else {
                    eprintln!("no keycode for keysym 0x{:x}", ks);
                }
            }
            (k, n) => {
                eprintln!("bad message kind {} len {}", k, n);
                return Ok(());
            }
        }
        conn.flush().ok();
    }
}

fn handle_client(o: &Opts, key: &str, conn: &Arc<RustConnection>, root: xproto::Window, w: u16, h: u16,
                 shm: &Arc<Shm>, keymap: &Arc<HashMap<u32, u8>>, nvenc: bool, mut tx: TcpStream) {
    tx.set_nodelay(true).ok();
    tx.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let link = match Link::server(&mut tx, key) {
        Ok(l) => Arc::new(l),
        Err(e) => { eprintln!("handshake: {}", e); return; }
    };
    tx.set_read_timeout(None).ok();
    let mut hello = vec![MSG_HELLO];
    hello.extend_from_slice(&w.to_be_bytes());
    hello.extend_from_slice(&h.to_be_bytes());
    if link.send(&mut tx, &hello).is_err() { return; }

    let mut enc = spawn_encoder(w, h, o.fps, &o.bitrate, nvenc, "h264", None);
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
        let (conn, keymap, stop, link) = (conn.clone(), keymap.clone(), stop.clone(), link.clone());
        let rx = tx.try_clone().unwrap();
        thread::spawn(move || {
            let _ = handle_input(&conn, root, &keymap, &link, rx);
            stop.store(true, Ordering::Relaxed);
        })
    };

    // This thread: ffmpeg stdout -> socket.
    let mut buf = vec![0u8; 32 * 1024 + 1];
    buf[0] = MSG_VIDEO;
    while !stop.load(Ordering::Relaxed) {
        let n = match enc_out.read(&mut buf[1..]) { Ok(0) | Err(_) => break, Ok(n) => n };
        if link.send(&mut tx, &buf[..n + 1]).is_err() { break; }
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
    let key = key_from_args();
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
        handle_client(&o, &key, &conn, root, w, h, &shm, &keymap, nvenc, s);
        eprintln!("client gone");
    }
}

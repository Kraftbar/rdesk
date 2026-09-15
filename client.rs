//! rdesk-client: connect to rdesk-server, decode the H.264 stream with ffmpeg,
//! show it in a resizable window and send mouse/keyboard back.

mod proto;

use minifb::{Key, KeyRepeat, MouseButton, MouseMode, ScaleMode, Window, WindowOptions};
use proto::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let key = key_from_args();
    let addr = std::env::args().skip(1).find(|a| !a.starts_with("--") && a.contains(':'))
        .unwrap_or_else(|| { eprintln!("usage: rdesk-client HOST:PORT --key PASSPHRASE [--hwaccel d3d11va]"); std::process::exit(2) });
    let mut sock = TcpStream::connect(&addr).expect("connect");
    sock.set_nodelay(true).ok();
    let link = Arc::new(Link::client(&mut sock, &key).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) }));
    let hello = link.recv(&mut sock).expect("hello");
    assert!(hello.len() == 5 && hello[0] == MSG_HELLO, "expected HELLO");
    let w = u16_at(&hello, 1) as usize;
    let h = u16_at(&hello, 3) as usize;
    eprintln!("rdesk-client: {} is {}x{}", addr, w, h);

    // Single decode thread: frame-threading adds a frame of latency per thread.
    // --hwaccel d3d11va|dxva2|vaapi|cuda hands decoding to the GPU (frames still come back as bgra).
    let mut dec = Command::new(ffmpeg_path());
    dec.args(["-hide_banner", "-loglevel", "error", "-probesize", "32", "-analyzeduration", "0", "-flags", "low_delay"]);
    if let Some(hw) = arg_after("--hwaccel") { dec.args(["-hwaccel", &hw]); } else { dec.args(["-threads", "1"]); }
    dec.args(["-f", "h264", "-i", "pipe:0", "-fps_mode", "passthrough", "-f", "rawvideo", "-pix_fmt", "bgra", "pipe:1"]);
    let mut dec = dec.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn().expect("spawn ffmpeg");
    let mut dec_in = dec.stdin.take().unwrap();
    let mut dec_out = dec.stdout.take().unwrap();

    // Network -> decoder.
    let mut rx = sock.try_clone().unwrap();
    {
        let link = link.clone();
        thread::spawn(move || {
            loop {
                let m = match link.recv(&mut rx) { Ok(m) => m, Err(e) => { eprintln!("recv: {}", e); break } };
                if m.is_empty() || m[0] != MSG_VIDEO { eprintln!("bad message"); break; }
                if dec_in.write_all(&m[1..]).is_err() { break; }
            }
            eprintln!("connection closed");
            std::process::exit(0);
        });
    }

    // Decoder -> latest frame. Only the newest frame is kept so display never lags behind.
    let latest: Arc<Mutex<Option<Vec<u32>>>> = Arc::new(Mutex::new(None));
    {
        let latest = latest.clone();
        thread::spawn(move || {
            let t0 = std::time::Instant::now();
            let (mut n, mut total, mut t_stat) = (0u64, 0u64, t0);
            loop {
                let mut px = vec![0u32; w * h];
                let bytes = unsafe { std::slice::from_raw_parts_mut(px.as_mut_ptr() as *mut u8, w * h * 4) };
                if dec_out.read_exact(bytes).is_err() { eprintln!("decoder ended"); std::process::exit(0); }
                if total == 0 { eprintln!("first frame after {:?}", t0.elapsed()); }
                n += 1; total += 1;
                if t_stat.elapsed().as_secs() >= 5 { eprintln!("decode: {:.1} fps", n as f64 / t_stat.elapsed().as_secs_f64()); n = 0; t_stat = std::time::Instant::now(); }
                *latest.lock().unwrap() = Some(px);
            }
        });
    }

    let mut win = Window::new("rdesk", w / 2, h / 2, WindowOptions {
        resize: true,
        scale_mode: ScaleMode::AspectRatioStretch,
        ..Default::default()
    }).expect("window");
    win.set_target_fps(120);

    let mut frame = vec![0u32; w * h];
    let mut last_mouse = (u16::MAX, u16::MAX);
    let mut btn_state = [false; 3];
    let btns = [MouseButton::Left, MouseButton::Middle, MouseButton::Right];

    while win.is_open() {
        // Take the frame in its own statement so the mutex guard does not live through the redraw.
        let fresh = latest.lock().unwrap().take();
        if let Some(f) = fresh { frame = f; win.update_with_buffer(&frame, w, h).unwrap(); }
        else { win.update(); }

        // Mouse: map window coords back through the aspect-fit scaling.
        if let Some((mx, my)) = win.get_unscaled_mouse_pos(MouseMode::Pass) {
            let (ww, wh) = win.get_size();
            let scale = (ww as f32 / w as f32).min(wh as f32 / h as f32);
            let offx = (ww as f32 - w as f32 * scale) / 2.0;
            let offy = (wh as f32 - h as f32 * scale) / 2.0;
            let bx = ((mx - offx) / scale).round();
            let by = ((my - offy) / scale).round();
            if bx >= 0.0 && by >= 0.0 && bx < w as f32 && by < h as f32 {
                let p = (bx as u16, by as u16);
                if p != last_mouse {
                    last_mouse = p;
                    let mut m = vec![MSG_MOUSE_MOVE];
                    m.extend_from_slice(&p.0.to_be_bytes());
                    m.extend_from_slice(&p.1.to_be_bytes());
                    link.send(&mut sock, &m).ok();
                }
            }
        }
        for (i, b) in btns.iter().enumerate() {
            let down = win.get_mouse_down(*b);
            if down != btn_state[i] {
                btn_state[i] = down;
                link.send(&mut sock, &[MSG_MOUSE_BTN, i as u8 + 1, down as u8]).ok();
            }
        }
        if let Some((sx, sy)) = win.get_scroll_wheel() {
            // X11: 4/5 = wheel up/down, 6/7 = wheel left/right. Sign only; one notch per frame.
            let b = if sy > 0.0 { 4 } else if sy < 0.0 { 5 } else if sx < 0.0 { 6 } else if sx > 0.0 { 7 } else { 0 };
            if b != 0 {
                link.send(&mut sock, &[MSG_MOUSE_BTN, b, 1]).ok();
                link.send(&mut sock, &[MSG_MOUSE_BTN, b, 0]).ok();
            }
        }
        for k in win.get_keys_pressed(KeyRepeat::No) {
            if let Some(ks) = keysym(k) { send_key(&link, &mut sock, ks, true); }
        }
        for k in win.get_keys_released() {
            if let Some(ks) = keysym(k) { send_key(&link, &mut sock, ks, false); }
        }
    }
    let _ = dec.kill();
}

fn arg_after(flag: &str) -> Option<String> {
    let mut a = std::env::args().skip(1);
    while let Some(k) = a.next() { if k == flag { return a.next(); } }
    None
}

/// Prefer an ffmpeg sitting next to our own binary, else whatever PATH has.
fn ffmpeg_path() -> std::path::PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let local = exe.with_file_name(if cfg!(windows) { "ffmpeg.exe" } else { "ffmpeg" });
        if local.exists() { return local; }
    }
    "ffmpeg".into()
}

fn send_key(link: &Link, sock: &mut TcpStream, ks: u32, pressed: bool) {
    let mut m = vec![MSG_KEY];
    m.extend_from_slice(&ks.to_be_bytes());
    m.push(pressed as u8);
    link.send(sock, &m).ok();
}

/// minifb Key -> X11 keysym. US-centric: keys minifb has no name for (æøå etc.) are dropped.
fn keysym(k: Key) -> Option<u32> {
    use Key::*;
    Some(match k {
        Key0 => 0x30, Key1 => 0x31, Key2 => 0x32, Key3 => 0x33, Key4 => 0x34,
        Key5 => 0x35, Key6 => 0x36, Key7 => 0x37, Key8 => 0x38, Key9 => 0x39,
        A => 0x61, B => 0x62, C => 0x63, D => 0x64, E => 0x65, F => 0x66, G => 0x67, H => 0x68,
        I => 0x69, J => 0x6a, K => 0x6b, L => 0x6c, M => 0x6d, N => 0x6e, O => 0x6f, P => 0x70,
        Q => 0x71, R => 0x72, S => 0x73, T => 0x74, U => 0x75, V => 0x76, W => 0x77, X => 0x78,
        Y => 0x79, Z => 0x7a,
        F1 => 0xffbe, F2 => 0xffbf, F3 => 0xffc0, F4 => 0xffc1, F5 => 0xffc2, F6 => 0xffc3,
        F7 => 0xffc4, F8 => 0xffc5, F9 => 0xffc6, F10 => 0xffc7, F11 => 0xffc8, F12 => 0xffc9,
        F13 => 0xffca, F14 => 0xffcb, F15 => 0xffcc,
        Down => 0xff54, Left => 0xff51, Right => 0xff53, Up => 0xff52,
        Apostrophe => 0x27, Backquote => 0x60, Backslash => 0x5c, Comma => 0x2c, Equal => 0x3d,
        LeftBracket => 0x5b, Minus => 0x2d, Period => 0x2e, RightBracket => 0x5d, Semicolon => 0x3b,
        Slash => 0x2f, Backspace => 0xff08, Delete => 0xffff, End => 0xff57, Enter => 0xff0d,
        Escape => 0xff1b, Home => 0xff50, Insert => 0xff63, Menu => 0xff67, PageDown => 0xff56,
        PageUp => 0xff55, Pause => 0xff13, Space => 0x20, Tab => 0xff09, NumLock => 0xff7f,
        CapsLock => 0xffe5, ScrollLock => 0xff14, LeftShift => 0xffe1, RightShift => 0xffe2,
        LeftCtrl => 0xffe3, RightCtrl => 0xffe4, LeftAlt => 0xffe9, RightAlt => 0xffea,
        LeftSuper => 0xffeb, RightSuper => 0xffec,
        NumPad0 => 0xffb0, NumPad1 => 0xffb1, NumPad2 => 0xffb2, NumPad3 => 0xffb3, NumPad4 => 0xffb4,
        NumPad5 => 0xffb5, NumPad6 => 0xffb6, NumPad7 => 0xffb7, NumPad8 => 0xffb8, NumPad9 => 0xffb9,
        NumPadDot => 0xffae, NumPadSlash => 0xffaf, NumPadAsterisk => 0xffaa, NumPadMinus => 0xffad,
        NumPadPlus => 0xffab, NumPadEnter => 0xff8d,
        _ => return None,
    })
}

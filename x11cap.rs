//! X11 capture helpers shared by the binaries: XShm screen grab, cursor overlay,
//! ffmpeg encoder spawning and keysym lookup.

#![allow(dead_code)]

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use x11rb::connection::Connection;
use x11rb::protocol::shm::{self, ConnectionExt as _};
use x11rb::protocol::xfixes::GetCursorImageReply;
use x11rb::protocol::xproto::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

/// A SysV shared-memory segment attached to both us and the X server.
pub struct Shm {
    pub seg: shm::Seg,
    pub ptr: *mut u8,
    pub len: usize,
}
unsafe impl Send for Shm {}
unsafe impl Sync for Shm {}

impl Shm {
    pub fn new(conn: &RustConnection, len: usize) -> Shm {
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
    pub fn buf(&self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

pub fn probe_nvenc() -> bool {
    Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", "color=size=256x256:rate=1",
               "-frames:v", "1", "-c:v", "h264_nvenc", "-f", "null", "-"])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

/// `container` is "h264" (raw Annex-B) or "avi" (one RIFF chunk per frame, exact sizes).
pub fn spawn_encoder(w: u16, h: u16, fps: u32, bitrate: &str, nvenc: bool, container: &str) -> Child {
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
    c.args(["-f", container, "-flush_packets", "1", "pipe:1"]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    c.spawn().expect("spawn ffmpeg")
}

/// Alpha-blend the (premultiplied ARGB) cursor image onto a BGRA frame.
pub fn draw_cursor(frame: &mut [u8], fw: usize, fh: usize, cur: &GetCursorImageReply) {
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
pub fn build_keymap(conn: &RustConnection) -> HashMap<u32, u8> {
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


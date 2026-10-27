//! Cold-boot login through a LightDM greeter wrapper. No password is stored or
//! typed into X: LightDM runs the normal PAM conversation and owns the session.

use anyhow::{Context, ensure};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use x11rb::protocol::randr::{ConnectionExt as _, Rotation, SetConfig};
use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _, Window};
use x11rb::rust_connection::RustConnection;

const SOCKET: &str = "/run/rdesk-login/greeter.sock";

/// None means no running greeter bridge (normally an existing user session).
/// Some means PAM succeeded; prepare_desktop must still confirm session start.
pub fn login(user: &str, password: &str) -> anyhow::Result<Option<()>> {
    let mut stream = match UnixStream::connect(SOCKET) {
        Ok(s) => s,
        Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => return Ok(None),
        Err(e) => return Err(e).context("connect to greeter bridge"),
    };
    // Socket directory is installed as lightdm:lightdm 0755. Check the actual
    // peer as well, before sending credentials to a local process.
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&peer) as libc::socklen_t;
    ensure!(unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
                        &mut peer as *mut _ as *mut libc::c_void, &mut len)
    } == 0, "cannot identify greeter peer");
    let account = std::ffi::CString::new("lightdm")?;
    let pw = unsafe { libc::getpwnam(account.as_ptr()) };
    ensure!(!pw.is_null() && peer.uid == unsafe { (*pw).pw_uid }, "unexpected greeter peer");
    stream.set_read_timeout(Some(Duration::from_secs(25)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    ensure!(!password.is_empty() && !password.contains('\0') && password.len() <= 2048, "invalid password length/encoding");
    ensure!(!user.contains('\0') && user.len() <= 256, "invalid username");
    for s in [user, password] {
        stream.write_all(&(s.len() as u32).to_be_bytes())?;
        stream.write_all(s.as_bytes())?;
    }
    let mut status = [0u8];
    stream.read_exact(&mut status).context("greeter did not confirm authentication")?;
    match status[0] {
        0 => Ok(Some(())),
        1 => anyhow::bail!("LightDM rejected authentication or session start"),
        2 => anyhow::bail!("PAM needs an interactive response; use the local login screen"),
        _ => anyhow::bail!("greeter busy or request timed out"),
    }
}

pub fn desktop_ready(conn: &RustConnection, root: Window) -> anyhow::Result<bool> {
    let wm_atom = conn.intern_atom(false, b"_NET_SUPPORTING_WM_CHECK")?.reply()?.atom;
    let name_atom = conn.intern_atom(false, b"_NET_WM_NAME")?.reply()?.atom;
    let prop = conn.get_property(false, root, wm_atom, AtomEnum::WINDOW, 0, 1)?.reply()?;
    let Some(wm) = prop.value32().and_then(|mut v| v.next()) else { return Ok(false) };
    let name = conn.get_property(false, wm, name_atom, AtomEnum::ANY, 0, 256)?.reply()?;
    let name = String::from_utf8_lossy(&name.value).to_lowercase();
    Ok(name.contains("muffin") || name.contains("cinnamon"))
}

/// Wait for Cinnamon after a greeter login. The mode is set later, in
/// `settle_mode`, once the client's desktop size is known.
pub fn prepare_desktop(conn: &RustConnection, root: Window) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !desktop_ready(conn, root).unwrap_or(false) {
        ensure!(Instant::now() < deadline, "Cinnamon did not become ready within 20 seconds");
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// Switch the freshly logged-in desktop to the monitor mode that best fits the
/// client: its exact size if the monitor has it, else the largest mode inside
/// it (the rest is scaled). Cinnamon's settings daemon can restore its saved
/// monitor configuration just after the WM appears, so hold it for 3 s.
pub fn settle_mode(conn: &RustConnection, root: Window, want_w: u16, want_h: u16) -> anyhow::Result<()> {
    let (tw, th) = best_mode(conn, root, want_w, want_h)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut stable = Instant::now();
    loop {
        ensure!(Instant::now() < deadline, "{}x{} mode did not settle", tw, th);
        let geo = conn.get_geometry(root)?.reply()?;
        if (geo.width, geo.height) != (tw, th) {
            set_mode(conn, root, tw, th)?;
            stable = Instant::now();
        } else if stable.elapsed() >= Duration::from_secs(3) {
            tracing::info!("cold-boot desktop ready at {}x{} (client asked {}x{})", tw, th, want_w, want_h);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The advertised mode of the single active output that fits the client best.
fn best_mode(conn: &RustConnection, root: Window, want_w: u16, want_h: u16) -> anyhow::Result<(u16, u16)> {
    conn.randr_query_version(1, 3)?.reply()?;
    let res = conn.randr_get_screen_resources_current(root)?.reply()?;
    let mut outputs = Vec::new();
    for crtc in &res.crtcs {
        let info = conn.randr_get_crtc_info(*crtc, res.config_timestamp)?.reply()?;
        if info.mode != 0 { outputs.extend(info.outputs); }
    }
    ensure!(outputs.len() == 1, "cold-boot mode requires one active monitor");
    let output = conn.randr_get_output_info(outputs[0], res.config_timestamp)?.reply()?;
    let sizes: Vec<(u16, u16)> = res.modes.iter().filter(|m| output.modes.contains(&m.id)).map(|m| (m.width, m.height)).collect();
    if sizes.contains(&(want_w, want_h)) { return Ok((want_w, want_h)); }
    sizes.iter().copied().filter(|&(w, h)| w <= want_w && h <= want_h)
        .max_by_key(|&(w, h)| w as u32 * h as u32)
        .or_else(|| sizes.iter().copied().min_by_key(|&(w, h)| w as u32 * h as u32))
        .context("monitor advertises no modes")
}

/// Kept for the nested-X test.
#[cfg_attr(not(test), allow(dead_code))]
pub fn set_1080p(conn: &RustConnection, root: Window) -> anyhow::Result<()> {
    set_mode(conn, root, 1920, 1080)
}

/// Exactly one unrotated active output, switched to an advertised w x h mode.
/// Use the existing X connection (the server has dropped root and cannot
/// reopen LightDM's root-owned Xauthority file).
pub fn set_mode(conn: &RustConnection, root: Window, want_w: u16, want_h: u16) -> anyhow::Result<()> {
    conn.randr_query_version(1, 3)?.reply()?;
    let res = conn.randr_get_screen_resources_current(root)?.reply()?;
    let mut active = Vec::new();
    for crtc in &res.crtcs {
        let info = conn.randr_get_crtc_info(*crtc, res.config_timestamp)?.reply()?;
        if info.mode != 0 { active.push((*crtc, info)); }
    }
    ensure!(active.len() == 1, "cold-boot mode requires one active monitor");
    let (crtc, old) = &active[0];
    ensure!(old.outputs.len() == 1 && old.rotation == Rotation::ROTATE0, "cloned/rotated monitors are not supported by cold-boot mode");
    let output = conn.randr_get_output_info(old.outputs[0], res.config_timestamp)?.reply()?;
    let mode = output.modes.iter().find(|id| res.modes.iter().any(|m| m.id == **id && m.width == want_w && m.height == want_h))
        .copied().with_context(|| format!("monitor does not advertise {}x{}", want_w, want_h))?;
    let geo = conn.get_geometry(root)?.reply()?;
    // Grow first if necessary; shrink only once the smaller CRTC fits.
    let grow = geo.width < want_w || geo.height < want_h;
    if grow {
        conn.randr_set_screen_size(root, geo.width.max(want_w), geo.height.max(want_h), 508, 286)?.check()?;
    }
    let result = conn.randr_set_crtc_config(*crtc, 0, res.config_timestamp, 0, 0, mode, old.rotation, &old.outputs)?.reply()?;
    if result.status != SetConfig::SUCCESS {
        if grow { let _ = conn.randr_set_screen_size(root, geo.width, geo.height, 508, 286)?.check(); }
        anyhow::bail!("RandR rejected {}x{}: {:?}", want_w, want_h, result.status);
    }
    if let Err(e) = conn.randr_set_screen_size(root, want_w, want_h, (want_w as u32 * 254 / 960) as u32, (want_h as u32 * 254 / 960) as u32)?.check() {
        // Leave a usable display if the driver rejects the framebuffer resize.
        let _ = conn.randr_set_crtc_config(*crtc, 0, 0, old.x, old.y, old.mode, old.rotation, &old.outputs)?.reply();
        return Err(e).context("set framebuffer size");
    }
    tracing::info!("set shared desktop to {}x{}", want_w, want_h);
    Ok(())
}

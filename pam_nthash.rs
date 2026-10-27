//! rdesk-nthash USER: pam_exec hook (auth, expose_authtok) that keeps USER's
//! ~/.config/rdesk/nthash current, so NLA works without setting anything up.
//! Runs as root (LightDM, sudo) or as the user (screensaver). Silent, always
//! exits 0, and only stores a password unix_chkpwd accepts.

mod nthash;

use std::io::Read;

fn main() {
    let _ = run();
}

fn run() -> Option<()> {
    let user = std::env::args().nth(1)?;
    if std::env::var("PAM_TYPE").ok()? != "auth" || std::env::var("PAM_USER").ok()? != user { return None }
    let mut buf = Vec::new();
    std::io::stdin().take(4096).read_to_end(&mut buf).ok()?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let pass = String::from_utf8(buf[..end].to_vec()).ok()?;
    if pass.is_empty() || !nthash::check(&user, &pass) { return None }

    let pw = unsafe { libc::getpwnam(std::ffi::CString::new(user.as_str()).ok()?.as_ptr()) };
    if pw.is_null() { return None }
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    let home = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) }.to_str().ok()?.to_owned();
    // Write as the user, never as root into a directory the user owns.
    unsafe {
        if libc::geteuid() == 0 {
            if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 { return None }
        } else if libc::geteuid() != uid {
            return None;
        }
    }
    nthash::store(&std::path::Path::new(&home).join(".config/rdesk/nthash"), &pass).ok()?;
    Some(())
}

//! NT hash of the Linux password, for NLA. /etc/shadow's crypt hash cannot be
//! turned into one, so it is caught whenever the password is typed anyway: the
//! rdesk-nthash PAM hook (login screen, unlock, sudo) and successful RDP logins.
//! MD4(UTF-16LE(password)) is password-equivalent for NTLM: 0600, owner only.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn hash(pass: &str) -> String {
    use md4::{Digest, Md4};
    let utf16: Vec<u8> = pass.encode_utf16().flat_map(u16::to_le_bytes).collect();
    Md4::digest(&utf16).iter().map(|b| format!("{:02x}", b)).collect()
}

/// The stored hash, if the file holds one.
pub fn read(path: &Path) -> Option<String> {
    let h = std::fs::read_to_string(path).ok()?;
    let h = h.trim();
    (h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit())).then(|| h.to_lowercase())
}

/// Checks `pass` for `user` (as root or as that user).
pub fn check(user: &str, pass: &str) -> bool {
    let Ok(mut child) = Command::new("/sbin/unix_chkpwd").args([user, "nullok"])
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() else { return false };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(pass.as_bytes());
        let _ = si.write_all(&[0]);
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// Writes the hash of an already checked password; true when the file changed.
pub fn store(path: &Path, pass: &str) -> std::io::Result<bool> {
    let hex = hash(pass);
    if read(path).as_deref() == Some(hex.as_str()) { return Ok(false) }
    if let Some(dir) = path.parent() { std::fs::create_dir_all(dir)?; }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
    f.write_all(format!("{}\n", hex).as_bytes())?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

//! Wire format shared by server and client.
//!
//! Transport: TCP, Noise NNpsk0 handshake keyed by a shared passphrase, then
//! every message is `u16 len || ciphertext` (ChaCha20-Poly1305, <= 65535 bytes).
//! Plaintext messages, integers big-endian:
//!
//! server -> client
//!   HELLO  u16 width, u16 height
//!   VIDEO  H.264 Annex-B bytes (arbitrary chunking)
//! client -> server
//!   MOUSE_MOVE  u16 x, u16 y            absolute, in server pixels
//!   MOUSE_BTN   u8 button, u8 pressed   X11 button numbers (1..7)
//!   KEY         u32 keysym, u8 pressed  X11 keysym

#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::sync::Mutex;

pub const MSG_HELLO: u8 = 0;
pub const MSG_VIDEO: u8 = 1;
pub const MSG_MOUSE_MOVE: u8 = 2;
pub const MSG_MOUSE_BTN: u8 = 3;
pub const MSG_KEY: u8 = 4;

/// Largest plaintext that fits one Noise message (65535 minus the 16-byte tag).
pub const MAX_PLAIN: usize = 65535 - 16;

const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

pub fn key_from_args() -> String {
    let mut a = std::env::args().skip(1);
    while let Some(k) = a.next() {
        if k == "--key" { return a.next().expect("--key PASSPHRASE"); }
    }
    std::env::var("RDESK_KEY").unwrap_or_else(|_| {
        eprintln!("no key: pass --key PASSPHRASE or set RDESK_KEY (must match on both ends)");
        std::process::exit(2);
    })
}

fn psk(pass: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"rdesk-psk-v1\0");
    h.update(pass.as_bytes());
    h.finalize().into()
}

fn bad(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn write_frame(w: &mut impl Write, ct: &[u8]) -> io::Result<()> {
    let mut v = Vec::with_capacity(2 + ct.len());
    v.extend_from_slice(&(ct.len() as u16).to_be_bytes());
    v.extend_from_slice(ct);
    w.write_all(&v)
}

fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l)?;
    let mut ct = vec![0u8; u16::from_be_bytes(l) as usize];
    r.read_exact(&mut ct)?;
    Ok(ct)
}

/// Encrypted, authenticated message channel. One thread may `send` while
/// another `recv`s; the lock is only held for the crypto, not the socket I/O.
pub struct Link {
    ts: Mutex<snow::TransportState>,
}

impl Link {
    pub fn client(sock: &mut (impl Read + Write), pass: &str) -> io::Result<Link> {
        let mut hs = snow::Builder::new(PATTERN.parse().unwrap())
            .psk(0, &psk(pass)).build_initiator().map_err(bad)?;
        let mut buf = vec![0u8; 1024];
        let n = hs.write_message(&[], &mut buf).map_err(bad)?;
        write_frame(sock, &buf[..n])?;
        let msg = read_frame(sock)?;
        hs.read_message(&msg, &mut buf).map_err(|_| bad("handshake failed: wrong key?"))?;
        Ok(Link { ts: Mutex::new(hs.into_transport_mode().map_err(bad)?) })
    }

    pub fn server(sock: &mut (impl Read + Write), pass: &str) -> io::Result<Link> {
        let mut hs = snow::Builder::new(PATTERN.parse().unwrap())
            .psk(0, &psk(pass)).build_responder().map_err(bad)?;
        let mut buf = vec![0u8; 1024];
        let msg = read_frame(sock)?;
        hs.read_message(&msg, &mut buf).map_err(|_| bad("handshake failed: wrong key?"))?;
        let n = hs.write_message(&[], &mut buf).map_err(bad)?;
        write_frame(sock, &buf[..n])?;
        Ok(Link { ts: Mutex::new(hs.into_transport_mode().map_err(bad)?) })
    }

    pub fn send(&self, sock: &mut impl Write, plain: &[u8]) -> io::Result<()> {
        assert!(plain.len() <= MAX_PLAIN);
        let mut ct = vec![0u8; plain.len() + 16];
        let n = self.ts.lock().unwrap().write_message(plain, &mut ct).map_err(bad)?;
        write_frame(sock, &ct[..n])
    }

    pub fn recv(&self, sock: &mut impl Read) -> io::Result<Vec<u8>> {
        let ct = read_frame(sock)?;
        let mut plain = vec![0u8; ct.len()];
        let n = self.ts.lock().unwrap().read_message(&ct, &mut plain).map_err(|_| bad("bad MAC"))?;
        plain.truncate(n);
        Ok(plain)
    }
}

pub fn u16_at(m: &[u8], i: usize) -> u16 { u16::from_be_bytes([m[i], m[i + 1]]) }
pub fn u32_at(m: &[u8], i: usize) -> u32 { u32::from_be_bytes([m[i], m[i + 1], m[i + 2], m[i + 3]]) }

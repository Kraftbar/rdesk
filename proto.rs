//! Wire format shared by server and client. Everything is big-endian.
//!
//! server -> client
//!   HELLO  u16 width, u16 height
//!   VIDEO  u32 len, len bytes of H.264 Annex-B (arbitrary chunking)
//! client -> server
//!   MOUSE_MOVE  u16 x, u16 y            absolute, in server pixels
//!   MOUSE_BTN   u8 button, u8 pressed   X11 button numbers (1..7)
//!   KEY         u32 keysym, u8 pressed  X11 keysym

#![allow(dead_code)]

use std::io::{self, Read, Write};

pub const MSG_HELLO: u8 = 0;
pub const MSG_VIDEO: u8 = 1;
pub const MSG_MOUSE_MOVE: u8 = 2;
pub const MSG_MOUSE_BTN: u8 = 3;
pub const MSG_KEY: u8 = 4;

pub fn read_u8(r: &mut impl Read) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

pub fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

pub fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

/// Small fixed-size messages (everything except VIDEO).
pub fn send_msg(w: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    let mut v = Vec::with_capacity(1 + payload.len());
    v.push(kind);
    v.extend_from_slice(payload);
    w.write_all(&v)
}

pub fn send_video(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = MSG_VIDEO;
    hdr[1..5].copy_from_slice(&(data.len() as u32).to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(data)
}

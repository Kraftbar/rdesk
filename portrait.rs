//! Temporarily expose a portrait X desktop through the monitor's RandR scaling
//! transform. Capture sees the logical desktop, before physical monitor scaling.

use anyhow::{Context, ensure};
use std::sync::Arc;
use x11rb::connection::Connection;
use x11rb::protocol::randr::{ConnectionExt as _, Crtc, GetCrtcInfoReply, Rotation, SetConfig};
use x11rb::protocol::render::Transform;
use x11rb::protocol::xproto::{ConnectionExt as _, Window};
use x11rb::rust_connection::RustConnection;

pub fn phone_size(w: u16, h: u16) -> bool {
    (320..=1600).contains(&w) && h > w && h <= 3200
}

fn scale(w: u16, h: u16, mode_w: u16, mode_h: u16) -> Transform {
    // RandR uses signed 16.16 fixed point. Floor, as xrandr --scale-from does,
    // so rounding cannot put the output past the logical framebuffer's edge.
    Transform {
        matrix11: ((w as i64 * 65536) / mode_w as i64) as i32,
        matrix22: ((h as i64 * 65536) / mode_h as i64) as i32,
        matrix33: 65536,
        ..Default::default()
    }
}

struct ServerGrab<'a>(&'a RustConnection);
impl Drop for ServerGrab<'_> {
    fn drop(&mut self) {
        let _ = self.0.ungrab_server();
        let _ = self.0.flush();
    }
}

pub struct PhoneDesktop {
    conn: Arc<RustConnection>,
    root: Window,
    crtc: Crtc,
    original: GetCrtcInfoReply,
    dimensions: (u16, u16),
    millimeters: (u32, u32),
    transform: Transform,
    filter: Vec<u8>,
    params: Vec<i32>,
    restore_needed: bool,
}

impl PhoneDesktop {
    pub fn start(conn: Arc<RustConnection>, root: Window, w: u16, h: u16) -> anyhow::Result<Option<Self>> {
        ensure!(phone_size(w, h), "outside supported portrait size range");
        let geo = conn.get_geometry(root)?.reply()?;
        if (geo.width, geo.height) == (w, h) { return Ok(None); }
        conn.randr_query_version(1, 3)?.reply()?;
        let range = conn.randr_get_screen_size_range(root)?.reply()?;
        ensure!(w >= range.min_width && h >= range.min_height && w <= range.max_width && h <= range.max_height,
                "portrait desktop exceeds driver size range");
        let resources = conn.randr_get_screen_resources_current(root)?.reply()?;
        let mut active = Vec::new();
        for crtc in &resources.crtcs {
            let info = conn.randr_get_crtc_info(*crtc, resources.config_timestamp)?.reply()?;
            if info.mode != 0 { active.push((*crtc, info)); }
        }
        ensure!(active.len() == 1, "portrait desktop needs one active monitor");
        let (crtc, original) = active.pop().unwrap();
        ensure!(original.outputs.len() == 1 && original.rotation == Rotation::ROTATE0,
                "portrait desktop does not support cloned/rotated monitors");
        let mode = resources.modes.iter().find(|m| m.id == original.mode).context("current mode missing")?;
        ensure!(mode.width > 0 && mode.height > 0, "empty monitor mode");
        let transform = conn.randr_get_crtc_transform(crtc)?.reply()?;
        ensure!(transform.has_transforms, "driver does not support display transforms");
        let pan = conn.randr_get_panning(crtc)?.reply()?;
        ensure!(pan.width == 0 && pan.height == 0, "disable RandR panning before portrait mode");
        let screen = conn.randr_get_screen_info(root)?.reply()?;
        let physical = screen.sizes.get(screen.size_id as usize).context("current screen size missing")?;
        let mut saved = Self {
            conn, root, crtc, original,
            dimensions: (geo.width, geo.height),
            millimeters: (physical.mwidth.into(), physical.mheight.into()),
            transform: transform.current_transform,
            filter: transform.current_filter_name, params: transform.current_params,
            restore_needed: true,
        };
        let new_transform = scale(w, h, mode.width, mode.height);
        // Apply at 96 DPI. Full original geometry, mode, refresh, transform and
        // physical dimensions are saved, rather than guessing a restore mode.
        if let Err(e) = saved.apply(w, h, (w as u32 * 254 / 960, h as u32 * 254 / 960), 0, 0,
                                   new_transform, b"bilinear", &[]) {
            if let Err(restore) = saved.restore() { tracing::error!("portrait rollback: {:#}", restore); }
            return Err(e);
        }
        tracing::info!("portrait desktop {}x{} (saved {}x{})", w, h, geo.width, geo.height);
        Ok(Some(saved))
    }

    fn apply(&self, w: u16, h: u16, mm: (u32, u32), x: i16, y: i16,
             transform: Transform, filter: &[u8], params: &[i32]) -> anyhow::Result<()> {
        // Keep other X clients from observing intermediate disabled/output
        // sizes while the framebuffer and transform change as a unit.
        self.conn.grab_server()?.check()?;
        let _grab = ServerGrab(&self.conn);
        let off = self.conn.randr_set_crtc_config(self.crtc, 0, 0, 0, 0, 0, Rotation::ROTATE0, &[])?.reply()?;
        ensure!(off.status == SetConfig::SUCCESS, "driver refused temporary output disable");
        self.conn.randr_set_screen_size(self.root, w, h, mm.0.max(1), mm.1.max(1))?.check()?;
        self.conn.randr_set_crtc_transform(self.crtc, transform, filter, params)?.check()?;
        let on = self.conn.randr_set_crtc_config(self.crtc, 0, 0, x, y, self.original.mode,
                                               self.original.rotation, &self.original.outputs)?.reply()?;
        ensure!(on.status == SetConfig::SUCCESS, "driver rejected portrait transform: {:?}", on.status);
        let actual = self.conn.get_geometry(self.root)?.reply()?;
        ensure!((actual.width, actual.height) == (w, h), "driver did not retain {}x{} framebuffer", w, h);
        Ok(())
    }

    pub fn restore(&mut self) -> anyhow::Result<()> {
        if self.restore_needed {
            self.apply(self.dimensions.0, self.dimensions.1, self.millimeters,
                       self.original.x, self.original.y, self.transform, &self.filter, &self.params)?;
            self.restore_needed = false;
            tracing::info!("restored desktop to {}x{}", self.dimensions.0, self.dimensions.1);
        }
        Ok(())
    }
}

impl Drop for PhoneDesktop {
    fn drop(&mut self) {
        if let Err(e) = self.restore() { tracing::error!("restore portrait desktop: {:#}", e); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x11rb::x11_utils::Serialize;

    #[test]
    fn only_bounded_portrait_clients_change_host_size() {
        assert!(phone_size(992, 1850));
        assert!(!phone_size(1920, 1080));
        assert!(!phone_size(1080, 1080));
        assert!(!phone_size(0, 1850));
        assert!(!phone_size(992, u16::MAX));
    }

    #[test]
    fn transform_does_not_extend_past_phone_framebuffer() {
        for (mw, mh) in [(1920, 1080), (3440, 1440)] {
            let t = scale(992, 1850, mw, mh);
            let right = t.matrix11 as f64 * mw as f64 / 65536.0;
            let bottom = t.matrix22 as f64 * mh as f64 / 65536.0;
            assert!(right <= 992.0 && right > 991.9);
            assert!(bottom <= 1850.0 && bottom > 1849.9);
            assert_eq!(t.matrix33, 65536);
        }
    }

    #[test]
    #[ignore = "temporarily resizes a real display; needs RDESK_ALLOW_DISPLAY_TEST=1"]
    fn live_portrait_round_trip() -> anyhow::Result<()> {
        ensure!(std::env::var("RDESK_ALLOW_DISPLAY_TEST").as_deref() == Ok("1"), "display test must be explicitly enabled");
        let (conn, sn) = x11rb::connect(None)?;
        let conn = Arc::new(conn);
        let root = conn.setup().roots[sn].root;
        let before = conn.get_geometry(root)?.reply()?;
        let saved = PhoneDesktop::start(conn.clone(), root, 992, 1850)?.context("display already at phone size")?;
        std::thread::sleep(std::time::Duration::from_secs(1));
        let actual = conn.get_geometry(root)?.reply()?;
        ensure!((actual.width, actual.height) == (992, 1850), "portrait geometry was overridden");
        let crtc = saved.crtc;
        let mode = saved.original.mode;
        let transform = saved.transform.serialize();
        let filter = saved.filter.clone();
        let params = saved.params.clone();
        let before_pointer = conn.query_pointer(root)?.reply()?;
        let pointer_check = (|| -> anyhow::Result<()> {
            for (x, y) in [(10i16, 10i16), (496, 925), (970, 1820)] {
                conn.warp_pointer(0u32, root, 0, 0, 0, 0, x, y)?.check()?;
                let p = conn.query_pointer(root)?.reply()?;
                ensure!((p.root_x, p.root_y) == (x, y), "pointer is constrained or scaled: {},{}", p.root_x, p.root_y);
            }
            Ok(())
        })();
        let _ = conn.warp_pointer(0u32, root, 0, 0, 0, 0, before_pointer.root_x, before_pointer.root_y)?.check();
        pointer_check?;
        // Same Drop path used at RDP disconnect and graceful shutdown.
        drop(saved);
        let after = conn.get_geometry(root)?.reply()?;
        ensure!((after.width, after.height) == (before.width, before.height), "desktop geometry was not restored");
        let restored = conn.randr_get_crtc_transform(crtc)?.reply()?;
        ensure!(restored.current_transform.serialize() == transform, "transform was not restored");
        ensure!(restored.current_filter_name == filter && restored.current_params == params, "filter was not restored");
        ensure!(conn.randr_get_crtc_info(crtc, 0)?.reply()?.mode == mode, "monitor mode was not restored");
        Ok(())
    }
}

//! Text clipboard between the RDP client and the X CLIPBOARD selection.
//!
//! One thread owns its own X connection (opened before rdesk drops root, like
//! the capture connection) and a hidden window. It watches CLIPBOARD owner
//! changes with XFixes and tells the client when there is local text; a paste
//! on the client reads CLIPBOARD as UTF8_STRING. A copy on the client is
//! fetched at once as CF_UNICODETEXT and the window takes CLIPBOARD, serving
//! it to local apps. Text only: no images, no files, no INCR transfers.

use ironrdp_cliprdr::backend::{ClipboardMessage, CliprdrBackend, CliprdrBackendFactory};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse,
    FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_core::IntoOwned as _;
use ironrdp_server::{CliprdrServerFactory, ServerEvent, ServerEventSender};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xfixes::{ConnectionExt as _, SelectionEventMask};
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, SelectionNotifyEvent,
    SELECTION_NOTIFY_EVENT, Window, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::CURRENT_TIME;

const TEXT: ClipboardFormatId = ClipboardFormatId::CF_UNICODETEXT;

enum Cmd {
    /// Client connected: offer local text if there is any.
    Announce,
    /// Client pastes: send it our CLIPBOARD text.
    Fetch,
    /// Client copied this text: own CLIPBOARD with it.
    Own(String),
}

#[derive(Default)]
struct Shared {
    ev: Mutex<Option<UnboundedSender<ServerEvent>>>,
}

impl Shared {
    fn send(&self, m: ClipboardMessage) {
        if let Some(tx) = self.ev.lock().unwrap().as_ref() {
            let _ = tx.send(ServerEvent::Clipboard(m));
        }
    }
}

pub struct ClipFactory {
    shared: Arc<Shared>,
    cmd: Sender<Cmd>,
}

impl ClipFactory {
    /// Start the X side. `display` None = $DISPLAY/$XAUTHORITY, so call this
    /// before dropping root when running as the system service.
    pub fn start(display: Option<&str>) -> anyhow::Result<ClipFactory> {
        let (conn, screen) = x11rb::connect(display)?;
        let shared = Arc::new(Shared::default());
        let (tx, rx) = channel();
        let s = shared.clone();
        std::thread::Builder::new().name("clipboard".into()).spawn(move || {
            if let Err(e) = x_loop(conn, screen, rx, s) { warn!("clipboard: {:#}", e); }
        })?;
        Ok(ClipFactory { shared, cmd: tx })
    }
}

impl ServerEventSender for ClipFactory {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self.shared.ev.lock().unwrap() = Some(sender);
    }
}

impl CliprdrBackendFactory for ClipFactory {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        Box::new(Backend { shared: self.shared.clone(), cmd: self.cmd.clone() })
    }
}

impl CliprdrServerFactory for ClipFactory {}

#[derive(Debug)]
struct Backend {
    shared: Arc<Shared>,
    cmd: Sender<Cmd>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Shared") }
}

ironrdp_core::impl_as_any!(Backend);

impl CliprdrBackend for Backend {
    fn temporary_directory(&self) -> &str { "/tmp" }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags { ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES }
    fn on_ready(&mut self) { let _ = self.cmd.send(Cmd::Announce); }
    fn on_request_format_list(&mut self) { let _ = self.cmd.send(Cmd::Announce); }
    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        if formats.iter().any(|f| f.id == TEXT) {
            self.shared.send(ClipboardMessage::SendInitiatePaste(TEXT));
        }
    }
    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        if request.format == TEXT {
            let _ = self.cmd.send(Cmd::Fetch);
        } else {
            self.shared.send(ClipboardMessage::SendFormatData(FormatDataResponse::new_error().into_owned()));
        }
    }
    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() { return; }
        let units: Vec<u16> = response.data().chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        let text = String::from_utf16_lossy(&units[..end]).replace("\r\n", "\n");
        let _ = self.cmd.send(Cmd::Own(text));
    }
    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _: LockDataId) {}
    fn on_unlock(&mut self, _: LockDataId) {}
}

fn utf16_text(s: &str) -> Vec<u8> {
    s.replace("\r\n", "\n").replace('\n', "\r\n").encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

fn x_loop(conn: RustConnection, screen: usize, rx: Receiver<Cmd>, shared: Arc<Shared>) -> anyhow::Result<()> {
    let root = conn.setup().roots[screen].root;
    let atom = |name: &str| -> anyhow::Result<Atom> { Ok(conn.intern_atom(false, name.as_bytes())?.reply()?.atom) };
    let (clipboard, utf8, targets, text_atom, prop) =
        (atom("CLIPBOARD")?, atom("UTF8_STRING")?, atom("TARGETS")?, atom("TEXT")?, atom("RDESK_CLIP")?);
    let win: Window = conn.generate_id()?;
    conn.create_window(0, win, root, -10, -10, 1, 1, 0, WindowClass::INPUT_ONLY, 0,
        &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE))?;
    conn.xfixes_query_version(5, 0)?.reply()?;
    conn.xfixes_select_selection_input(win, clipboard, SelectionEventMask::SET_SELECTION_OWNER)?;
    conn.flush()?;
    info!("clipboard ready (text)");

    let mut ours: Option<String> = None;
    let mut fetch_deadline: Option<Instant> = None;
    let offer = |ours: &Option<String>| {
        // Local text exists and is not the client's own copy coming back.
        if ours.is_none() {
            shared.send(ClipboardMessage::SendInitiateCopy(vec![ClipboardFormat::new(TEXT)]));
        }
    };
    loop {
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                Cmd::Announce => {
                    let owner = conn.get_selection_owner(clipboard)?.reply()?.owner;
                    if owner != 0 && owner != win { offer(&ours); }
                }
                Cmd::Fetch => match &ours {
                    Some(t) => shared.send(ClipboardMessage::SendFormatData(FormatDataResponse::new_data(utf16_text(t)).into_owned())),
                    None => {
                        conn.convert_selection(win, clipboard, utf8, prop, CURRENT_TIME)?;
                        conn.flush()?;
                        fetch_deadline = Some(Instant::now() + Duration::from_secs(2));
                    }
                },
                Cmd::Own(t) => {
                    ours = Some(t);
                    conn.set_selection_owner(win, clipboard, CURRENT_TIME)?;
                    conn.flush()?;
                }
            }
        }
        if fetch_deadline.is_some_and(|d| Instant::now() > d) {
            fetch_deadline = None;
            shared.send(ClipboardMessage::SendFormatData(FormatDataResponse::new_error().into_owned()));
        }
        let Some(event) = conn.poll_for_event()? else {
            std::thread::sleep(Duration::from_millis(20));
            continue;
        };
        match event {
            Event::XfixesSelectionNotify(e) if e.selection == clipboard => {
                if e.owner != win && e.owner != 0 {
                    ours = None;
                    offer(&ours);
                }
            }
            Event::SelectionClear(e) if e.selection == clipboard => ours = None,
            Event::SelectionNotify(e) if e.selection == clipboard && fetch_deadline.is_some() => {
                fetch_deadline = None;
                let data = if e.property == 0 { None } else {
                    let r = conn.get_property(true, win, prop, AtomEnum::ANY, 0, 16 << 20)?.reply()?;
                    (r.type_ == utf8 || r.type_ == u32::from(AtomEnum::STRING)).then_some(r.value)
                };
                let resp = match data {
                    Some(v) => FormatDataResponse::new_data(utf16_text(&String::from_utf8_lossy(&v))),
                    None => FormatDataResponse::new_error(),
                };
                shared.send(ClipboardMessage::SendFormatData(resp.into_owned()));
            }
            Event::SelectionRequest(r) if r.selection == clipboard => {
                let property = if r.property == 0 { r.target } else { r.property };
                let ok = match &ours {
                    Some(_) if r.target == targets => {
                        let list = [targets, utf8, text_atom, u32::from(AtomEnum::STRING)];
                        conn.change_property32(PropMode::REPLACE, r.requestor, property, AtomEnum::ATOM, &list)?;
                        true
                    }
                    Some(t) if r.target == utf8 || r.target == text_atom || r.target == u32::from(AtomEnum::STRING) => {
                        conn.change_property8(PropMode::REPLACE, r.requestor, property, utf8, t.as_bytes())?;
                        true
                    }
                    _ => false,
                };
                let reply = SelectionNotifyEvent {
                    response_type: SELECTION_NOTIFY_EVENT, sequence: 0, time: r.time, requestor: r.requestor,
                    selection: r.selection, target: r.target, property: if ok { property } else { 0 },
                };
                conn.send_event(false, r.requestor, EventMask::NO_EVENT, reply)?;
                conn.flush()?;
            }
            _ => {}
        }
    }
}

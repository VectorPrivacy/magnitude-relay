//! The admin socket: how `query`, `count`, `delete` and `sync` reach a running
//! relay, whose data directory they cannot open themselves.
//!
//! A Unix socket at `<data>/admin.sock`, mode 0600. Whoever may open it may run
//! operator commands, so file permissions are the whole authentication and
//! nothing listens on the network. A connection is one request, a single JSON
//! line, answered with JSON lines:
//!
//! ```text
//! {"op":"query","filters":[...],"limit":N}
//!     {"event":{...}} per event, newest first, then {"done":true,"count":N}
//! {"op":"count","filters":[...]}
//!     {"count":N}
//! {"op":"delete","filters":[...],"age":S,"all":true,"dry_run":true}
//!     {"matched":N,"deleted":0,"sample":[{"id":..,"kind":..,"created_at":..,"pubkey":..}]}
//! {"op":"delete",...} without "dry_run"
//!     {"progress":N} after each batch, then {"matched":N,"deleted":M,"sample":[]}
//! {"op":"backup","filters":[],"dest":"/absolute/path"}
//!     {"progress":BYTES,"total":BYTES} now and then, then
//!     {"backup":true,"events":N,"files":F,"bytes":B,"written":W}
//! {"op":"items","filters":[one],"limit":N,"hide_wraps":true}
//!     {"items":"<hex>"} with up to 1000 (created_at, id) pairs of 40 bytes each,
//!     newest first, at most N+1 in all, then {"done":true,"count":N}
//! {"op":"ingest","events":[{...},...]}
//!     {"verdicts":["stored","refused blocked: ...",...]}, one per event
//! {"op":"top","filters":[],"minutes":M,"by":"bytes","limit":N}
//!     {"text":"..."} per line of the table (see `talk`), then {"done":true,"count":N}
//! {"op":"heavy","filters":[],"minutes":M,"by":"time","limit":N}
//!     the same, for slow and big requests and bursts (see `heavy`)
//! ```
//!
//! `items` is a negentropy set and `ingest` stores events another relay sent:
//! the two halves of a sync. Ingested events are checked as a client's EVENT is
//! (policy, id, signature), in the connection's thread, and stored through the
//! writer like a client batch: relayed live, answered once durable.
//!
//! Any failure is `{"error":"..."}`. Reads run on a snapshot in the
//! connection's own thread, off the reactors and the writer. A delete finds its
//! events there too, but only the writer thread may kill them: the kills go to
//! it a batch at a time (see `ingest::Control`), between its own work. A backup
//! is copied here as well; the writer only starts it, and hears when it is over.

use crate::inbound::{self, Verdict};
use crate::ingest::{self, Control};
use crate::operator::{self, Deleted, Sample};
use crate::session::SessionCfg;
use relay_proto::filter::FilterError;
use relay_proto::json::{self, RawStr, Scanner};
use relay_proto::record::push_u64;
use relay_proto::{hex, Filter};
use relay_store::backup::Copied;
use relay_store::writer::DELETE_BATCH;
use relay_store::{Store, Version};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::Duration;

/// How long a client may take to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a client may stop reading before it is dropped: it holds a
/// snapshot, which keeps deleted bytes on disk.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// A request is one line. Filters can be long (hundreds of authors), but not this long.
const MAX_REQUEST: u64 = 16 << 20;
/// Connections served at once; more are turned away.
const MAX_CONNECTIONS: usize = 4;
const STOPPING: &str = "the relay is shutting down";

pub fn socket_path(data: &Path) -> PathBuf {
    data.join("admin.sock")
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Query,
    Count,
    Delete,
    Backup,
    Items,
    Ingest,
    Top,
    Heavy,
}

impl Op {
    const NAMES: [(Op, &'static str); 8] = [
        (Op::Query, "query"),
        (Op::Count, "count"),
        (Op::Delete, "delete"),
        (Op::Backup, "backup"),
        (Op::Items, "items"),
        (Op::Ingest, "ingest"),
        (Op::Top, "top"),
        (Op::Heavy, "heavy"),
    ];

    fn name(self) -> &'static str {
        Op::NAMES.iter().find(|(o, _)| *o == self).map(|(_, n)| *n).expect("every op is named")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub op: Op,
    pub filters: Vec<Filter>,
    /// query: at most this many events. items: this many and one more.
    pub limit: Option<u64>,
    /// delete: only events created more than this many seconds ago.
    pub age: Option<u64>,
    /// delete: the filters may match every event.
    pub all: bool,
    /// delete: change nothing, say what would go.
    pub dry_run: bool,
    /// backup: where to, as an absolute path.
    pub dest: Option<String>,
    /// items: leave out gift wraps unless the filter names their author,
    /// recipient or id, as this relay does for its own clients.
    pub hide_wraps: bool,
    /// ingest: event objects, as JSON text.
    pub events: Vec<String>,
    /// ingest: indices into `events` whose signatures a trusted peer vouched
    /// for (it took them from a client itself): not checked again.
    pub trusted: Vec<u64>,
    /// top, heavy: the last this many minutes, sorted by this (see `talk::By`, `heavy::By`).
    pub minutes: Option<u64>,
    pub by: Option<String>,
}

/// Items per `{"items":..}` line: 80 KB of hex.
const ITEMS_PER_LINE: usize = 1000;

/// Why a request or reply could not be read.
struct Bad(String);

impl From<json::Error> for Bad {
    fn from(e: json::Error) -> Bad {
        Bad(e.to_string())
    }
}

impl From<FilterError> for Bad {
    fn from(e: FilterError) -> Bad {
        Bad(e.to_string())
    }
}

impl From<&str> for Bad {
    fn from(e: &str) -> Bad {
        Bad(e.to_string())
    }
}

fn boolean(s: &mut Scanner<'_>) -> Result<bool, Bad> {
    match s.raw_value()? {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => Err("expected true or false".into()),
    }
}

impl Request {
    pub fn new(op: Op, filters: Vec<Filter>) -> Request {
        Request {
            op,
            filters,
            limit: None,
            age: None,
            all: false,
            dry_run: false,
            dest: None,
            hide_wraps: false,
            events: Vec::new(),
            trusted: Vec::new(),
            minutes: None,
            by: None,
        }
    }

    fn to_line(&self) -> String {
        let mut out = format!("{{\"op\":\"{}\",\"filters\":[", self.op.name()).into_bytes();
        for (i, f) in self.filters.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            f.write_json(&mut out);
        }
        out.push(b']');
        for (key, v) in [("limit", self.limit), ("age", self.age), ("minutes", self.minutes)] {
            if let Some(v) = v {
                out.extend_from_slice(format!(",\"{key}\":").as_bytes());
                push_u64(&mut out, v);
            }
        }
        for (key, v) in [("all", self.all), ("dry_run", self.dry_run), ("hide_wraps", self.hide_wraps)] {
            if v {
                out.extend_from_slice(format!(",\"{key}\":true").as_bytes());
            }
        }
        for (key, v) in [("dest", &self.dest), ("by", &self.by)] {
            if let Some(v) = v {
                out.extend_from_slice(format!(",\"{key}\":\"").as_bytes());
                json::escape_str(v, &mut out);
                out.push(b'"');
            }
        }
        if !self.events.is_empty() {
            out.extend_from_slice(b",\"events\":[");
            for (i, e) in self.events.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // As received: an event's bytes are what its id commits to.
                out.extend_from_slice(e.as_bytes());
            }
            out.push(b']');
        }
        if !self.trusted.is_empty() {
            out.extend_from_slice(b",\"trusted\":[");
            for (i, n) in self.trusted.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                push_u64(&mut out, *n);
            }
            out.push(b']');
        }
        out.push(b'}');
        String::from_utf8(out).expect("request JSON is UTF-8")
    }

    fn parse(line: &str) -> Result<Request, String> {
        let mut s = Scanner::new(line);
        let mut op = None;
        let mut r = Request::new(Op::Query, Vec::new());
        s.object(|s, key| -> Result<(), Bad> {
            match key.bytes {
                b"op" => {
                    let v = s.string()?;
                    let found = Op::NAMES.iter().find(|(_, n)| v.is(n.as_bytes()));
                    op = Some(found.ok_or("unknown op")?.0);
                }
                b"filters" => s.array(|s| -> Result<(), Bad> {
                    r.filters.push(Filter::parse(s)?);
                    Ok(())
                })?,
                b"limit" => r.limit = Some(s.u64()?),
                b"age" => r.age = Some(s.u64()?),
                b"all" => r.all = boolean(s)?,
                b"dry_run" => r.dry_run = boolean(s)?,
                b"dest" => r.dest = Some(s.string()?.to_text()),
                b"hide_wraps" => r.hide_wraps = boolean(s)?,
                b"events" => s.array(|s| -> Result<(), Bad> {
                    s.ws();
                    if s.peek() != Some(b'{') {
                        return Err("events must be JSON objects".into());
                    }
                    // A slice of a &str between JSON delimiters is UTF-8.
                    r.events.push(String::from_utf8_lossy(s.raw_value()?).into_owned());
                    Ok(())
                })?,
                b"trusted" => s.array(|s| -> Result<(), Bad> {
                    r.trusted.push(s.u64()?);
                    Ok(())
                })?,
                b"minutes" => r.minutes = Some(s.u64()?),
                b"by" => r.by = Some(s.string()?.to_text()),
                _ => return Err("unknown key".into()),
            }
            Ok(())
        })
        .map_err(|b| b.0)?;
        s.end().map_err(|e| e.to_string())?;
        r.op = op.ok_or("no op")?;
        Ok(r)
    }
}

// The server.

/// The listening socket, for `serve` to take down on shutdown.
pub struct Admin {
    path: PathBuf,
}

impl Admin {
    /// Removes the socket file, so that no one finds it once the relay is gone.
    pub fn stop(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// What a request may use: the store to read, the writer to change it through,
/// and the policy events handed in must pass.
#[derive(Clone)]
pub struct Ctx {
    pub store: Store,
    pub ctl: Sender<Control>,
    pub policy: Arc<SessionCfg>,
    /// Asks the reactors who has been using the relay (`Shared::top`).
    pub top: Option<TopFn>,
    /// Asks the reactors what strained them (`Shared::heavy`).
    pub heavy: Option<HeavyFn>,
}

pub type TopFn = Arc<dyn Fn(u64) -> crate::subs::FxMap<std::net::IpAddr, crate::talk::Agg> + Send + Sync>;
pub type HeavyFn = Arc<dyn Fn(u64) -> Vec<crate::heavy::Heavy> + Send + Sync>;

/// Starts listening on `<data>/admin.sock`.
pub fn start(data: &Path, cx: Ctx) -> io::Result<Admin> {
    let path = socket_path(data);
    let listener = bind(&path)?;
    std::thread::Builder::new().name("admin".into()).spawn(move || accept_loop(listener, cx))?;
    Ok(Admin { path })
}

/// A socket that only its owner can open, from the moment it exists. Its mode
/// can be set only after `bind` creates it, so it is bound inside a directory
/// no one else can enter, restricted, and then moved into place.
fn bind(path: &Path) -> io::Result<UnixListener> {
    // Whatever socket is already there was left by a crash: the store's lock,
    // which this process holds, proves no other relay uses the directory.
    // Anything else is not ours to replace.
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_socket() => return Err(io::Error::other(format!("{} exists and is not a socket", path.display()))),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let tmp = path.with_extension("tmp");
    let inner = tmp.join("s");
    check_len(path)?;
    check_len(&inner)?;
    let bound = bind_private(&tmp, &inner, path);
    if bound.is_err() {
        let _ = std::fs::remove_file(&inner);
    }
    let _ = std::fs::remove_dir(&tmp);
    bound
}

fn bind_private(tmp: &Path, inner: &Path, path: &Path) -> io::Result<UnixListener> {
    match std::fs::DirBuilder::new().mode(0o700).create(tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o700))?,
        Err(e) => return Err(e),
    }
    // A leftover of a crash between here and the rename.
    let _ = std::fs::remove_file(inner);
    let listener = UnixListener::bind(inner)?;
    std::fs::set_permissions(inner, std::fs::Permissions::from_mode(0o600))?;
    // Replaces a stale socket in one step.
    std::fs::rename(inner, path)?;
    Ok(listener)
}

/// A socket path must fit `sun_path`: 104 bytes with the NUL on macOS, 108 on Linux.
pub(crate) fn check_len(path: &Path) -> io::Result<()> {
    const MAX: usize = 103;
    if path.as_os_str().len() > MAX {
        return Err(io::Error::other(format!(
            "{} is too long for a Unix socket (at most {MAX} bytes); give the data directory a shorter path (a symlink will do)",
            path.display()
        )));
    }
    Ok(())
}

/// Counts a connection while it is served.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn accept_loop(listener: UnixListener, cx: Ctx) {
    let open = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            // Out of descriptors, say: do not spin.
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };
        if open.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            open.fetch_sub(1, Ordering::AcqRel);
            refuse(&mut &stream, "busy: too many admin connections, try again");
            continue;
        }
        let slot = Slot(open.clone());
        let cx = cx.clone();
        // If no thread can be had the closure, and the slot with it, is dropped.
        let _ = std::thread::Builder::new().name("admin-conn".into()).spawn(move || {
            let _slot = slot;
            serve(&stream, &cx);
        });
    }
}

fn refuse(out: &mut impl Write, why: &str) {
    let mut line = b"{\"error\":\"".to_vec();
    json::escape_str(why, &mut line);
    line.extend_from_slice(b"\"}\n");
    let _ = out.write_all(&line);
}

fn serve(stream: &UnixStream, cx: &Ctx) {
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let mut line = String::new();
    let read = BufReader::new(stream.take(MAX_REQUEST)).read_line(&mut line);
    let mut out = BufWriter::new(stream);
    let result = match read {
        Ok(0) => Err("no request".to_string()),
        Ok(n) if n as u64 >= MAX_REQUEST && !line.ends_with('\n') => Err("request too large".to_string()),
        Ok(_) => handle(&line, &mut out, cx),
        Err(e) => Err(format!("cannot read the request: {e}")),
    };
    if let Err(why) = result {
        refuse(&mut out, &why);
    }
    let _ = out.flush();
}

fn handle(line: &str, out: &mut impl Write, cx: &Ctx) -> Result<(), String> {
    let (store, ctl) = (&cx.store, &cx.ctl);
    let req = Request::parse(line)?;
    if req.op == Op::Backup {
        return backup(&req, out, ctl);
    }
    if req.op == Op::Ingest {
        return ingest(&req, out, cx);
    }
    if req.op == Op::Top {
        return top(&req, out, cx);
    }
    if req.op == Op::Heavy {
        return heavy(&req, out, cx);
    }
    operator::check_filters(&req.filters)?;
    let now = ingest::now();
    match req.op {
        Op::Items => {
            let [f] = &req.filters[..] else { return Err("items takes exactly one filter".into()) };
            let cap = req.limit.map_or(usize::MAX, |l| l as usize);
            let items = crate::sync::local::items_of(&store.snapshot(), f, req.hide_wraps, cap, now);
            for chunk in items.chunks(ITEMS_PER_LINE) {
                let mut b = b"{\"items\":\"".to_vec();
                for (ca, id) in chunk {
                    hex::encode_into(&ca.to_be_bytes(), &mut b);
                    hex::encode_into(id, &mut b);
                }
                b.extend_from_slice(b"\"}\n");
                out.write_all(&b).map_err(|e| e.to_string())?;
            }
            writeln!(out, "{{\"done\":true,\"count\":{}}}", items.len()).map_err(|e| e.to_string())
        }
        Op::Ingest => unreachable!("handled above"),
        Op::Query => {
            let v = store.snapshot();
            let mut buf = Vec::new();
            let n = operator::stream(&v, &req.filters, req.limit, now, &mut |rec| {
                buf.clear();
                buf.extend_from_slice(b"{\"event\":");
                rec.write_json(&mut buf);
                buf.extend_from_slice(b"}\n");
                out.write_all(&buf)
            })
            .map_err(|e| e.to_string())?;
            writeln!(out, "{{\"done\":true,\"count\":{n}}}").map_err(|e| e.to_string())
        }
        Op::Count => {
            let n = operator::count_matching(&store.snapshot(), &req.filters, now);
            writeln!(out, "{{\"count\":{n}}}").map_err(|e| e.to_string())
        }
        Op::Delete => delete(&req, out, store, ctl, now),
        Op::Backup | Op::Top | Op::Heavy => unreachable!("answered above"),
    }
}

/// Who has been using the relay, as the lines of a table.
fn top(req: &Request, out: &mut impl Write, cx: &Ctx) -> Result<(), String> {
    let Some(ask) = &cx.top else { return Err("top reports on connections, which only the running relay has".into()) };
    let minutes = req.minutes.unwrap_or(60).clamp(1, crate::talk::SLOTS as u64 * crate::talk::SLOT_SECS / 60);
    let by = match &req.by {
        None => crate::talk::By::Bytes,
        Some(b) => crate::talk::By::parse(b).ok_or_else(|| {
            let names: Vec<&str> = crate::talk::By::NAMES.iter().map(|(_, n)| *n).collect();
            format!("--by is one of {}, not {b:?}", names.join(", "))
        })?,
    };
    let lines = crate::talk::render(ask(minutes), minutes, by, req.limit.unwrap_or(25) as usize);
    text(&lines, out)
}

/// What strained the relay lately, as the lines of a table.
fn heavy(req: &Request, out: &mut impl Write, cx: &Ctx) -> Result<(), String> {
    let Some(ask) = &cx.heavy else { return Err("heavy reports on requests, which only the running relay has".into()) };
    let minutes = req.minutes.unwrap_or(60).clamp(1, 24 * 60);
    let by = match &req.by {
        None => crate::heavy::By::Time,
        Some(b) => crate::heavy::By::parse(b).ok_or_else(|| {
            let names: Vec<&str> = crate::heavy::By::NAMES.iter().map(|(_, n)| *n).collect();
            format!("--by is one of {}, not {b:?}", names.join(", "))
        })?,
    };
    text(&crate::heavy::render(ask(minutes), minutes, by, req.limit.unwrap_or(25) as usize), out)
}

/// A table's lines as `{"text":..}` replies, then `{"done":..}`.
fn text(lines: &[String], out: &mut impl Write) -> Result<(), String> {
    let mut b = Vec::new();
    for line in lines {
        b.clear();
        b.extend_from_slice(b"{\"text\":\"");
        json::escape_str(line, &mut b);
        b.extend_from_slice(b"\"}\n");
        out.write_all(&b).map_err(|e| e.to_string())?;
    }
    writeln!(out, "{{\"done\":true,\"count\":{}}}", lines.len()).map_err(|e| e.to_string())
}

/// Copies the store to `dest` while the relay serves (see `relay_store::backup`).
/// The writer only starts the backup; the copy runs on this thread, and the
/// writer hears that it is over however it ends.
fn backup(req: &Request, out: &mut impl Write, ctl: &Sender<Control>) -> Result<(), String> {
    let dest = Path::new(req.dest.as_deref().ok_or("a backup needs \"dest\"")?);
    if !dest.is_absolute() {
        return Err("a backup's destination must be an absolute path".into());
    }
    let (reply, answer) = mpsc::channel();
    ctl.send(Control::BeginBackup { reply }).map_err(|_| STOPPING.to_string())?;
    let plan = answer.recv().map_err(|_| STOPPING.to_string())?.map_err(|e| e.to_string())?;
    let held = Held(Some(ctl.clone()));
    let events = plan.events();
    let copied = relay_store::backup::copy(&plan, dest, &mut |done, total| {
        // The client going away (Ctrl-C), or the relay stopping, abandons the copy.
        !ingest::SHUTDOWN.load(Ordering::Acquire) && writeln!(out, "{{\"progress\":{done},\"total\":{total}}}").and_then(|()| out.flush()).is_ok()
    });
    drop(plan);
    let ended = held.end();
    let c = copied.map_err(|e| e.to_string())?;
    ended?;
    writeln!(out, "{{\"backup\":true,\"events\":{events},\"files\":{},\"bytes\":{},\"written\":{}}}", c.files, c.bytes, c.written).map_err(|e| e.to_string())
}

/// A backup the writer holds still for. Ended once, or on the way out of a
/// panic, so log compaction never stays held.
struct Held(Option<Sender<Control>>);

impl Held {
    fn end(mut self) -> Result<(), String> {
        let ctl = self.0.take().expect("ended once");
        let (reply, answer) = mpsc::channel();
        ctl.send(Control::EndBackup { reply }).map_err(|_| STOPPING.to_string())?;
        answer.recv().map_err(|_| STOPPING.to_string())?.map_err(|e| e.to_string())
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(ctl) = self.0.take() {
            let (reply, _) = mpsc::channel();
            let _ = ctl.send(Control::EndBackup { reply });
        }
    }
}

/// Threads one ingest request may use to check signatures: it runs beside the
/// relay's own work, so it takes no more than half the machine.
fn ingest_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get() / 2).clamp(1, 4)
}

/// Checks each event as a client's EVENT is checked, then stores what passed
/// through the writer, which relays it live and answers once it is durable.
fn ingest(req: &Request, out: &mut impl Write, cx: &Ctx) -> Result<(), String> {
    if !req.filters.is_empty() {
        return Err("ingest takes events, not filters".into());
    }
    let mut vouched = vec![false; req.events.len()];
    for &i in &req.trusted {
        *vouched.get_mut(i as usize).ok_or("a trusted index names no event")? = true;
    }
    let texts: Vec<(&str, usize, bool)> = req.events.iter().zip(vouched).map(|(e, t)| (e.as_str(), 0, t)).collect();
    let v = cx.store.snapshot();
    let checked = inbound::check_all(&texts, &cx.policy, &v, ingest::now(), ingest_threads());
    // Not held while the writer works: a snapshot pins what it may reclaim.
    drop(v);
    let mut verdicts: Vec<Option<Verdict>> = Vec::with_capacity(checked.len());
    let mut recs = Vec::new();
    for c in checked {
        match c {
            Ok(rec) => {
                recs.push(rec);
                verdicts.push(None);
            }
            Err(v) => verdicts.push(Some(v)),
        }
    }
    let mut outcomes = if recs.is_empty() { Vec::new() } else { store_through_writer(&cx.ctl, recs)? }.into_iter();
    let mut b = b"{\"verdicts\":[".to_vec();
    for (i, v) in verdicts.into_iter().enumerate() {
        if i > 0 {
            b.push(b',');
        }
        let v = v.unwrap_or_else(|| outcomes.next().unwrap_or(Verdict::Failed));
        b.push(b'"');
        json::escape_str(&v.code(), &mut b);
        b.push(b'"');
    }
    b.extend_from_slice(b"]}\n");
    out.write_all(&b).map_err(|e| e.to_string())
}

/// Hands checked records to the writer and waits until they are durable.
fn store_through_writer(ctl: &Sender<Control>, recs: Vec<Vec<u8>>) -> Result<Vec<Verdict>, String> {
    let n = recs.len();
    let (reply, answer) = mpsc::channel();
    let reply: ingest::IngestReply = Box::new(move |o| {
        let _ = reply.send(o);
    });
    ctl.send(Control::Ingest { recs, reply }).map_err(|_| STOPPING.to_string())?;
    match answer.recv().map_err(|_| STOPPING.to_string())? {
        Some(outcomes) => Ok(outcomes.into_iter().map(|o| Verdict::of(Some(o))).collect()),
        None => Ok(vec![Verdict::Failed; n]),
    }
}

fn delete(req: &Request, out: &mut impl Write, store: &Store, ctl: &Sender<Control>, now: u64) -> Result<(), String> {
    operator::check_delete(&req.filters, req.all)?;
    let older = operator::older_than(req.age, now);
    // Held until the kills are checkpointed: while a reader holds it, nothing
    // that was killed is zeroed on disk, and zeroing must not run ahead of the
    // checkpoint that makes the kills permanent.
    let v = store.snapshot();
    if req.dry_run {
        return write_deleted(out, &operator::preview(&v, &req.filters, older, now)).map_err(|e| e.to_string());
    }
    let (d, mut failed) = kill_matching(&v, &req.filters, older, now, ctl, &mut |deleted| {
        // The client going away (Ctrl-C) ends the delete after the batch in flight.
        writeln!(out, "{{\"progress\":{deleted}}}").and_then(|()| out.flush()).is_ok()
    });
    if d.deleted > 0 {
        if let Err(e) = checkpoint(ctl) {
            failed.get_or_insert(e);
        }
    }
    drop(v);
    match failed {
        Some(why) => Err(format!("{why} (deleted {} before stopping)", d.deleted)),
        None => write_deleted(out, &d).map_err(|e| e.to_string()),
    }
}

/// Hands what `filters` match to the writer to kill, a batch at a time. Returns
/// what was done, and why it stopped early if it did. `listening` is told the
/// running total after each batch and says whether to go on.
fn kill_matching(
    v: &Version,
    filters: &[Filter],
    older: Option<u64>,
    now: u64,
    ctl: &Sender<Control>,
    listening: &mut dyn FnMut(u64) -> bool,
) -> (Deleted, Option<String>) {
    let mut d = Deleted::default();
    let mut batch = Vec::with_capacity(DELETE_BATCH);
    for hit in v.matching_seqs(filters, older, now) {
        d.matched += 1;
        batch.push(hit.seq);
        if batch.len() < DELETE_BATCH {
            continue;
        }
        match kill(ctl, std::mem::take(&mut batch)) {
            Ok(n) => d.deleted += n,
            Err(e) => return (d, Some(e)),
        }
        if !listening(d.deleted) {
            return (d, None);
        }
    }
    match kill(ctl, batch) {
        Ok(n) => d.deleted += n,
        Err(e) => return (d, Some(e)),
    }
    (d, None)
}

/// Asks the writer to kill `seqs`; how many were still live.
fn kill(ctl: &Sender<Control>, seqs: Vec<u64>) -> Result<u64, String> {
    if seqs.is_empty() {
        return Ok(0);
    }
    let (reply, answer) = mpsc::channel();
    ctl.send(Control::Kill { seqs, reply }).map_err(|_| STOPPING.to_string())?;
    let n = answer.recv().map_err(|_| STOPPING.to_string())?.map_err(|e| e.to_string())?;
    Ok(n as u64)
}

fn checkpoint(ctl: &Sender<Control>) -> Result<(), String> {
    let (reply, answer) = mpsc::channel();
    ctl.send(Control::Checkpoint { reply }).map_err(|_| STOPPING.to_string())?;
    answer.recv().map_err(|_| STOPPING.to_string())?.map_err(|e| e.to_string())
}

fn write_deleted(out: &mut impl Write, d: &Deleted) -> io::Result<()> {
    let mut b = b"{\"matched\":".to_vec();
    push_u64(&mut b, d.matched);
    b.extend_from_slice(b",\"deleted\":");
    push_u64(&mut b, d.deleted);
    b.extend_from_slice(b",\"sample\":[");
    for (i, s) in d.sample.iter().enumerate() {
        if i > 0 {
            b.push(b',');
        }
        b.extend_from_slice(b"{\"id\":\"");
        hex::encode_into(&s.id, &mut b);
        b.extend_from_slice(b"\",\"kind\":");
        push_u64(&mut b, s.kind);
        b.extend_from_slice(b",\"created_at\":");
        push_u64(&mut b, s.created_at);
        b.extend_from_slice(b",\"pubkey\":\"");
        hex::encode_into(&s.pubkey, &mut b);
        b.extend_from_slice(b"\"}");
    }
    b.extend_from_slice(b"]}\n");
    out.write_all(&b)
}

// The client.

/// One connection to a running relay's admin socket, good for one request.
pub struct Client(UnixStream);

enum Reply<'a> {
    Event(&'a str),
    Text(String),
    /// Done so far, and of how much when the relay says.
    Progress(u64, Option<u64>),
    Done(u64),
    Count(u64),
    Deleted(Deleted),
    BackedUp(u64, Copied),
    Items(Vec<(u64, [u8; 32])>),
    Verdicts(Vec<Verdict>),
}

impl Client {
    pub fn connect(sock: &Path) -> io::Result<Client> {
        check_len(sock)?;
        UnixStream::connect(sock).map(Client)
    }

    fn ask(mut self, req: &Request) -> io::Result<BufReader<UnixStream>> {
        let mut line = req.to_line();
        line.push('\n');
        self.0.write_all(line.as_bytes())?;
        Ok(BufReader::new(self.0))
    }

    /// Hands each event's JSON to `emit`, newest first. Returns how many.
    pub fn query(self, req: &Request, emit: &mut dyn FnMut(&str) -> io::Result<()>) -> io::Result<u64> {
        let mut r = self.ask(req)?;
        let mut line = String::new();
        let mut got = 0;
        loop {
            match next_reply(&mut r, &mut line)? {
                Reply::Event(e) => {
                    emit(e)?;
                    got += 1;
                }
                Reply::Done(n) if n == got => return Ok(got),
                _ => return Err(io::Error::other("the relay's reply was not what was asked for")),
            }
        }
    }

    pub fn count(self, req: &Request) -> io::Result<u64> {
        let mut r = self.ask(req)?;
        match next_reply(&mut r, &mut String::new())? {
            Reply::Count(n) => Ok(n),
            _ => Err(io::Error::other("the relay's reply was not what was asked for")),
        }
    }

    pub fn delete(self, req: &Request) -> io::Result<Deleted> {
        let mut r = self.ask(req)?;
        let mut line = String::new();
        loop {
            match next_reply(&mut r, &mut line)? {
                Reply::Progress(..) => {}
                Reply::Deleted(d) => return Ok(d),
                _ => return Err(io::Error::other("the relay's reply was not what was asked for")),
            }
        }
    }

    /// Has the relay copy itself to `req.dest`. `progress` hears (bytes done,
    /// bytes in all). Returns the events in the backup, and what was copied.
    pub fn backup(self, req: &Request, progress: &mut dyn FnMut(u64, u64)) -> io::Result<(u64, Copied)> {
        let mut r = self.ask(req)?;
        let mut line = String::new();
        loop {
            match next_reply(&mut r, &mut line)? {
                Reply::Progress(done, Some(total)) => progress(done, total),
                Reply::BackedUp(events, c) => return Ok((events, c)),
                _ => return Err(io::Error::other("the relay's reply was not what was asked for")),
            }
        }
    }

    /// A filter's `(created_at, id)` set, newest first.
    pub fn items(self, req: &Request) -> io::Result<Vec<(u64, [u8; 32])>> {
        let mut r = self.ask(req)?;
        let mut line = String::new();
        let mut items = Vec::new();
        loop {
            match next_reply(&mut r, &mut line)? {
                Reply::Items(mut more) => items.append(&mut more),
                Reply::Done(n) if n == items.len() as u64 => return Ok(items),
                _ => return Err(io::Error::other("the relay's reply was not what was asked for")),
            }
        }
    }

    /// A table's lines (`top`, `heavy`).
    pub fn text(self, req: &Request) -> io::Result<Vec<String>> {
        let mut r = self.ask(req)?;
        let mut line = String::new();
        let mut lines = Vec::new();
        loop {
            match next_reply(&mut r, &mut line)? {
                Reply::Text(t) => lines.push(t),
                Reply::Done(n) if n == lines.len() as u64 => return Ok(lines),
                _ => return Err(io::Error::other("the relay's reply was not what was asked for")),
            }
        }
    }

    pub fn ingest(self, req: &Request) -> io::Result<Vec<Verdict>> {
        let mut r = self.ask(req)?;
        match next_reply(&mut r, &mut String::new())? {
            Reply::Verdicts(v) if v.len() == req.events.len() => Ok(v),
            _ => Err(io::Error::other("the relay's reply was not what was asked for")),
        }
    }
}

/// The next reply line. The relay's own `{"error":..}` becomes the error.
fn next_reply<'a>(r: &mut impl BufRead, line: &'a mut String) -> io::Result<Reply<'a>> {
    line.clear();
    if r.read_line(line)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the relay closed the connection before it finished"));
    }
    parse_reply(line).map_err(io::Error::other)?.map_err(io::Error::other)
}

/// `Ok(Err(message))` is a reply that says the request failed.
fn parse_reply(line: &str) -> Result<Result<Reply<'_>, String>, String> {
    if let Some(ev) = line.strip_prefix("{\"event\":").and_then(|l| l.trim_end().strip_suffix('}')) {
        return Ok(Ok(Reply::Event(ev)));
    }
    let (mut error, mut done, mut progress, mut total) = (None, false, None, None);
    let (mut count, mut matched, mut deleted) = (None, None, None);
    let (mut backed_up, mut events, mut files, mut bytes, mut written) = (false, None, None, None, None);
    let mut sample = Vec::new();
    let (mut items, mut verdicts, mut text) = (None, None, None);
    let mut s = Scanner::new(line);
    s.object(|s, key| -> Result<(), Bad> {
        match key.bytes {
            b"items" => {
                let h = s.string()?;
                let mut raw = vec![0u8; h.bytes.len() / 2];
                if h.escaped || h.bytes.len() % 80 != 0 || !hex::decode_into(h.bytes, &mut raw) {
                    return Err("bad items in a reply".into());
                }
                items = Some(raw.chunks(40).map(|c| (u64::from_be_bytes(c[..8].try_into().unwrap()), c[8..].try_into().unwrap())).collect());
            }
            b"verdicts" => {
                let mut v = Vec::new();
                s.array(|s| -> Result<(), Bad> {
                    v.push(Verdict::parse(&s.string()?.to_text()).ok_or("bad verdict in a reply")?);
                    Ok(())
                })?;
                verdicts = Some(v);
            }
            b"error" => error = Some(s.string()?.to_text()),
            b"text" => text = Some(s.string()?.to_text()),
            b"done" => {
                s.skip()?;
                done = true;
            }
            b"progress" => progress = Some(s.u64()?),
            b"total" => total = Some(s.u64()?),
            b"backup" => {
                s.skip()?;
                backed_up = true;
            }
            b"events" => events = Some(s.u64()?),
            b"files" => files = Some(s.u64()?),
            b"bytes" => bytes = Some(s.u64()?),
            b"written" => written = Some(s.u64()?),
            b"count" => count = Some(s.u64()?),
            b"matched" => matched = Some(s.u64()?),
            b"deleted" => deleted = Some(s.u64()?),
            b"sample" => s.array(|s| -> Result<(), Bad> {
                sample.push(parse_sample(s)?);
                Ok(())
            })?,
            // A newer relay may say more.
            _ => s.skip()?,
        }
        Ok(())
    })
    .map_err(|b| format!("unreadable reply from the relay: {}", b.0))?;
    Ok(if let Some(msg) = error {
        Err(msg)
    } else if let Some(t) = text {
        Ok(Reply::Text(t))
    } else if let Some(items) = items {
        Ok(Reply::Items(items))
    } else if let Some(v) = verdicts {
        Ok(Reply::Verdicts(v))
    } else if done {
        Ok(Reply::Done(count.unwrap_or(0)))
    } else if let Some(n) = progress {
        Ok(Reply::Progress(n, total))
    } else if let (true, Some(events), Some(files), Some(bytes), Some(written)) = (backed_up, events, files, bytes, written) {
        Ok(Reply::BackedUp(events, Copied { files: files as usize, bytes, written }))
    } else if let (Some(matched), Some(deleted)) = (matched, deleted) {
        Ok(Reply::Deleted(Deleted { matched, deleted, sample }))
    } else if let Some(n) = count {
        Ok(Reply::Count(n))
    } else {
        Err("unreadable reply from the relay".to_string())
    })
}

fn parse_sample(s: &mut Scanner<'_>) -> Result<Sample, Bad> {
    let (mut id, mut pubkey, mut kind, mut created_at) = ([0u8; 32], [0u8; 32], 0, 0);
    let hex32 = |v: RawStr<'_>| hex::decode_32(v.bytes).ok_or(Bad("bad hex in a reply".into()));
    s.object(|s, key| -> Result<(), Bad> {
        match key.bytes {
            b"id" => id = hex32(s.string()?)?,
            b"pubkey" => pubkey = hex32(s.string()?)?,
            b"kind" => kind = s.u64()?,
            b"created_at" => created_at = s.u64()?,
            _ => s.skip()?,
        }
        Ok(())
    })?;
    Ok(Sample { id, kind, created_at, pubkey })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters(json: &str) -> Vec<Filter> {
        operator::parse_filters(json).unwrap()
    }

    #[test]
    fn requests_round_trip() {
        let h = "ab".repeat(32);
        let fs = filters(&format!(
            r##"[{{"kinds":[1059,14],"authors":["{h}"],"#p":["{h}"],"#t":["plain \"quoted\" tag"],"since":5,"until":9}},{{"ids":["{h}"]}},{{}}]"##
        ));
        for req in [
            Request::new(Op::Query, fs.clone()),
            Request { limit: Some(7), ..Request::new(Op::Query, fs.clone()) },
            Request::new(Op::Count, fs.clone()),
            Request { age: Some(86_400), all: true, dry_run: true, ..Request::new(Op::Delete, fs.clone()) },
            Request { age: Some(0), ..Request::new(Op::Delete, fs.clone()) },
            Request { dest: Some("/srv/backups/a \"quoted\" \\ name\ttab".into()), ..Request::new(Op::Backup, Vec::new()) },
            Request { limit: Some(500_000), hide_wraps: true, ..Request::new(Op::Items, fs[..1].to_vec()) },
            Request {
                events: vec![format!(r#"{{"id":"{h}","content":"a \"quoted\" line\nand more"}}"#), "{}".into()],
                ..Request::new(Op::Ingest, Vec::new())
            },
        ] {
            let line = req.to_line();
            assert!(!line.contains('\n'), "one line: {line}");
            assert_eq!(Request::parse(&line).unwrap(), req, "{line}");
        }
    }

    #[test]
    fn bad_requests_say_why() {
        for (line, why) in [
            (r#"{"filters":[]}"#, "no op"),
            (r#"{"op":"drop","filters":[]}"#, "unknown op"),
            (r#"{"op":"count","filters":[],"oops":1}"#, "unknown key"),
            (r#"{"op":"count","filters":[{"nope":1}]}"#, "unknown key"),
            (r#"{"op":"delete","filters":[],"all":1}"#, "true or false"),
            (r#"{"op":"count""#, "byte"),
            ("", "byte"),
        ] {
            let err = Request::parse(line).unwrap_err();
            assert!(err.contains(why), "{line}: {err}");
        }
    }

    #[test]
    fn replies_are_told_apart() {
        let ev = r#"{"event":{"content":"a","id":"x"}}"#;
        assert!(matches!(parse_reply(ev), Ok(Ok(Reply::Event(e))) if e == r#"{"content":"a","id":"x"}"#));
        assert!(matches!(parse_reply(r#"{"done":true,"count":3}"#), Ok(Ok(Reply::Done(3)))));
        assert!(matches!(parse_reply(r#"{"count":9}"#), Ok(Ok(Reply::Count(9)))));
        assert!(matches!(parse_reply(r#"{"progress":4096}"#), Ok(Ok(Reply::Progress(4096, None)))));
        assert!(matches!(parse_reply(r#"{"progress":4096,"total":8192}"#), Ok(Ok(Reply::Progress(4096, Some(8192))))));
        let backed = r#"{"backup":true,"events":60000,"files":9,"bytes":123,"written":45}"#;
        let Ok(Ok(Reply::BackedUp(events, c))) = parse_reply(backed) else { panic!("not a backup reply") };
        assert_eq!((events, c.files, c.bytes, c.written), (60_000, 9, 123, 45));
        let id = "cd".repeat(32);
        let line = format!(r#"{{"matched":5,"deleted":0,"sample":[{{"id":"{id}","kind":14,"created_at":77,"pubkey":"{id}"}}]}}"#);
        let Ok(Ok(Reply::Deleted(d))) = parse_reply(&line) else { panic!("not a delete reply") };
        assert_eq!((d.matched, d.deleted, d.sample.len()), (5, 0, 1));
        assert_eq!((d.sample[0].kind, d.sample[0].created_at, d.sample[0].id), (14, 77, [0xcd; 32]));
        // A set, as 40-byte (created_at, id) items in hex.
        let items = format!(r#"{{"items":"{}{}{}{}"}}"#, hex::encode_string(&7u64.to_be_bytes()), "ab".repeat(32), hex::encode_string(&9u64.to_be_bytes()), "cd".repeat(32));
        let Ok(Ok(Reply::Items(got))) = parse_reply(&items) else { panic!("not items") };
        assert_eq!(got, [(7, [0xab; 32]), (9, [0xcd; 32])]);
        assert!(parse_reply(r#"{"items":"abcd"}"#).is_err(), "items come whole");
        let Ok(Ok(Reply::Verdicts(v))) = parse_reply(r#"{"verdicts":["stored","refused blocked: kind 1 is not accepted by this relay","vanished"]}"#) else {
            panic!("not verdicts")
        };
        assert_eq!(v, [Verdict::Stored, Verdict::Refused("blocked: kind 1 is not accepted by this relay".into()), Verdict::Vanished]);
        assert!(parse_reply(r#"{"verdicts":["sideways"]}"#).is_err());
        // And what a relay says when it fails survives its escaping.
        let mut e = b"{\"error\":\"".to_vec();
        json::escape_str("a \"b\" \\ c\nd", &mut e);
        e.extend_from_slice(b"\"}");
        let Ok(Err(msg)) = parse_reply(std::str::from_utf8(&e).unwrap()) else { panic!("not an error") };
        assert_eq!(msg, "a \"b\" \\ c\nd");
    }

    /// A store of `n` events and a stand-in for the writer thread that answers `Control`.
    fn store_with_a_writer(n: usize) -> (Store, Sender<Control>, std::thread::JoinHandle<()>) {
        use relay_proto::{event::parse_event_json, EventParser};
        let dir = std::env::temp_dir().join(format!("relay-admin-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (store, mut w) = Store::open(&dir, relay_store::Options { segment_size: 16 << 20, ..Default::default() }).unwrap();
        let mut parser = EventParser::new();
        let recs: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let json = format!(
                    r#"{{"id":"{:064x}","pubkey":"{:064x}","created_at":{},"kind":14,"tags":[],"content":"x","sig":"{}"}}"#,
                    i + 1,
                    1,
                    1_000 + i,
                    "00".repeat(64)
                );
                let mut rec = Vec::new();
                parse_event_json(&json, &mut parser, &mut rec, false).unwrap();
                rec
            })
            .collect();
        for chunk in recs.chunks(1_000) {
            let refs: Vec<&[u8]> = chunk.iter().map(Vec::as_slice).collect();
            w.write(&refs).unwrap();
        }
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            for c in rx {
                ingest::control(&mut w, c);
            }
        });
        (store, tx, thread)
    }

    #[test]
    fn a_departed_client_stops_a_delete_after_its_batch() {
        let n = DELETE_BATCH * 3 + 5;
        let (store, ctl, writer) = store_with_a_writer(n);
        let all = filters("{}");
        let v = store.snapshot();
        let mut told = Vec::new();
        let (d, failed) = kill_matching(&v, &all, None, ingest::now(), &ctl, &mut |deleted| {
            told.push(deleted);
            told.len() < 2
        });
        assert!(failed.is_none());
        // Two batches went; the client was told after each, and the second time it was gone.
        assert_eq!(told, [DELETE_BATCH as u64, DELETE_BATCH as u64 * 2]);
        assert_eq!(d.deleted, DELETE_BATCH as u64 * 2);
        assert_eq!(operator::count_matching(&store.snapshot(), &all, ingest::now()), (n - DELETE_BATCH * 2) as u64);

        // Left to finish, the rest goes (the events already killed are skipped), and the walk's total is what was killed.
        let (d, failed) = kill_matching(&store.snapshot(), &all, None, ingest::now(), &ctl, &mut |_| true);
        assert!(failed.is_none());
        assert_eq!((d.matched, d.deleted), ((n - DELETE_BATCH * 2) as u64, (n - DELETE_BATCH * 2) as u64));
        assert_eq!(operator::count_matching(&store.snapshot(), &all, ingest::now()), 0);

        drop((v, ctl));
        writer.join().unwrap();
    }

    #[test]
    fn a_writer_that_is_gone_is_an_error_not_a_hang() {
        let (gone, rx) = mpsc::channel::<Control>();
        drop(rx);
        assert_eq!(kill(&gone, vec![1, 2, 3]).unwrap_err(), STOPPING);
        assert_eq!(checkpoint(&gone).unwrap_err(), STOPPING);
        // One that stops between taking a request and answering it.
        let (ctl, rx) = mpsc::channel::<Control>();
        let stopper = std::thread::spawn(move || drop(rx.recv()));
        assert_eq!(kill(&ctl, vec![1]).unwrap_err(), STOPPING);
        stopper.join().unwrap();
    }
}

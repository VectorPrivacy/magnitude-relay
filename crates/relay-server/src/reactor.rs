//! Reactors: one thread per core, each running its own single-threaded runtime.
//!
//! A connection lives on one reactor for its whole life. Parsing, signature
//! checks, queries and replies all happen on that core, so load spreads across
//! cores with no handoffs and no locks on the request path. Each reactor keeps
//! its own live-subscription index and receives every committed batch from the
//! writer (see `ingest.rs`) to fan out to its own connections.

use crate::config::Config;
use crate::heavy::{self, Heavy, HeavyLog, Path, Took, What};
use crate::ingest::{ReactorMsg, WriteReq};
use crate::metrics::{self, Metrics};
use crate::session::{self, Ctx, HeldReqs, Outbox, Session, SessionCfg, SigQueue};
use crate::sock::{Incoming, Sock, Stream, TlsConfig};
use crate::subs::{ConnId, FxMap, SubIndex};
use crate::talk::{self, Agg, Talk, TalkLog};
use crate::verify::Job;
use relay_net::conn::{server_handshake_checked, Handshake, OwnedRequest, Refusal};
use relay_net::http::{write_response, ExtensionPolicy};
use relay_net::ws::{self, Compressor, DeflateParams, Decoder, Event, Role};
use relay_proto::{EventParser, Record};
use relay_store::{Store, Version};
use std::cell::{Cell, RefCell};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

/// A client silent this long gets a ping; silent twice as long, it is dropped.
const IDLE_PING: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest an idle reactor keeps a replaced snapshot.
const SNAPSHOT_MAX_AGE: Duration = Duration::from_millis(50);
const MAX_HEAD: usize = 8 * 1024;

/// State every reactor shares. Read-mostly; the only lock is the per-IP table,
/// touched on connect, disconnect and EVENT.
pub struct Shared {
    pub cfg: Config,
    /// Shared with the admin socket and the sync thread, which hold events to
    /// the same policy as the reactors.
    pub scfg: Arc<SessionCfg>,
    pub store: Store,
    pub writer: SyncSender<WriteReq>,
    pub reactors: OnceLock<Vec<mpsc::UnboundedSender<ReactorMsg>>>,
    /// The counting workers' queue (see `count_workers`).
    pub counts: OnceLock<SyncSender<crate::ingest::Job>>,
    pub nip11: String,
    pub next_conn: AtomicU64,
    ips: Mutex<IpTable>,
    pub metrics: Metrics,
    /// One per `[[sync]]` entry.
    pub sync: Vec<Arc<crate::sync::live::Stats>>,
    /// One per `[[peer]]`: its passes against this relay.
    pub links: Vec<Arc<crate::sync::PeerLink>>,
    /// Checks reads' signatures in batches across connections.
    pub verify: crate::verify::Pool,
    /// Ephemeral ids of the last two minutes: each is delivered once.
    pub ephemeral_seen: crate::ephemeral::Seen,
    /// Clients' ephemeral events, for the sync thread to pass to its peers.
    pub ephemeral_out: tokio::sync::broadcast::Sender<Arc<[u8]>>,
}

/// Per address: connections open, and two token buckets (tokens scaled by
/// 1000 for sub-token refill), one for EVENTs and one for new connections.
struct IpState {
    conns: u32,
    tokens: u64,
    last: Instant,
    conn_tokens: u64,
    conn_last: Instant,
}

/// The per-address table. An address stays in it while it has connections
/// open or either bucket is still refilling: one that reconnected must not
/// come back to a full allowance.
struct IpTable {
    map: FxMap<IpAddr, IpState>,
    swept: Instant,
}

/// How often addresses with nothing left to remember are dropped.
const IP_SWEEP: Duration = Duration::from_secs(60);

/// Refills a bucket of `cap` tokens (scaled) at `per_min` tokens a minute.
fn refill(tokens: &mut u64, last: &mut Instant, now: Instant, per_min: u64, cap: u64) {
    let add = now.duration_since(*last).as_millis() as u64 * per_min / 60;
    *tokens = (*tokens + add).min(cap);
    *last = now;
}

impl IpState {
    fn new(now: Instant, l: &crate::config::LimitsCfg) -> IpState {
        IpState {
            conns: 0,
            tokens: u64::from(l.events_per_minute_per_ip) * 1000,
            last: now,
            conn_tokens: u64::from(l.connection_burst_per_ip) * 1000,
            conn_last: now,
        }
    }

    /// Nothing to remember: no connections, and both buckets would be full.
    fn idle(&self, now: Instant, l: &crate::config::LimitsCfg) -> bool {
        let full = |tokens: u64, last: Instant, per_min: u64, cap: u64| {
            per_min == 0 || tokens + now.duration_since(last).as_millis() as u64 * per_min / 60 >= cap
        };
        let (epm, cpm) = (u64::from(l.events_per_minute_per_ip), u64::from(l.connections_per_minute_per_ip));
        self.conns == 0
            && full(self.tokens, self.last, epm, epm * 1000)
            && full(self.conn_tokens, self.conn_last, cpm, u64::from(l.connection_burst_per_ip) * 1000)
    }
}

impl IpTable {
    fn sweep(&mut self, now: Instant, l: &crate::config::LimitsCfg) {
        if now.duration_since(self.swept) >= IP_SWEEP {
            self.map.retain(|_, e| !e.idle(now, l));
            self.swept = now;
        }
    }
}

impl Shared {
    pub fn new(cfg: Config, scfg: Arc<SessionCfg>, store: Store, writer: SyncSender<WriteReq>, reactors: usize) -> Shared {
        let nip11 = cfg.nip11_json();
        let sync = crate::sync::live::stats_for(&cfg.sync);
        let links = cfg.peers.iter().map(|p| Arc::new(crate::sync::PeerLink::new(&p.name))).collect();
        Shared {
            cfg,
            scfg,
            store,
            writer,
            reactors: OnceLock::new(),
            counts: OnceLock::new(),
            nip11,
            next_conn: AtomicU64::new(1),
            ips: Mutex::new(IpTable { map: FxMap::default(), swept: Instant::now() }),
            metrics: Metrics::new(reactors),
            sync,
            links,
            verify: crate::verify::Pool::new(reactors),
            ephemeral_seen: crate::ephemeral::Seen::default(),
            ephemeral_out: tokio::sync::broadcast::channel(EPHEMERAL_OUT).0,
        }
    }

    /// An ephemeral event a client sent here: delivered on every reactor and
    /// handed to the sync peers, once per id (a peer may have sent it first).
    pub fn client_ephemeral(&self, e: Arc<[u8]>) {
        if self.ephemeral_seen.first(Record(&e).id(), Instant::now()) {
            let _ = self.ephemeral_out.send(e.clone());
            self.broadcast(ReactorMsg::Ephemeral(e));
        }
    }

    /// One a sync peer relayed: delivered here, once per id, and never passed
    /// on, so it cannot circle between relays. False when it was a repeat.
    pub fn peer_ephemeral(&self, e: Arc<[u8]>) -> bool {
        let first = self.ephemeral_seen.first(Record(&e).id(), Instant::now());
        if first {
            self.broadcast(ReactorMsg::Ephemeral(e));
        }
        first
    }

    /// Counts a connection from `ip`, unless that IP is at its limit.
    fn admit(&self, ip: IpAddr) -> bool {
        // Loopback is never a client's own address: it is a service on this
        // machine (a push server, the operator's tools), or everyone who came
        // through Tor or I2P, which nginx caps per listener. One allowance
        // shared by all of them would turn the 257th Tor user away.
        if ip.is_loopback() {
            return true;
        }
        let l = &self.cfg.limits;
        let max = l.max_connections_per_ip;
        let now = Instant::now();
        let mut ips = self.ips.lock().unwrap();
        ips.sweep(now, l);
        let e = ips.map.entry(ip).or_insert_with(|| IpState::new(now, l));
        if max != 0 && e.conns >= max {
            return false;
        }
        e.conns += 1;
        true
    }

    fn release(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut ips = self.ips.lock().unwrap();
        if let Some(e) = ips.map.get_mut(&ip) {
            e.conns = e.conns.saturating_sub(1);
            if e.idle(now, &self.cfg.limits) {
                ips.map.remove(&ip);
            }
        }
    }

    /// Takes one new-connection token for `ip`, or says how many seconds until
    /// one is due. Asked before the WebSocket upgrade (see `accept`).
    pub fn allow_connection(&self, ip: IpAddr) -> Result<(), u64> {
        let l = &self.cfg.limits;
        let per_min = u64::from(l.connections_per_minute_per_ip);
        if per_min == 0 || ip.is_loopback() {
            return Ok(());
        }
        let now = Instant::now();
        let mut ips = self.ips.lock().unwrap();
        ips.sweep(now, l);
        let e = ips.map.entry(ip).or_insert_with(|| IpState::new(now, l));
        refill(&mut e.conn_tokens, &mut e.conn_last, now, per_min, u64::from(l.connection_burst_per_ip) * 1000);
        if e.conn_tokens >= 1000 {
            e.conn_tokens -= 1000;
            Ok(())
        } else {
            Err(((1000 - e.conn_tokens) * 60).div_ceil(per_min * 1000).max(1))
        }
    }

    /// Takes one EVENT token for `ip` (a bucket holding a minute's allowance,
    /// refilled continuously).
    fn take_event(&self, ip: IpAddr) -> bool {
        let per_min = u64::from(self.cfg.limits.events_per_minute_per_ip);
        if per_min == 0 || ip.is_loopback() {
            return true;
        }
        let mut ips = self.ips.lock().unwrap();
        let Some(e) = ips.map.get_mut(&ip) else { return true };
        refill(&mut e.tokens, &mut e.last, Instant::now(), per_min, per_min * 1000);
        if e.tokens >= 1000 {
            e.tokens -= 1000;
            true
        } else {
            false
        }
    }

    /// Every address's totals over the last `minutes` (to the slot), from each
    /// reactor's table and its open connections: the operator's `top`.
    pub fn top(&self, minutes: u64) -> FxMap<IpAddr, Agg> {
        let from = crate::ingest::now().saturating_sub(minutes * 60) / talk::SLOT_SECS;
        let (tx, rx) = std::sync::mpsc::channel();
        let reactors = self.reactors.get().map_or(0, Vec::len);
        self.broadcast(ReactorMsg::Top(Arc::new(crate::ingest::TopAsk { from, reply: tx })));
        let mut all: FxMap<IpAddr, Agg> = FxMap::default();
        for _ in 0..reactors {
            let Ok(part) = rx.recv_timeout(Duration::from_secs(5)) else { break };
            for (ip, a) in part {
                all.entry(ip).or_default().merge(&a);
            }
        }
        all
    }

    /// Heavy requests and bursts over the last `minutes`, from every reactor,
    /// with the bursts going on now: the operator's `heavy`.
    pub fn heavy(&self, minutes: u64) -> Vec<Heavy> {
        let from = heavy::now_ms().saturating_sub(minutes * 60_000);
        let (tx, rx) = std::sync::mpsc::channel();
        let reactors = self.reactors.get().map_or(0, Vec::len);
        self.broadcast(ReactorMsg::Heavy(Arc::new(crate::ingest::HeavyAsk { from, reply: tx })));
        let mut all = Vec::new();
        for _ in 0..reactors {
            let Ok(mut part) = rx.recv_timeout(Duration::from_secs(5)) else { break };
            all.append(&mut part);
        }
        all
    }

    pub fn broadcast(&self, msg: ReactorMsg) {
        for tx in self.reactors.get().expect("reactors registered") {
            let _ = tx.send(msg.clone());
        }
    }
}

/// One connection's outgoing bytes, filled by its own task and by fan-out.
struct ConnOut {
    buf: RefCell<Vec<u8>>,
    /// Event bodies shared by every subscriber they go to, each spliced into
    /// `buf` at an offset: written with one vectored write, never copied per
    /// connection. Only large live events take this path (see `SHARE_MIN`).
    spliced: RefCell<Vec<(usize, Rc<[u8]>)>>,
    spliced_bytes: Cell<usize>,
    notify: Notify,
    /// Set when the client fell too far behind; its task closes it.
    overflow: Cell<bool>,
    /// permessage-deflate, when the client asked for it.
    deflate: RefCell<Option<Compressor>>,
    /// Large live events may be shared rather than copied: a plain socket that
    /// does not compress (TLS and compression each need their own bytes).
    share: bool,
    /// A trusted peer's: events this relay took from clients are marked so.
    peer: bool,
    /// For the operator's `top`: who, with what, since when, and its counts.
    ip: IpAddr,
    ua: Box<str>,
    started: Instant,
    talk: Talk,
    /// Its bytes out at the reactor's last look, and a burst under way (see `heavy`).
    burst: Cell<heavy::Burst>,
}

impl ConnOut {
    /// The reactor's look for bursts, `us` after its last: one that ended, as a row.
    fn look(&self, now: u64, us: u64, last: bool) -> Option<Heavy> {
        let mut b = self.burst.get();
        let ended = b.look(now, us, self.talk.bytes_out.get(), self.talk.reqs.get(), last);
        self.burst.set(b);
        ended.map(|on| heavy::burst(on, self.ip, &self.ua, self.talk.shape.get(), false))
    }

    fn new(deflate: Option<Compressor>, plain: bool, peer: bool, ip: IpAddr, ua: Box<str>) -> ConnOut {
        ConnOut {
            share: plain && deflate.is_none(),
            peer,
            ip,
            ua,
            started: Instant::now(),
            talk: Talk::default(),
            burst: Cell::new(heavy::Burst::default()),
            buf: RefCell::new(Vec::new()),
            spliced: RefCell::new(Vec::new()),
            spliced_bytes: Cell::new(0),
            notify: Notify::new(),
            overflow: Cell::new(false),
            deflate: RefCell::new(deflate),
        }
    }

    /// Appends messages to this connection's output, compressed if it negotiated that.
    #[inline]
    fn write(&self, f: impl FnOnce(&mut WsOut<'_>)) {
        let mut buf = self.buf.borrow_mut();
        let mut z = self.deflate.borrow_mut();
        f(&mut WsOut { buf: &mut buf, z: z.as_mut() });
    }

    /// Bytes waiting to be written.
    #[inline]
    fn queued(&self) -> usize {
        self.buf.borrow().len() + self.spliced_bytes.get()
    }

    /// A live `["EVENT",sub,body]` with `body` shared rather than copied, or
    /// false when this connection needs its own bytes (it compresses).
    #[inline]
    fn event_shared(&self, sub: &str, body: &Rc<[u8]>) -> bool {
        if !self.share {
            return false;
        }
        let mut buf = self.buf.borrow_mut();
        let prefix = b"[\"EVENT\",\"".len() + sub.len() + 2;
        ws::write_frame_header(&mut buf, ws::Opcode::Text, true, prefix + body.len() + 1);
        buf.extend_from_slice(b"[\"EVENT\",\"");
        buf.extend_from_slice(sub.as_bytes());
        buf.extend_from_slice(b"\",");
        self.spliced.borrow_mut().push((buf.len(), body.clone()));
        self.spliced_bytes.set(self.spliced_bytes.get() + body.len());
        buf.push(b']');
        true
    }
}

/// Live events at least this large are shared between subscribers instead of
/// copied into each one's output. Below it a copy costs less than the extra
/// vectored-write entries.
const SHARE_MIN: usize = 1024;

struct Reactor {
    idx: usize,
    snap: Arc<Version>,
    subs: SubIndex,
    conns: FxMap<ConnId, Rc<ConnOut>>,
    parser: EventParser,
    rec: Vec<u8>,
    sigs: SigQueue,
    /// Read buffer shared by every connection on this reactor.
    scratch: Vec<u8>,
    /// Live batches relayed but not yet published, oldest first.
    pending: std::collections::VecDeque<Arc<crate::ingest::LiveBatch>>,
    /// Subscriptions waiting for a worker's answer to their REQ.
    held: HeldReqs,
    /// Closed connections' counts by address, for the operator's `top`.
    talk: TalkLog,
    /// Heavy requests and bursts, for the operator's `heavy`, and when this
    /// reactor last looked for bursts.
    heavy: HeavyLog,
    looked: Instant,
}

impl Reactor {
    /// Keeps a worker's request if it was slow or big (see `heavy`).
    fn note_worker(&mut self, what: What, conn: ConnId, took: &Took, events: u64, bytes: u64, m: &metrics::Block) {
        if heavy::is_heavy(took.wait_us + took.run_us, events, bytes) {
            metrics::inc(&m.requests_heavy);
            let ua: Box<str> = self.conns.get(&conn).map_or("".into(), |o| o.ua.clone());
            let h = Heavy { at: heavy::now_ms(), ip: took.ip, ua, what, path: Path::Worker, wait_us: took.wait_us, run_us: took.run_us, events, bytes, shape: took.shape, ongoing: false };
            self.heavy.push(h);
        }
    }
}

/// Frames each reply as a WebSocket text message: built in place, or, for a
/// connection that negotiated compression, built aside and compressed in.
struct WsOut<'a> {
    buf: &'a mut Vec<u8>,
    z: Option<&'a mut Compressor>,
}

thread_local! {
    /// Where a message for a compressing connection is built first (one per reactor).
    static STAGE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

impl Outbox for WsOut<'_> {
    #[inline]
    fn queued(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    fn text(&mut self, f: &mut dyn FnMut(&mut Vec<u8>)) {
        match self.z.as_deref_mut() {
            None => {
                let mark = ws::begin_text(self.buf);
                f(self.buf);
                ws::finish_text(self.buf, mark);
            }
            Some(z) => STAGE.with(|stage| {
                let mut stage = stage.borrow_mut();
                stage.clear();
                f(&mut stage);
                z.compress_text(self.buf, &stage);
                if stage.capacity() > 1 << 20 {
                    *stage = Vec::new();
                }
            }),
        }
    }
}

/// Binds the relay's one listener.
pub fn listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let s = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    s.set_reuseaddr(true)?;
    s.set_nodelay(true)?;
    s.bind(addr)?;
    let l = s.listen(4096)?;
    let l = l.into_std()?;
    // The acceptor thread blocks in accept(); connections become non-blocking
    // when their reactor adopts them.
    l.set_nonblocking(false)?;
    Ok(l)
}

/// Binds the Unix socket at `path` with permission bits `mode`. A socket file
/// already there is replaced when nothing answers on it (left by a relay that
/// did not stop cleanly); one that something answers on, or a file that is not
/// a socket, is refused.
pub fn unix_listener(path: &std::path::Path, mode: u32) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    // sun_path: 104 bytes with the NUL on macOS, 108 on Linux.
    if path.as_os_str().len() > 103 {
        return Err(io::Error::other("the path is too long for a Unix socket (at most 103 bytes): choose a shorter unix_socket"));
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_socket() => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "a file that is not a socket is in the way")),
        Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => return Err(io::Error::new(io::ErrorKind::AddrInUse, "another program is listening on it")),
            Err(_) => std::fs::remove_file(path)?,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(l)
}

/// Send and receive buffer asked for on each Unix connection (see
/// `relay_net::conn::unix_buffers`).
const UNIX_BUFFER: usize = 2 << 20;

/// [`accept_loop`] for the Unix socket. Its connections have no address: the
/// web server in front names the client in `real_ip_header`, and without that
/// they count as 127.0.0.1, like any local connection.
pub fn accept_loop_unix(l: std::os::unix::net::UnixListener, conns: Vec<mpsc::UnboundedSender<Incoming>>) {
    let local = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut next = 0usize;
    loop {
        match l.accept() {
            Ok((s, _)) => {
                relay_net::conn::unix_buffers(std::os::fd::AsRawFd::as_raw_fd(&s), UNIX_BUFFER);
                if s.set_nonblocking(true).is_ok() {
                    let _ = conns[next % conns.len()].send((Stream::Unix(s), local, None));
                    next = next.wrapping_add(1);
                }
            }
            Err(e) => {
                eprintln!("accept failed: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Accepts connections and deals them to reactors round-robin. SO_REUSEPORT
/// hashing leaves reactors idle when connections are few (eight benchmark
/// clients can land 3-3-1-1 or worse), and signature checks are per core, so an
/// idle reactor is lost throughput; dealing in turn places them exactly. `tls` is
/// set for the HTTPS listener: its connections do the TLS handshake on their reactor.
pub fn accept_loop(l: std::net::TcpListener, conns: Vec<mpsc::UnboundedSender<Incoming>>, tls: Option<TlsConfig>) {
    let mut next = 0usize;
    loop {
        match l.accept() {
            Ok((s, peer)) => {
                let _ = s.set_nodelay(true);
                if s.set_nonblocking(true).is_ok() {
                    let _ = conns[next % conns.len()].send((Stream::Tcp(s), peer, tls.clone()));
                    next = next.wrapping_add(1);
                }
            }
            Err(e) => {
                // Out of descriptors and the like: back off instead of spinning.
                eprintln!("accept failed: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Runs reactor `idx` on the current thread until the process exits.
pub fn run(
    idx: usize,
    shared: Arc<Shared>,
    mut conns: mpsc::UnboundedReceiver<Incoming>,
    rx: mpsc::UnboundedReceiver<ReactorMsg>,
) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        let st = Rc::new(RefCell::new(Reactor {
            idx,
            snap: shared.store.snapshot(),
            subs: SubIndex::default(),
            conns: FxMap::default(),
            parser: EventParser::new(),
            rec: Vec::new(),
            sigs: SigQueue::default(),
            scratch: vec![0; READ_CHUNK],
            pending: std::collections::VecDeque::new(),
            held: HeldReqs::default(),
            talk: TalkLog::default(),
            heavy: HeavyLog::default(),
            looked: Instant::now(),
        }));
        tokio::task::spawn_local(fanout(rx, st.clone(), shared.clone()));
        tokio::task::spawn_local(keep_fresh(st.clone(), shared.clone()));
        while let Some((s, peer, tls)) = conns.recv().await {
            tokio::task::spawn_local(connection(s, peer, tls, st.clone(), shared.clone()));
        }
    });
}

/// Lets go of the cached snapshot once a newer version is out, even when no
/// client message comes in to do it. The store reclaims what old versions pin
/// (deleted records' bytes, log segments replaced by compaction) only after
/// every reader has moved on, so an idle reactor must not hold one for long.
async fn keep_fresh(st: Rc<RefCell<Reactor>>, shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(SNAPSHOT_MAX_AGE);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let mut guard = st.borrow_mut();
        let r = &mut *guard;
        shared.store.refresh(&mut r.snap);
        // Once a second, also: which connections are taking a lot out.
        let us = micros(r.looked.elapsed());
        if us >= heavy::LOOK_US {
            r.looked = Instant::now();
            let now = heavy::now_ms();
            for o in r.conns.values() {
                if let Some(h) = o.look(now, us, false) {
                    metrics::inc(&shared.metrics.of(r.idx).bursts);
                    r.heavy.push(h);
                }
            }
        }
    }
}

/// COUNTs and REQs too big for a reactor, run on their own threads against the
/// snapshot the request saw; each answer goes back to the connection's reactor.
/// The queue is bounded: when it is full, a big request is refused, not queued.
pub fn count_workers(shared: &Arc<Shared>, workers: usize) {
    let (tx, rx) = std::sync::mpsc::sync_channel::<crate::ingest::Job>(COUNT_QUEUE);
    assert!(shared.counts.set(tx).is_ok(), "counting workers start once");
    let rx = Arc::new(Mutex::new(rx));
    for i in 0..workers {
        let (rx, shared) = (rx.clone(), shared.clone());
        std::thread::Builder::new()
            .name(format!("count-{i}"))
            .spawn(move || loop {
                let job = match rx.lock().unwrap().recv() {
                    Ok(j) => j,
                    Err(_) => return,
                };
                let (reactor, msg) = match job {
                    crate::ingest::Job::Count(job) => {
                        let start = Instant::now();
                        let n = job.snap.count_all(&job.filters, job.now);
                        let took = Box::new(Took { wait_us: micros(start - job.queued), run_us: micros(start.elapsed()), ..job.took });
                        (job.reactor, ReactorMsg::Count { conn: job.conn, sub: job.sub, n, took })
                    }
                    crate::ingest::Job::Req(job) => {
                        let start = Instant::now();
                        let mut c = session::Collect::default();
                        let a = session::answer(&job.snap, &job.filters, &job.limits, &job.sub, job.peer, job.now, job.max_outbound, &mut c);
                        metrics::add(&shared.metrics.of(job.reactor).events_out, a.sent);
                        let took = Took { wait_us: micros(start - job.queued), run_us: micros(start.elapsed()), ..job.took };
                        let ans = crate::ingest::ReqAnswer { conn: job.conn, sub: job.sub, token: job.token, msgs: c.buf, ends: c.ends, too_big: a.too_big, sent: a.sent, took };
                        (job.reactor, ReactorMsg::Req(Arc::new(ans)))
                    }
                };
                if let Some(r) = shared.reactors.get().and_then(|r| r.get(reactor)) {
                    let _ = r.send(msg);
                }
            })
            .expect("counting worker");
    }
}

/// Large COUNTs waiting for a worker before new ones are refused.
const COUNT_QUEUE: usize = 64;

fn micros(d: Duration) -> u64 {
    d.as_micros().min(u128::from(u64::MAX)) as u64
}

/// Clients' ephemeral events the sync thread may be behind on before the
/// oldest are skipped (they are live or worthless).
const EPHEMERAL_OUT: usize = 4096;

/// Delivers OK replies and live events from each committed batch.
async fn fanout(mut rx: mpsc::UnboundedReceiver<ReactorMsg>, st: Rc<RefCell<Reactor>>, shared: Arc<Shared>) {
    let mut targets = Vec::new();
    let mut json = Vec::new();
    let limit = shared.cfg.limits.outbound_buffer_bytes;
    // RELAY_DEBUG_WRITER: how long live batches take to reach this reactor.
    let debug = crate::ingest::debug();
    let (mut d_n, mut d_handoff, mut d_since_read, mut d_max) = (0u64, 0f64, 0f64, 0f64);
    let mut d_last = std::time::Instant::now();
    while let Some(msg) = rx.recv().await {
        let mut guard = st.borrow_mut();
        let r = &mut *guard;
        if debug {
            if let ReactorMsg::Live(b) = &msg {
                let h = b.sent.elapsed().as_secs_f64();
                d_n += 1;
                d_handoff += h;
                d_max = d_max.max(h);
                d_since_read += b.received.elapsed().as_secs_f64();
            }
            if d_last.elapsed().as_secs() >= 1 && d_n > 0 {
                eprintln!(
                    "reactor {}: {d_n} live batches, handoff {:.0} us avg ({:.0} max), EVENT read to fan-out {:.0} us avg",
                    r.idx,
                    d_handoff * 1e6 / d_n as f64,
                    d_max * 1e6,
                    d_since_read * 1e6 / d_n as f64
                );
                (d_n, d_handoff, d_since_read, d_max) = (0, 0.0, 0.0, 0.0);
                d_last = std::time::Instant::now();
            }
        }
        let (events, gen): (&[Arc<[u8]>], u64) = match &msg {
            ReactorMsg::Top(ask) => {
                let mut part = FxMap::default();
                r.talk.since(ask.from, &mut part);
                for o in r.conns.values() {
                    part.entry(o.ip).or_default().add(&o.talk, &o.ua, 0, true);
                }
                let _ = ask.reply.send(part);
                (&[], 0)
            }
            ReactorMsg::Heavy(ask) => {
                let mut part = Vec::new();
                r.heavy.since(ask.from, &mut part);
                for o in r.conns.values() {
                    if let Some(on) = o.burst.get().ongoing() {
                        part.push(heavy::burst(on, o.ip, &o.ua, o.talk.shape.get(), true));
                    }
                }
                let _ = ask.reply.send(part);
                (&[], 0)
            }
            ReactorMsg::Live(b) => {
                // Kept until published: a REQ answered from an older snapshot in
                // the meantime replays it (see Session::on_req).
                r.pending.push_back(b.clone());
                (&b.events, b.gen)
            }
            ReactorMsg::Replies(c) => {
                while r.pending.front().is_some_and(|p| p.gen <= c.gen) {
                    r.pending.pop_front();
                }
                let m = shared.metrics.of(r.idx);
                for reply in &c.replies[r.idx] {
                    let t = r.conns.get(&reply.conn).map(|o| &o.talk);
                    match reply.outcome {
                        Some(relay_store::Outcome::Stored(_)) => metrics::inc(&m.events_stored),
                        Some(relay_store::Outcome::Duplicate) => metrics::inc(&m.events_duplicate),
                        Some(relay_store::Outcome::Superseded) => session::Refused::Superseded.count(m, t),
                        Some(relay_store::Outcome::Deleted | relay_store::Outcome::Vanished) => session::Refused::Deleted.count(m, t),
                        _ => session::Refused::Other.count(m, t),
                    }
                    if let Some(o) = r.conns.get(&reply.conn) {
                        o.write(|w| session::ok_reply(w, reply));
                        o.notify.notify_one();
                    }
                }
                (&[], 0)
            }
            ReactorMsg::Ephemeral(e) => (std::slice::from_ref(e), u64::MAX),
            ReactorMsg::Count { conn, sub, n, took } => {
                if let Some(o) = r.conns.get(conn) {
                    o.write(|w| session::count_msg(w, sub, *n));
                    o.notify.notify_one();
                }
                r.note_worker(What::Count, *conn, took, 0, 0, shared.metrics.of(r.idx));
                (&[], 0)
            }
            ReactorMsg::Req(a) => {
                r.note_worker(What::Req, a.conn, &a.took, a.sent, a.msgs.len() as u64, shared.metrics.of(r.idx));
                // Unless the subscription was closed or replaced meanwhile: its
                // stored events, EOSE, then what came live while it was held.
                if let (Some(h), Some(o)) = (r.held.take(a.conn, &a.sub, a.token), r.conns.get(&a.conn)) {
                    let max = shared.scfg.max_outbound;
                    if a.too_big {
                        session::ReqRefused::Limits.count(shared.metrics.of(r.idx), Some(&o.talk));
                    }
                    o.write(|w| {
                        let mut start = 0;
                        for &end in &a.ends {
                            w.text(&mut |b| b.extend_from_slice(&a.msgs[start..end]));
                            start = end;
                        }
                        if a.too_big {
                            session::closed_too_big(w, &a.sub, max);
                        } else {
                            session::eose(w, &a.sub);
                            for rec in &h.recs {
                                session::event_msg(w, &a.sub, Record(rec), o.peer);
                            }
                        }
                    });
                    if a.too_big {
                        r.subs.remove(a.conn, &a.sub);
                    } else {
                        let m = shared.metrics.of(r.idx);
                        metrics::add(&m.events_out, h.recs.len() as u64);
                        metrics::add(&m.events_live, h.recs.len() as u64);
                    }
                    o.notify.notify_one();
                }
                (&[], 0)
            }
        };
        for rec in events {
            targets.clear();
            r.subs.matches(Record(rec), gen, &mut targets);
            if targets.is_empty() {
                continue;
            }
            // Encoded once, whatever the number of subscribers; a large one is
            // also stored once, shared by every plain connection it goes to.
            json.clear();
            Record(rec).write_json(&mut json);
            let body: Option<Rc<[u8]>> = (json.len() >= SHARE_MIN && targets.len() > 1).then(|| Rc::from(&json[..]));
            for (conn, sub) in &targets {
                let Some(o) = r.conns.get(conn) else { continue };
                // Held while a worker answers its REQ: after EOSE.
                if !r.held.is_empty() {
                    match r.held.keep(*conn, sub, rec) {
                        Some(true) => continue,
                        Some(false) => {
                            o.overflow.set(true);
                            o.notify.notify_one();
                            continue;
                        }
                        None => {}
                    }
                }
                if o.queued() > limit {
                    o.overflow.set(true);
                } else {
                    let m = shared.metrics.of(r.idx);
                    // The mark is this connection's own ending: not shared.
                    let mark = o.peer && Record(rec).is_first_hand();
                    if !mark && body.as_ref().is_some_and(|b| o.event_shared(sub, b)) {
                        metrics::inc(&m.events_shared);
                    } else {
                        o.write(|w| session::event_msg_json(w, sub, &json, mark));
                    }
                    metrics::inc(&m.events_out);
                    metrics::inc(&m.events_live);
                }
                o.notify.notify_one();
            }
        }
    }
}

/// Which of our trusted peers a connection is: `/peer/<secret>` naming a
/// `[[peer]]`, from one of that peer's addresses; both, or it is not. `None`
/// for any other path; `Some(None)` for a peer path that does not check out.
fn trusted_peer(peers: &[crate::config::PeerCfg], path: &str, ip: IpAddr) -> Option<Option<usize>> {
    let rest = path.strip_prefix("/peer/")?;
    let secret = rest.split(['?', '#', '/']).next().unwrap_or("").as_bytes();
    // Every secret compared in full: how long a comparison takes says nothing
    // about how much of a guess was right.
    let same = |a: &[u8], b: &[u8]| a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0;
    Some(peers.iter().enumerate().fold(None, |found, (i, p)| if same(p.secret.as_bytes(), secret) & p.ips.contains(&ip) { Some(i) } else { found }))
}

fn client_ip(req: &OwnedRequest, peer: SocketAddr, header: &str) -> IpAddr {
    let fallback = peer.ip().to_canonical();
    if header.is_empty() {
        return fallback;
    }
    // Right-most entry of the last header line: the one our own proxy appended.
    let Some((_, v)) = req.headers.iter().rev().find(|(n, _)| n == header) else { return fallback };
    let last = v.rsplit(|&b| b == b',').next().unwrap_or(&[]);
    std::str::from_utf8(last).ok().and_then(|s| s.trim().parse::<IpAddr>().ok()).map_or(fallback, |ip| ip.to_canonical())
}

/// An accepted connection: what serving it needs, and nothing of its
/// handshake (the request, its headers, the parser's state).
struct Accepted {
    s: Sock,
    buf: Vec<u8>,
    ip: IpAddr,
    deflate: Option<DeflateParams>,
    /// Which `[[peer]]` it is, if it is one.
    peer: Option<usize>,
    conn: ConnId,
    out: Rc<ConnOut>,
}

async fn connection(s: Stream, peer: SocketAddr, tls: Option<TlsConfig>, st: Rc<RefCell<Reactor>>, shared: Arc<Shared>) {
    // The handshake runs in a future of its own, freed once it is done: an
    // async fn's state is as large as its largest phase, and every idle
    // connection carried the handshake's (and kept its request's headers).
    let Some(a) = Box::pin(accept(s, peer, tls, &st, &shared)).await else { return };
    let Accepted { mut s, mut buf, ip, deflate, peer, conn, out } = a;
    let _ = serve(&mut s, &mut buf, conn, ip, deflate, peer, &out, &st, &shared).await;

    {
        let mut r = st.borrow_mut();
        r.subs.remove_conn(conn);
        r.held.release_conn(conn);
        r.conns.remove(&conn);
        if let Some(h) = out.look(heavy::now_ms(), micros(r.looked.elapsed()), true) {
            metrics::inc(&shared.metrics.of(r.idx).bursts);
            r.heavy.push(h);
        }
        r.talk.fold(crate::ingest::now(), ip, &out.ua, &out.talk, out.started.elapsed().as_secs());
    }
    shared.release(ip);
    shared.metrics.open.fetch_sub(1, Ordering::Relaxed);
}

/// TLS (on the HTTPS listener), the WebSocket handshake, and admission: the
/// connection, ready to serve, or `None` once it has been answered or refused.
async fn accept(s: Stream, peer: SocketAddr, tls: Option<TlsConfig>, st: &Rc<RefCell<Reactor>>, shared: &Arc<Shared>) -> Option<Accepted> {
    // Clients of the HTTPS listener connect to the relay directly, so a header
    // naming "the real address" is theirs to forge: only the socket's peer counts.
    let real_ip_header = if tls.is_some() { "" } else { shared.cfg.relay.real_ip_header.as_str() };
    let mut s = Sock::open(s, tls).await?;
    let mut buf = Vec::with_capacity(4096);
    let policy = match shared.cfg.relay.deflate_policy() {
        Some(p) => ExtensionPolicy::with_deflate(p),
        None => ExtensionPolicy::NONE,
    };
    let idx = st.borrow().idx;
    // An address opening connections faster than its allowance is answered
    // 429 before the upgrade. A trusted peer is not held to it.
    let check = |req: &OwnedRequest| {
        let ip = client_ip(req, peer, real_ip_header);
        if matches!(trusted_peer(&shared.cfg.peers, &req.path, ip), Some(Some(_))) {
            return None;
        }
        shared.allow_connection(ip).err().map(|wait| {
            metrics::inc(&shared.metrics.of(idx).connections_rate_limited);
            let ua = req.headers.iter().find(|(n, _)| n == "user-agent").map_or_else(String::new, |(_, v)| String::from_utf8_lossy(&v[..v.len().min(96)]).into_owned());
            st.borrow_mut().talk.limited(crate::ingest::now(), ip, &ua);
            Refusal { status: 429, retry_after: Some(wait), message: "rate-limited: too many new connections from your address" }
        })
    };
    let (req, deflate) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, server_handshake_checked(&mut s, &mut buf, MAX_HEAD, &policy, check)).await {
        Ok(Ok((Handshake::Upgraded(req), ext))) => (req, ext.deflate),
        Ok(Ok((Handshake::PlainHttp(req), _))) => {
            let _ = plain_http(&mut s, &req, shared).await;
            return None;
        }
        _ => return None,
    };
    let ip = client_ip(&req, peer, real_ip_header);
    let peer = match trusted_peer(&shared.cfg.peers, &req.path, ip) {
        None => None,
        Some(Some(i)) => Some(i),
        Some(None) => {
            metrics::inc(&shared.metrics.of(idx).connections_refused);
            let mut out = Vec::new();
            ws::write_close(&mut out, 1008, "not a known peer");
            let _ = s.write_all(&out).await;
            return None;
        }
    };
    if !shared.admit(ip) {
        metrics::inc(&shared.metrics.of(idx).connections_refused);
        let mut out = Vec::new();
        ws::write_close(&mut out, 1008, "too many connections from your address");
        let _ = s.write_all(&out).await;
        return None;
    }
    shared.metrics.open.fetch_add(1, Ordering::Relaxed);
    metrics::inc(&shared.metrics.of(idx).connections_total);
    let conn = shared.next_conn.fetch_add(1, Ordering::Relaxed);
    let z = deflate.map(|p| Compressor::for_role(&p, Role::Server, Compressor::DEFAULT_MIN_LEN));
    if z.is_some() {
        metrics::inc(&shared.metrics.of(idx).connections_deflate);
    }
    let ua: Box<str> = req.headers.iter().find(|(n, _)| n == "user-agent").map_or_else(Box::default, |(_, v)| String::from_utf8_lossy(&v[..v.len().min(96)]).into());
    let out = Rc::new(ConnOut::new(z, s.is_clear(), peer.is_some(), ip, ua));
    st.borrow_mut().conns.insert(conn, out.clone());

    Some(Accepted { s, buf, ip, deflate, peer, conn, out })
}

/// The least time a write to a client may take before the client counts as
/// gone; larger writes get more, at 64 KB/s.
const WRITE_STALL: Duration = Duration::from_secs(60);

/// Runs a write to the client, unless the client has stopped reading: then
/// false, and the connection is dropped. That is when live events have piled
/// up past its outbound limit behind the write, or when the write outlasts
/// its time budget. Without this a client that never reads kept its
/// connection, and everything buffered for it, forever: the overflow close
/// was only looked at between writes, and the write never finished.
/// A write that completes at once polls nothing else (no timer is armed).
async fn finish_write(write: impl std::future::Future<Output = io::Result<()>>, out: &ConnOut, len: usize) -> io::Result<bool> {
    let budget = WRITE_STALL.max(Duration::from_millis((len / 64) as u64));
    let overflowed = async {
        loop {
            out.notify.notified().await;
            if out.overflow.get() {
                return;
            }
        }
    };
    tokio::select! {
        biased;
        r = write => r.map(|()| true),
        () = overflowed => Ok(false),
        () = tokio::time::sleep(budget) => Ok(false),
    }
}

/// Writes `buf` with each shared body inserted at its offset, in vectored writes.
async fn write_spliced(s: &mut Sock, buf: &[u8], spliced: &[(usize, Rc<[u8]>)]) -> io::Result<()> {
    // Only unencrypted connections share bodies (`ConnOut::share`).
    match s {
        Sock::Plain(s) => write_vectored_all(s, buf, spliced).await,
        Sock::Unix(s) => write_vectored_all(s, buf, spliced).await,
        Sock::Tls(_) => Err(io::Error::other("spliced output on an encrypted connection")),
    }
}

async fn write_vectored_all<W: AsyncWrite + Unpin>(s: &mut W, buf: &[u8], spliced: &[(usize, Rc<[u8]>)]) -> io::Result<()> {
    let mut parts: Vec<io::IoSlice<'_>> = Vec::with_capacity(spliced.len() * 2 + 1);
    let mut at = 0;
    for (off, body) in spliced {
        parts.push(io::IoSlice::new(&buf[at..*off]));
        parts.push(io::IoSlice::new(body));
        at = *off;
    }
    parts.push(io::IoSlice::new(&buf[at..]));
    let mut rest = &mut parts[..];
    while !rest.is_empty() {
        // IOV_MAX is 1024 on Linux and macOS.
        let n = s.write_vectored(&rest[..rest.len().min(1024)]).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        io::IoSlice::advance_slices(&mut rest, n);
    }
    Ok(())
}

/// Bytes read per readiness event, into the reactor's shared scratch buffer.
const READ_CHUNK: usize = 64 * 1024;

/// Work one connection may do before letting the reactor's other tasks run.
/// A burst of 64 EVENTs is ~4 ms of signature checks; without a budget, live
/// deliveries and REQs on the same core would wait behind all of it.
const TURN_BUDGET: Duration = Duration::from_micros(300);

/// What one pass over a buffer did.
struct Pass {
    /// Bytes used (a trailing partial frame, or frames left for the next turn, remain).
    used: usize,
    closing: bool,
    /// Stopped on the time budget with whole frames still unprocessed.
    more: bool,
    /// The read's EVENTs went to the verifier threads: finish them when their
    /// verdicts come back, before anything else from this connection.
    wait: Option<oneshot::Receiver<Job>>,
}

/// Runs `f` with this reactor's context for a session, its replies going to `out`.
fn with_cx(st: &RefCell<Reactor>, shared: &Shared, ip: IpAddr, conn: ConnId, out: &ConnOut, f: impl FnOnce(&mut Ctx<'_>, &mut WsOut<'_>)) {
    let broadcast = |m: ReactorMsg| match m {
        ReactorMsg::Ephemeral(e) => shared.client_ephemeral(e),
        m => shared.broadcast(m),
    };
    let allow_event = || shared.take_event(ip);
    let offload = |job: crate::ingest::Job| shared.counts.get().is_some_and(|q| q.try_send(job).is_ok());
    let mut guard = st.borrow_mut();
    let r = &mut *guard;
    shared.store.refresh(&mut r.snap);
    let mut cx = Ctx {
        cfg: &shared.scfg,
        store: &shared.store,
        snap: &mut r.snap,
        subs: &mut r.subs,
        writer: &shared.writer,
        reactor: r.idx,
        broadcast: &broadcast,
        allow_event: &allow_event,
        parser: &mut r.parser,
        rec: &mut r.rec,
        sigs: &mut r.sigs,
        now: crate::ingest::now(),
        m: shared.metrics.of(r.idx),
        pending: &r.pending,
        offload: &offload,
        held: &mut r.held,
        conn,
        talk: &out.talk,
        ip: out.ip,
        ua: &out.ua,
        heavy: &mut r.heavy,
    };
    out.write(|w| f(&mut cx, w));
}

/// Decodes and answers whole frames in `data` until the buffer or the turn's
/// time budget runs out. EVENTs among them have their signatures checked
/// together once the frames are done (or before any other kind of frame).
fn process(data: &mut [u8], dec: &mut Decoder, session: &mut Session, out: &ConnOut, st: &RefCell<Reactor>, shared: &Shared, ip: IpAddr) -> Pass {
    let conn = session.conn;
    let mut p = process_frames(data, dec, session, out, st, shared, ip);
    let n = st.borrow().sigs.len();
    if n > 0 && session.batches() && shared.verify.wants(n) {
        let job = std::mem::take(&mut st.borrow_mut().sigs.job);
        p.wait = Some(shared.verify.submit(job));
    } else {
        with_cx(st, shared, ip, conn, out, |cx, w| session.flush_events(cx, w));
    }
    p
}

/// Finishes a read's EVENTs once the verifier threads have checked them, and
/// gives the job's buffers back to the reactor for the next read.
async fn finish(rx: oneshot::Receiver<Job>, session: &mut Session, out: &ConnOut, st: &RefCell<Reactor>, shared: &Shared, ip: IpAddr) -> io::Result<()> {
    let mut job = rx.await.map_err(|_| io::Error::other("the signature verifiers stopped"))?;
    with_cx(st, shared, ip, session.conn, out, |cx, w| session.finish_job(&job, cx, w));
    job.clear();
    let mut r = st.borrow_mut();
    if r.sigs.job.recs.capacity() == 0 {
        r.sigs.job = job;
    }
    Ok(())
}

fn process_frames(data: &mut [u8], dec: &mut Decoder, session: &mut Session, out: &ConnOut, st: &RefCell<Reactor>, shared: &Shared, ip: IpAddr) -> Pass {
    let conn = session.conn;
    let started = Instant::now();
    let mut off = 0;
    loop {
        // Out of time, or a full queue of EVENTs to check before reading on.
        if off > 0 && (started.elapsed() >= TURN_BUDGET || st.borrow().sigs.len() >= session.queue_cap()) {
            return Pass { used: off, closing: false, more: true, wait: None };
        }
        let d = match dec.decode(&mut data[off..]) {
            Ok(d) => d,
            Err(e) => {
                with_cx(st, shared, ip, conn, out, |cx, w| session.flush_events(cx, w));
                ws::write_close(&mut out.buf.borrow_mut(), e.close_code(), e.reason());
                return Pass { used: off, closing: true, more: false, wait: None };
            }
        };
        off += d.consumed;
        match d.event {
            Some(Event::Text(t)) => {
                metrics::inc(&shared.metrics.of(st.borrow().idx).messages_in);
                with_cx(st, shared, ip, conn, out, |cx, w| session.on_text(t, cx, w));
            }
            Some(Event::Binary(_)) => {
                with_cx(st, shared, ip, conn, out, |cx, w| {
                    session.flush_events(cx, w);
                    session::notice(w, "error: binary messages are not supported");
                });
            }
            Some(Event::Ping(p)) => ws::write_pong(&mut out.buf.borrow_mut(), p),
            Some(Event::Pong(_)) => {}
            Some(Event::Close(c)) => {
                // Nothing may follow the close frame: answer queued EVENTs first.
                with_cx(st, shared, ip, conn, out, |cx, w| session.flush_events(cx, w));
                let mut b = out.buf.borrow_mut();
                match c {
                    Some((code, _)) => ws::write_close(&mut b, code, ""),
                    None => ws::write_close_empty(&mut b),
                }
                return Pass { used: off, closing: true, more: false, wait: None };
            }
            None => return Pass { used: off, closing: false, more: false, wait: None },
        }
    }
}

/// Runs one WebSocket connection. Reads land in the reactor's shared scratch
/// buffer and are decoded in place; the connection keeps bytes of its own only
/// while a frame is split across reads, and frees them as soon as it is whole,
/// so an idle connection costs almost nothing.
#[allow(clippy::too_many_arguments)]
async fn serve(
    s: &mut Sock,
    buf: &mut Vec<u8>,
    conn: ConnId,
    ip: IpAddr,
    deflate: Option<DeflateParams>,
    peer: Option<usize>,
    out: &Rc<ConnOut>,
    st: &Rc<RefCell<Reactor>>,
    shared: &Arc<Shared>,
) -> io::Result<()> {
    let max = shared.cfg.limits.max_message_bytes;
    let mut dec = Decoder::server(max, max);
    if let Some(p) = &deflate {
        dec = dec.with_deflate(p);
    }
    let mut session = Session::new(conn, peer.map(|i| shared.links[i].clone()));
    let mut wbuf = Vec::new();
    let mut wspliced: Vec<(usize, Rc<[u8]>)> = Vec::new();
    let mut last_rx = Instant::now();
    let mut pinged = false;
    // Frames that arrived with the handshake.
    let p = process(&mut buf[..], &mut dec, &mut session, out, st, shared, ip);
    buf.drain(..p.used);
    *buf = buf.to_vec();
    let (mut closing, mut more, mut waiting) = (p.closing, p.more, p.wait);
    loop {
        // A read's EVENTs are answered before anything after them is read.
        if let Some(rx) = waiting.take() {
            finish(rx, &mut session, out, st, shared, ip).await?;
        }
        // Flush (taking the buffer, so fan-out keeps appending to a fresh one).
        if out.overflow.get() {
            ws::write_close(&mut out.buf.borrow_mut(), 1008, "too slow: messages were piling up");
            metrics::inc(&shared.metrics.of(st.borrow().idx).slow_drops);
            closing = true;
        }
        if !out.buf.borrow().is_empty() {
            std::mem::swap(&mut wbuf, &mut *out.buf.borrow_mut());
            std::mem::swap(&mut wspliced, &mut *out.spliced.borrow_mut());
            let spliced = out.spliced_bytes.replace(0);
            metrics::add(&shared.metrics.of(st.borrow().idx).bytes_out, (wbuf.len() + spliced) as u64);
            let len = wbuf.len() + spliced;
            out.talk.bytes_out.set(out.talk.bytes_out.get() + len as u64);
            let write = async {
                if wspliced.is_empty() {
                    s.write_all(&wbuf).await
                } else {
                    write_spliced(s, &wbuf, &wspliced).await
                }
            };
            if !finish_write(write, out, len).await? {
                // The client stopped reading: nothing more can reach it.
                metrics::inc(&shared.metrics.of(st.borrow().idx).slow_drops);
                return Ok(());
            }
            // The overflow watch may have taken the wakeup for what was queued
            // during the write: give it back, or that waits for the next one.
            if !out.buf.borrow().is_empty() {
                out.notify.notify_one();
            }
            wspliced.clear();
            wbuf.clear();
            // Idle connections keep no output buffer; a busy one keeps a modest one.
            if wbuf.capacity() > 64 * 1024 {
                wbuf = Vec::new();
            }
        }
        if closing {
            return Ok(());
        }
        if more {
            // Out of budget with frames left: let the reactor's other tasks run.
            tokio::task::yield_now().await;
            let p = process(&mut buf[..], &mut dec, &mut session, out, st, shared, ip);
            buf.drain(..p.used);
            (closing, more, waiting) = (p.closing, p.more, p.wait);
            if buf.is_empty() && buf.capacity() > 0 {
                *buf = Vec::new();
            }
            continue;
        }

        // Wait for input, queued output, or the idle timer.
        let idle_at = last_rx + if pinged { IDLE_PING * 2 } else { IDLE_PING };
        tokio::select! {
            r = s.readable() => {
                r?;
                let mut scratch = std::mem::take(&mut st.borrow_mut().scratch);
                scratch.resize(READ_CHUNK, 0);
                let result = s.try_read(&mut scratch);
                match result {
                    Ok(0) => {
                        st.borrow_mut().scratch = scratch;
                        return Ok(());
                    }
                    Ok(n) => {
                        metrics::add(&shared.metrics.of(st.borrow().idx).bytes_in, n as u64);
                        last_rx = Instant::now();
                        pinged = false;
                        if buf.is_empty() {
                            // The common case: decode straight from the scratch buffer.
                            let p = process(&mut scratch[..n], &mut dec, &mut session, out, st, shared, ip);
                            buf.extend_from_slice(&scratch[p.used..n]);
                            (closing, more, waiting) = (p.closing, p.more, p.wait);
                        } else {
                            buf.extend_from_slice(&scratch[..n]);
                            let p = process(&mut buf[..], &mut dec, &mut session, out, st, shared, ip);
                            buf.drain(..p.used);
                            (closing, more, waiting) = (p.closing, p.more, p.wait);
                        }
                        if buf.is_empty() && buf.capacity() > 0 {
                            *buf = Vec::new();
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        st.borrow_mut().scratch = scratch;
                        return Err(e);
                    }
                }
                st.borrow_mut().scratch = scratch;
            }
            _ = out.notify.notified() => {}
            _ = tokio::time::sleep_until(idle_at.into()) => {
                if pinged {
                    return Ok(());
                }
                ws::write_ping(&mut out.buf.borrow_mut(), b"");
                pinged = true;
            }
        }
    }
}

/// Plain HTTP: the NIP-11 document for `Accept: application/nostr+json`, a short
/// note otherwise.
async fn plain_http(s: &mut Sock, req: &OwnedRequest, shared: &Shared) -> io::Result<()> {
    let mut out = Vec::new();
    let cors = [
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Headers", "*"),
        ("Access-Control-Allow-Methods", "GET, OPTIONS"),
    ];
    let path = req.path.split('?').next().unwrap_or("");
    // Pages are known by their last segment, so they work wherever a web
    // server mounts the relay: /stats, and /nostr/stats behind nginx's /nostr.
    let page = path.rsplit('/').next().unwrap_or("");
    if req.method == "OPTIONS" {
        write_response(&mut out, 204, "No Content", "text/plain", &cors, b"", true);
    } else if page == "dashboard" {
        // Reads `stats` beside it, relative to where it is served.
        write_response(&mut out, 200, "OK", "text/html; charset=utf-8", &[], include_str!("dashboard.html").as_bytes(), true);
    } else if page == "stats" {
        write_response(&mut out, 200, "OK", "application/json", &cors, crate::stats::json(shared).as_bytes(), true);
    } else if page == "metrics" {
        write_response(&mut out, 200, "OK", "text/plain; version=0.0.4", &[], crate::stats::prometheus(shared).as_bytes(), true);
    } else if page == "live" {
        write_response(&mut out, 200, "OK", "application/json", &cors, crate::landing::live_json(shared).as_bytes(), true);
    } else if page == "font" {
        // No extension: web servers' static-file rules (`\.woff2$`) would take it.
        write_response(&mut out, 200, "OK", "font/woff2", &[("Cache-Control", "public, max-age=604800")], crate::landing::FONT, true);
    } else if req.accepts("application/nostr+json") {
        write_response(&mut out, 200, "OK", "application/nostr+json", &cors, shared.nip11.as_bytes(), true);
    } else {
        write_response(&mut out, 200, "OK", "text/html; charset=utf-8", &[], crate::landing::page(shared, path).as_bytes(), true);
    }
    s.write_all(&out).await?;
    s.shutdown().await
}

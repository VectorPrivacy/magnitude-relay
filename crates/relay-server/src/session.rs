//! The protocol, one connection at a time: what each client message does and
//! what goes back. No sockets here; replies are written into an [`Outbox`]
//! (the WebSocket layer frames them in place), so all of it is testable alone.

use crate::heavy::{self, HeavyLog, Path, What};
use crate::lists::KeyList;
use crate::ingest::{ReactorMsg, Reply, WriteReq};
use crate::metrics::{self, Block};
use crate::subs::{ConnId, SubIndex};
use crate::sync::PeerLink;
use crate::talk::{bump, Shape, Talk};
use relay_proto::event::EventInfo;
use relay_proto::json::{escape_str, Scanner};
use relay_proto::message::{ClientMsg, MsgError};
use relay_proto::negentropy::{self, VecStorage};
use crate::verify::{Checked, Checker, Job, Verdict};
use relay_proto::{hex, kind, EventParser, Filter, Record};
use relay_store::{Outcome, Store, Version};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;

/// Where replies go: one call per protocol message.
pub trait Outbox {
    fn text(&mut self, f: &mut dyn FnMut(&mut Vec<u8>));
    /// Bytes already waiting to be written to this connection.
    fn queued(&self) -> usize;
}

/// Why an EVENT was refused, for the counters; the message tells the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Kind,
    Invalid,
    Protected,
    Rate,
    Superseded,
    Deleted,
    Other,
}

impl Refused {
    /// Counts one, under its reason and in the total, and against its
    /// connection when it has one.
    #[inline]
    pub fn count(self, m: &Block, t: Option<&Talk>) {
        if let Some(t) = t {
            bump(&t.refused);
        }
        metrics::inc(&m.events_refused);
        metrics::inc(match self {
            Refused::Kind => &m.events_refused_kind,
            Refused::Invalid => &m.events_refused_invalid,
            Refused::Protected => &m.events_refused_protected,
            Refused::Rate => &m.events_refused_rate,
            Refused::Superseded => &m.events_refused_superseded,
            Refused::Deleted => &m.events_refused_deleted,
            Refused::Other => &m.events_refused_other,
        });
    }
}

/// Why a REQ, COUNT or NEG-OPEN was refused, for the counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReqRefused {
    Wraps,
    Limits,
    Invalid,
    Busy,
}

impl ReqRefused {
    #[inline]
    pub fn count(self, m: &Block, t: Option<&Talk>) {
        if let (ReqRefused::Wraps, Some(t)) = (self, t) {
            bump(&t.wraps);
        }
        metrics::inc(match self {
            ReqRefused::Wraps => &m.reqs_refused_wraps,
            ReqRefused::Limits => &m.reqs_refused_limits,
            ReqRefused::Invalid => &m.reqs_refused_invalid,
            ReqRefused::Busy => &m.reqs_refused_busy,
        });
    }
}

/// The limits and policy a session enforces (built once from the config).
pub struct SessionCfg {
    pub max_subscriptions: usize,
    pub max_filters: usize,
    pub max_filter_values: usize,
    pub default_limit: usize,
    pub max_limit: usize,
    pub max_event_bytes: usize,
    pub max_future_seconds: u64,
    pub max_tags: usize,
    /// The bytes a connection may have waiting: live events past it close the
    /// connection, and a REQ's stored results stop at it.
    pub max_outbound: usize,
    pub kind_allowed: Box<dyn Fn(u64) -> bool + Send + Sync>,
    /// `deny_kinds`: refused even from an allowlisted author.
    pub kind_denied: Box<dyn Fn(u64) -> bool + Send + Sync>,
    pub bans: Option<Arc<KeyList>>,
    /// Authors whose events may be of any kind but a denied one.
    pub allowed: Option<Arc<KeyList>>,
}

impl SessionCfg {
    pub fn from_config(cfg: &crate::config::Config) -> Result<SessionCfg, String> {
        let kinds = cfg.policy.kind_policy();
        let denied = cfg.policy.deny_kinds.clone();
        let bans = KeyList::banlist(cfg)?;
        let allowed = KeyList::allowlist(cfg)?;
        Ok(SessionCfg {
            max_subscriptions: cfg.limits.max_subscriptions,
            max_filters: cfg.limits.max_filters,
            max_filter_values: cfg.limits.max_filter_values,
            default_limit: cfg.limits.default_limit,
            max_limit: cfg.limits.max_limit,
            max_event_bytes: cfg.policy.max_event_bytes,
            max_future_seconds: cfg.policy.max_future_seconds,
            max_tags: cfg.policy.max_tags,
            max_outbound: cfg.limits.outbound_buffer_bytes,
            kind_allowed: Box::new(move |k| kinds.allows(k)),
            kind_denied: Box::new(move |k| denied.contains(&k)),
            bans,
            allowed,
        })
    }

    /// Whether an event of a kind the policy refuses is let in for its author.
    #[inline]
    fn lets_in(&self, author: &[u8; 32], kind: u64) -> bool {
        self.allowed.as_ref().is_some_and(|l| l.with(|s| s.contains(author))) && !(self.kind_denied)(kind)
    }

    /// Whether a valid event is to be answered `OK` and dropped (see `bans`).
    #[inline]
    pub fn silences(&self, rec: Record<'_>) -> bool {
        self.bans.as_ref().is_some_and(|b| b.with(|s| s.silences(rec)))
    }

    /// Why an event is refused on policy alone, before anything is hashed:
    /// the same answer for a client's EVENT and for an event synced in.
    pub fn refusal(&self, info: &EventInfo, rec: Record<'_>, now: u64) -> Option<(Refused, String)> {
        if !(self.kind_allowed)(info.kind) && !self.lets_in(rec.pubkey(), info.kind) {
            Some((Refused::Kind, format!("blocked: kind {} is not accepted by this relay", info.kind)))
        } else if info.tag_count as usize > self.max_tags {
            Some((Refused::Invalid, String::from("invalid: too many tags")))
        } else if info.created_at > now + self.max_future_seconds {
            Some((Refused::Invalid, String::from("invalid: created_at is too far in the future")))
        } else if info.expiration.is_some_and(|e| e <= now) {
            Some((Refused::Invalid, String::from("invalid: event has already expired")))
        } else if info.protected {
            // NIP-70 needs AUTH to prove authorship, and this relay never uses AUTH.
            Some((Refused::Protected, String::from("blocked: protected events are not accepted here")))
        } else if rec.json_len() > self.max_event_bytes {
            Some((Refused::Invalid, format!("invalid: event is larger than {} bytes", self.max_event_bytes)))
        } else {
            None
        }
    }
}

/// Everything a session needs from its reactor.
pub struct Ctx<'a> {
    pub cfg: &'a SessionCfg,
    pub store: &'a Store,
    pub snap: &'a mut Arc<Version>,
    pub subs: &'a mut SubIndex,
    pub writer: &'a SyncSender<WriteReq>,
    pub reactor: usize,
    /// Delivers an ephemeral event to every reactor, this one included.
    pub broadcast: &'a dyn Fn(ReactorMsg),
    /// Takes one EVENT from the client IP's allowance; false when it is spent.
    pub allow_event: &'a dyn Fn() -> bool,
    pub parser: &'a mut EventParser,
    pub rec: &'a mut Vec<u8>,
    /// Events from this read waiting for their signature check.
    pub sigs: &'a mut SigQueue,
    pub now: u64,
    /// This reactor's counters.
    pub m: &'a Block,
    /// Live batches this reactor relayed that are not yet published.
    pub pending: &'a std::collections::VecDeque<Arc<crate::ingest::LiveBatch>>,
    /// Hands a large COUNT or REQ to the query workers; false when they are full.
    pub offload: &'a dyn Fn(crate::ingest::Job) -> bool,
    /// This reactor's subscriptions whose stored events a worker is finding.
    pub held: &'a mut HeldReqs,
    /// This reactor's NEG-OPENs a worker is answering, and the sets built for them.
    pub negs: &'a mut HeldNegs,
    pub conn: ConnId,
    /// This connection's counts, for the operator's `top`.
    pub talk: &'a Talk,
    /// Who is asking, and this reactor's heavy requests, for the operator's `heavy`.
    pub ip: std::net::IpAddr,
    pub ua: &'a str,
    pub heavy: &'a mut HeavyLog,
}

impl Ctx<'_> {
    /// Keeps a request answered here if it was slow or big. Only the
    /// comparison is on every request's path.
    #[inline]
    fn note(&mut self, what: What, path: Path, filters: &[Filter], run_us: u64, events: u64, bytes: u64) {
        if heavy::is_heavy(run_us, events, bytes) {
            self.keep(what, path, filters, run_us, events, bytes);
        }
    }

    #[cold]
    #[inline(never)]
    fn keep(&mut self, what: What, path: Path, filters: &[Filter], run_us: u64, events: u64, bytes: u64) {
        metrics::inc(&self.m.requests_heavy);
        let at = heavy::now_ms();
        let shape = Shape::of(filters);
        self.heavy.push(heavy::Heavy { at, ip: self.ip, ua: self.ua.into(), what, path, wait_us: 0, run_us, events, bytes, shape, ongoing: false });
    }

    /// What a worker's answer must carry back to be kept (see `note`).
    fn took(&self, filters: &[Filter]) -> (std::time::Instant, heavy::Took) {
        (std::time::Instant::now(), heavy::Took { ip: self.ip, shape: Shape::of(filters), wait_us: 0, run_us: 0 })
    }
}

/// COUNTs expected to walk more index keys than this (about 2.5 ms of work)
/// go to the counting workers, so one big count never stalls a reactor's other
/// connections. Smaller ones are answered on the spot.
const INLINE_COUNT_KEYS: u64 = 50_000;
/// REQs expected to read more index entries than this (a few ms with their
/// records), or to seek more ranges than `INLINE_REQ_RANGES`, are answered by
/// the query workers: four clients sending 50-filter REQs had held every
/// other connection on their reactors for 400 ms at a time. A range costs
/// about 3.5 us to seek, so 1024 of them is the same few ms: a Concord
/// subscription (hundreds of plane keys x 1059 and 21059) stays on the
/// reactors, all of them at once, instead of queueing for a worker.
const INLINE_REQ_COST: u64 = 20_000;
const INLINE_REQ_RANGES: usize = 1024;
/// When the workers' queue is full, a REQ up to this size is answered on the
/// spot rather than refused: up to 2000 authors x 4 kinds, the most Vector and
/// Concord ask for, so a reconnect burst is slower, never refused. Bigger
/// ones (only hostile clients send them) get `rate-limited`.
const FALLBACK_REQ_COST: u64 = 200_000;
const FALLBACK_REQ_RANGES: usize = 8192;
/// The same for a COUNT: up to this many index keys are counted on the spot.
const FALLBACK_COUNT_KEYS: u64 = 1_000_000;
/// NEG-OPENs whose set is expected to hold more than this many records (a
/// few ms at 0.1-0.7 us a record) are built and first reconciled by the
/// query workers: a trusted peer's passes, 100 000 to 500 000 records a
/// window, had held every other connection on their reactors for 71-344 ms.
/// Vector's mailboxes, thousands of records, stay on the reactors.
const INLINE_NEG_ITEMS: u64 = 20_000;
/// When the workers' queue is full, a set up to this size is built on the
/// spot; a bigger one is refused, and a peer's pass tries again later.
const FALLBACK_NEG_ITEMS: u64 = 200_000;
/// Not "too many": a peer takes that for a window too large and splits it.
const NEG_BUSY: &str = "rate-limited: the relay is busy with large requests, try again shortly";
/// Live events a held subscription keeps before its connection counts as
/// unable to keep up.
const HELD_MAX: usize = 4096;

/// Subscriptions whose stored events a worker is still finding: their live
/// events wait here, to go out after EOSE (stored, then EOSE, then live, as
/// for a REQ answered on the spot). One per reactor.
#[derive(Default)]
pub struct HeldReqs {
    by_conn: crate::subs::FxMap<ConnId, Vec<HeldReq>>,
    next_token: u64,
}

pub struct HeldReq {
    sub: Box<str>,
    token: u64,
    pub recs: Vec<Arc<[u8]>>,
}

impl HeldReqs {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.by_conn.is_empty()
    }

    fn hold(&mut self, conn: ConnId, sub: &str, recs: Vec<Arc<[u8]>>) -> u64 {
        self.release(conn, sub);
        self.next_token += 1;
        self.by_conn.entry(conn).or_default().push(HeldReq { sub: sub.into(), token: self.next_token, recs });
        self.next_token
    }

    /// Ends a hold (a CLOSE, a new REQ with the same id).
    pub fn release(&mut self, conn: ConnId, sub: &str) {
        if let Some(v) = self.by_conn.get_mut(&conn) {
            v.retain(|h| &*h.sub != sub);
            if v.is_empty() {
                self.by_conn.remove(&conn);
            }
        }
    }

    pub fn release_conn(&mut self, conn: ConnId) {
        self.by_conn.remove(&conn);
    }

    /// The hold `token` names, ended; `None` if it ended already.
    pub fn take(&mut self, conn: ConnId, sub: &str, token: u64) -> Option<HeldReq> {
        let v = self.by_conn.get_mut(&conn)?;
        let i = v.iter().position(|h| h.token == token && &*h.sub == sub)?;
        let h = v.swap_remove(i);
        if v.is_empty() {
            self.by_conn.remove(&conn);
        }
        Some(h)
    }

    /// Keeps a live event for a held subscription. `None` when it is not
    /// held; `Some(false)` when the hold is full.
    #[inline]
    pub fn keep(&mut self, conn: ConnId, sub: &str, rec: &Arc<[u8]>) -> Option<bool> {
        let h = self.by_conn.get_mut(&conn)?.iter_mut().find(|h| &*h.sub == sub)?;
        if h.recs.len() >= HELD_MAX {
            return Some(false);
        }
        h.recs.push(rec.clone());
        Some(true)
    }
}

/// NEG-OPENs a worker is answering, one table per reactor. The worker's
/// answer goes out from the reactor, and the set it built waits here until
/// the connection next speaks negentropy: sessions live on the connection's
/// own task, out of the reactor's reach.
#[derive(Default)]
pub struct HeldNegs {
    by_conn: crate::subs::FxMap<ConnId, Vec<HeldNeg>>,
    next_token: u64,
}

struct HeldNeg {
    sub: Box<str>,
    token: u64,
    /// The set, once its answer has gone out.
    ready: Option<NegSession>,
}

impl HeldNegs {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.by_conn.is_empty()
    }

    fn hold(&mut self, conn: ConnId, sub: &str) -> u64 {
        self.release(conn, sub);
        self.next_token += 1;
        self.by_conn.entry(conn).or_default().push(HeldNeg { sub: sub.into(), token: self.next_token, ready: None });
        self.next_token
    }

    /// Ends a hold (a NEG-CLOSE, a new NEG-OPEN with the same id), giving its
    /// set back if it was built. True when the worker had not answered yet.
    fn release(&mut self, conn: ConnId, sub: &str) -> bool {
        let Some(v) = self.by_conn.get_mut(&conn) else { return false };
        let mut waiting = false;
        v.retain(|h| {
            let ends = &*h.sub == sub;
            waiting |= ends && h.ready.is_none();
            !ends
        });
        if v.is_empty() {
            self.by_conn.remove(&conn);
        }
        waiting
    }

    pub fn release_conn(&mut self, conn: ConnId) {
        self.by_conn.remove(&conn);
    }

    /// Holds of this connection, answered or not.
    fn count(&self, conn: ConnId) -> usize {
        self.by_conn.get(&conn).map_or(0, Vec::len)
    }

    /// Moves the connection's sets whose answers have gone out into `into`.
    fn adopt(&mut self, conn: ConnId, into: &mut Vec<NegSession>) {
        let Some(v) = self.by_conn.get_mut(&conn) else { return };
        v.retain_mut(|h| match h.ready.take() {
            Some(s) => {
                into.push(s);
                false
            }
            None => true,
        });
        if v.is_empty() {
            self.by_conn.remove(&conn);
        }
    }

    /// A worker's answer for hold `token`: its set kept for the connection,
    /// or, refused (`None`), the hold ended. False when the hold ended
    /// meanwhile: the answer is dropped, and its set given back.
    pub fn settle(&mut self, conn: ConnId, sub: &str, token: u64, set: Option<NegSession>) -> bool {
        let Some(v) = self.by_conn.get_mut(&conn) else { return false };
        let Some(i) = v.iter().position(|h| h.token == token && &*h.sub == sub) else { return false };
        match set {
            Some(s) => v[i].ready = Some(s),
            None => {
                v.swap_remove(i);
                if v.is_empty() {
                    self.by_conn.remove(&conn);
                }
            }
        }
        true
    }
}

/// Messages collected instead of sent: what a worker builds for a reactor.
#[derive(Default)]
pub struct Collect {
    pub buf: Vec<u8>,
    pub ends: Vec<usize>,
}

impl Outbox for Collect {
    fn text(&mut self, f: &mut dyn FnMut(&mut Vec<u8>)) {
        f(&mut self.buf);
        self.ends.push(self.buf.len());
    }

    fn queued(&self) -> usize {
        self.buf.len()
    }
}

/// How writing a REQ's stored events went.
pub struct Answered {
    pub sent: u64,
    /// Stopped at the outbound limit.
    pub too_big: bool,
}

/// Writes the stored events answering `filters` (each at its limit) from
/// `snap`, newest first, each once; stops when `out` holds more than
/// `max_outbound` bytes. Not EOSE. The same on a reactor and on a worker.
#[allow(clippy::too_many_arguments)]
pub fn answer(snap: &Version, filters: &[Filter], limits: &[usize], sub_id: &str, peer: bool, now: u64, max_outbound: usize, out: &mut dyn Outbox) -> Answered {
    let mut hits = Vec::new();
    for (f, &limit) in filters.iter().zip(limits) {
        hits.extend(snap.query(f, limit, now));
    }
    // One filter's results are distinct and in order already. An event two
    // filters match is two equal hits, side by side once sorted.
    if filters.len() > 1 {
        hits.sort_unstable_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.id.cmp(&b.id)));
        hits.dedup_by_key(|h| h.seq);
    }
    // A gift wrap only broad filters matched is left out; with no broad
    // filter (Vector's are never broad) every hit came from one that is not.
    let any_broad = !peer && filters.iter().any(broad);
    let mut sent = 0;
    for (i, h) in hits.iter().enumerate() {
        // An answer bigger than the connection may have waiting is all built
        // in memory before a byte of it goes out (50 filters of 5000 events
        // each can be hundreds of megabytes, held as long as the client does
        // not read). Stop there and say so, rather than truncate silently.
        if out.queued() > max_outbound {
            return Answered { sent, too_big: true };
        }
        // A later event's bytes load while this one is written out.
        if let Some(next) = hits.get(i + 3) {
            snap.prefetch_record(next.seq);
        }
        if let Some(rec) = snap.record(h.seq) {
            if any_broad && hides_wrap(filters, rec) {
                continue;
            }
            event_msg(out, sub_id, rec, peer);
            sent += 1;
        }
    }
    Answered { sent, too_big: false }
}

/// `["CLOSED", sub, ...]` for an answer that outgrew the outbound limit.
pub fn closed_too_big(out: &mut dyn Outbox, sub_id: &str, max_outbound: usize) {
    closed(out, sub_id, &format!("error: the answer is larger than {} MB; ask for fewer events at a time", max_outbound >> 20));
}

/// Items held by every open negentropy session, relay-wide (each ~90 bytes).
pub static NEG_ITEMS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// What open sessions may hold together, about 1 GB: one session may hold
/// `MAX_NEG_ITEMS`, and sixteen connections of eight whole-store sessions
/// each took a 50k-event relay from 470 MB to 1 GB. Vector's syncs hold a
/// mailbox each, thousands of items.
const NEG_ITEMS_BUDGET: u64 = 12_000_000;

/// An open negentropy session; dropped, it gives its items back to the budget.
pub struct NegSession {
    sub: Box<str>,
    storage: VecStorage,
    items: u64,
}

impl Drop for NegSession {
    fn drop(&mut self) {
        NEG_ITEMS.fetch_sub(self.items, std::sync::atomic::Ordering::Relaxed);
    }
}

/// How a NEG-OPEN went (see [`neg_open`]).
pub struct NegOpened {
    /// The open session, or why the NEG-OPEN was refused (its answer is a NEG-ERR).
    pub session: Result<NegSession, ReqRefused>,
    /// Records in the set, as far as it was built.
    pub items: u64,
}

/// Builds the set `f` matches in `snap` (`limit` does not apply) and answers
/// the client's first message, `msg`: a NEG-MSG, or a NEG-ERR when the set
/// is too large, the budget is spent or the message is bad. Events expiring
/// before `horizon` are left out, and so are gift wraps only a broad filter
/// matches, unless the set is for a trusted peer. The same on a reactor and
/// on a worker.
pub fn neg_open(snap: &Version, f: &Filter, horizon: u64, peer: bool, sub_id: &str, msg: &[u8], out: &mut dyn Outbox) -> NegOpened {
    // Vector's DM shape is answered from covering index keys alone.
    let items = match snap.neg_items(f, horizon) {
        Some(items) => items,
        None => {
            let hits = snap.query(f, MAX_NEG_ITEMS + 1, horizon);
            hits.iter().filter(|h| peer || !broad_wrap(f, snap, h.seq)).map(|h| (h.created_at, h.id)).collect()
        }
    };
    let n = items.len() as u64;
    if items.len() > MAX_NEG_ITEMS {
        neg_err(out, sub_id, "blocked: too many records to reconcile, narrow the filter");
        return NegOpened { session: Err(ReqRefused::Limits), items: n };
    }
    // Reserved before the set is built; given back if it is refused.
    if NEG_ITEMS.fetch_add(n, std::sync::atomic::Ordering::Relaxed) + n > NEG_ITEMS_BUDGET {
        NEG_ITEMS.fetch_sub(n, std::sync::atomic::Ordering::Relaxed);
        neg_err(out, sub_id, "rate-limited: too many records held by open sync sessions, try again shortly");
        return NegOpened { session: Err(ReqRefused::Busy), items: n };
    }
    let session = NegSession { sub: sub_id.into(), storage: VecStorage::new(items), items: n };
    match negentropy::reconcile(&session.storage, msg, NEG_FRAME_LIMIT) {
        Ok(resp) => {
            neg_msg(out, sub_id, &resp);
            NegOpened { session: Ok(session), items: n }
        }
        Err(e) => {
            neg_err(out, sub_id, &format!("error: {e}"));
            NegOpened { session: Err(ReqRefused::Invalid), items: n }
        }
    }
}

/// Open negentropy sessions per connection (Vector runs one per relay at a time).
const MAX_NEG_SESSIONS: usize = 8;
/// Largest set a NEG-OPEN may reconcile, as strfry's `maxSyncEvents`.
const MAX_NEG_ITEMS: usize = 2_000_000;
/// Response cap in bytes before hex: ~100 KB on the wire, inside the 128 KB
/// frame Vector's negentropy client assumes.
const NEG_FRAME_LIMIT: usize = 50_000;

/// Most EVENTs a read queues before their signatures are checked: plenty
/// for a batch, since the verifier threads combine reads (`crate::verify`).
const MAX_QUEUED: usize = 64;
/// The same for a connection whose signatures are checked one at a time on
/// its reactor: about 0.6 ms of verification, so a burst still yields to the
/// reactor's other connections.
const MAX_QUEUED_ALONE: usize = 16;

/// EVENTs that passed every check but the signature, held until the frames of
/// the current read are all parsed: then the reactor checks them on the spot,
/// or hands the job to the verifier threads. One per reactor.
#[derive(Default)]
pub struct SigQueue {
    pub checker: Checker,
    pub job: Job,
}

impl SigQueue {
    pub fn len(&self) -> usize {
        self.job.len()
    }

    pub fn is_empty(&self) -> bool {
        self.job.is_empty()
    }
}

pub struct Session {
    pub conn: ConnId,
    /// Events queued to the writer and not yet answered.
    pub pending: usize,
    neg: Vec<NegSession>,
    /// One of our own relays (a `[[peer]]`): gift wraps are listed to it like
    /// any other event, and events this relay took from clients are marked so.
    trusted: bool,
    /// That peer's passes against this relay, for the dashboard.
    link: Option<Arc<PeerLink>>,
    /// This is the connection a peer runs its passes on (it opened a
    /// negentropy session): what it sends or asks for by id is bulk.
    bulk: bool,
    /// A batch of this connection's signatures failed once: check the rest
    /// one at a time (a client mixing bad signatures into bursts would
    /// otherwise make every batch pay twice).
    no_batch: bool,
}

impl Session {
    /// `link` is set for a trusted peer's connection.
    pub fn new(conn: ConnId, link: Option<Arc<PeerLink>>) -> Session {
        Session { conn, pending: 0, neg: Vec::new(), trusted: link.is_some(), link, bulk: false, no_batch: false }
    }

    /// Counts `n` events of a pass that moved over this connection.
    fn moved(&self, n: u64) {
        if let (true, Some(l), 1..) = (self.bulk, &self.link, n) {
            l.moved(crate::ingest::now(), n);
        }
    }

    pub fn on_text(&mut self, text: &str, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        let msg = ClientMsg::parse(text, cx.parser, cx.rec);
        if !matches!(msg, Ok(ClientMsg::Event { .. })) {
            // Replies keep the order the messages came in.
            self.flush_events(cx, out);
        }
        match msg {
            Ok(ClientMsg::Event { info, at }) => self.on_event(text, info, at, cx, out),
            Ok(ClientMsg::Req { sub_id, filters }) => self.on_req(sub_id, filters, cx, out),
            Ok(ClientMsg::Count { sub_id, filters }) => self.on_count(sub_id, filters, cx, out),
            Ok(ClientMsg::Close { sub_id }) => {
                cx.subs.remove(self.conn, sub_id);
                cx.held.release(self.conn, sub_id);
            }
            Ok(ClientMsg::Auth { .. }) => {
                metrics::inc(&cx.m.auth_refused);
                let id = *Record(cx.rec).id();
                ok(out, &id, false, "restricted: this relay does not use AUTH");
            }
            Ok(ClientMsg::NegOpen { sub_id, filter, msg }) => self.on_neg_open(sub_id, filter, &msg, cx, out),
            Ok(ClientMsg::NegMsg { sub_id, msg }) => self.on_neg_msg(sub_id, &msg, cx, out),
            Ok(ClientMsg::NegClose { sub_id }) => self.close_neg(sub_id, cx),
            Err(MsgError::Filter { sub_id, err }) => {
                ReqRefused::Invalid.count(cx.m, Some(cx.talk));
                closed(out, &sub_id, &format!("error: {err}"))
            }
            Err(e) => notice(out, &e.to_string()),
        }
    }

    fn on_event(&mut self, text: &str, info: EventInfo, at: usize, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        metrics::inc(&cx.m.events_in);
        if self.trusted {
            metrics::inc(&cx.m.events_in_peer);
            self.moved(1);
        }
        bump(&cx.talk.events);
        let id = *Record(cx.rec).id();
        // Cheap checks first: nothing below costs a hash until these pass.
        if let Some((why, msg)) = cx.cfg.refusal(&info, Record(cx.rec), cx.now) {
            why.count(cx.m, Some(cx.talk));
            return ok(out, &id, false, &msg);
        }
        if !(cx.allow_event)() {
            Refused::Rate.count(cx.m, Some(cx.talk));
            return ok(out, &id, false, "rate-limited: slow down, too many events from your address");
        }
        // A resend is answered from the index, before any hashing.
        cx.store.refresh(cx.snap);
        // A resend is answered from the index, unless the copy we hold is still
        // syncing: then the writer answers, after the sync, so an OK never
        // promises something a crash could take back.
        if cx.snap.lookup_id(&id).is_some_and(|seq| seq < cx.store.durable_seq()) {
            metrics::inc(&cx.m.events_duplicate);
            return ok(out, &id, true, "duplicate: already have this event");
        }
        // An id is hashed here only when the event had escapes: if their
        // canonical form does not match, the id is retried on the text as
        // received, which only this reactor still has. Every other id is
        // hashed with the signature check, eight at a time.
        if info.any_escaped && cx.parser.confirm_id(Scanner::new_at(text, at), cx.rec, info).is_err() {
            Refused::Invalid.count(cx.m, Some(cx.talk));
            return ok(out, &id, false, "invalid: bad event id");
        }
        // Taken from a client and checked here. What a peer sends was taken by
        // some other relay first, so it is not.
        if !self.trusted {
            relay_proto::record::mark_first_hand(cx.rec);
        }
        // The signature last, together with any other EVENTs from this read.
        cx.sigs.job.push(cx.rec, info.kind, !info.any_escaped);
    }

    /// Whether this connection's signatures may be checked in batches.
    pub fn batches(&self) -> bool {
        !self.no_batch
    }

    /// How many EVENTs a read may queue before they must be checked.
    pub fn queue_cap(&self) -> usize {
        if self.no_batch {
            MAX_QUEUED_ALONE
        } else {
            MAX_QUEUED
        }
    }

    /// Verifies the queued signatures here and finishes each event in arrival
    /// order: for a read whose EVENTs do not go to the verifier threads, and
    /// before anything in a read that is not an EVENT.
    pub fn flush_events(&mut self, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        if cx.sigs.is_empty() {
            return;
        }
        // The job comes out of the queue while its events finish (finishing
        // needs the whole context), and goes back empty for the next read.
        let mut job = std::mem::take(&mut cx.sigs.job);
        cx.sigs.checker.check(&mut [&mut job], !self.no_batch);
        self.finish_job(&job, cx, out);
        job.clear();
        cx.sigs.job = job;
    }

    /// Finishes a job's events in arrival order, with the verdicts it carries.
    pub fn finish_job(&mut self, job: &Job, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        match job.checked {
            Checked::OneByOne => {}
            Checked::Batch => {
                metrics::add(&cx.m.sigs_batched, job.len() as u64);
                if job.head {
                    metrics::inc(&cx.m.sig_batches);
                }
            }
            Checked::BatchFailed => {
                metrics::inc(&cx.m.sig_batches_failed);
                self.no_batch = true;
            }
        }
        for ((rec, &kind), &verdict) in job.records().zip(&job.kinds).zip(&job.verdicts) {
            self.finish_event(rec, kind, verdict, cx, out);
        }
    }

    fn finish_event(&mut self, rec: &[u8], kind: u64, verdict: Verdict, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        let id = *Record(rec).id();
        match verdict {
            Verdict::Valid => {}
            Verdict::BadId => {
                Refused::Invalid.count(cx.m, Some(cx.talk));
                return ok(out, &id, false, "invalid: bad event id");
            }
            Verdict::BadSig => {
                Refused::Invalid.count(cx.m, Some(cx.talk));
                return ok(out, &id, false, "invalid: bad signature");
            }
        }
        if cx.cfg.silences(Record(rec)) {
            bump(&cx.talk.silenced);
            return ok(out, &id, true, "");
        }
        if kind::is_ephemeral(kind) {
            metrics::inc(&cx.m.events_ephemeral);
            (cx.broadcast)(ReactorMsg::Ephemeral(Arc::from(rec)));
            // Even with nobody listening: Vector's relay check treats a refusal as fatal.
            return ok(out, &id, true, "");
        }
        match cx.writer.try_send(WriteReq { reactor: cx.reactor, conn: self.conn, rec: rec.to_vec(), at: std::time::Instant::now() }) {
            Ok(()) => self.pending += 1,
            Err(TrySendError::Full(_)) => {
                Refused::Rate.count(cx.m, Some(cx.talk));
                ok(out, &id, false, "rate-limited: the relay is busy, try again shortly")
            }
            Err(TrySendError::Disconnected(_)) => {
                Refused::Other.count(cx.m, Some(cx.talk));
                ok(out, &id, false, "error: the relay is shutting down")
            }
        }
    }

    /// Validates filters against the limits and the gift-wrap rule.
    fn check_filters(&self, filters: &mut [Filter], cx: &Ctx<'_>) -> Result<(), String> {
        if filters.len() > cx.cfg.max_filters {
            ReqRefused::Limits.count(cx.m, Some(cx.talk));
            return Err(format!("error: at most {} filters per request", cx.cfg.max_filters));
        }
        for f in filters.iter_mut() {
            let max = cx.cfg.max_filter_values;
            let too_many = f.ids.as_ref().is_some_and(|v| v.len() > max)
                || f.authors.as_ref().is_some_and(|v| v.len() > max)
                || f.kinds.as_ref().is_some_and(|v| v.len() > max)
                || f.tags.iter().any(|t| t.values.len() > max);
            if too_many {
                ReqRefused::Limits.count(cx.m, Some(cx.talk));
                return Err(format!("error: at most {max} values per filter list"));
            }
            // No bulk scraping of gift wraps: they are found by author (Concord),
            // recipient (#p) or id, never listed wholesale.
            let addressed = f.ids.is_some() || f.authors.is_some() || f.tags.iter().any(|t| t.name == b'p');
            let wants_wraps = f.kinds.as_ref().is_some_and(|k| k.contains(&kind::GIFT_WRAP));
            if wants_wraps && !addressed && !self.trusted {
                ReqRefused::Wraps.count(cx.m, Some(cx.talk));
                return Err(String::from("restricted: gift wraps are requested by author, recipient or id"));
            }
        }
        if let Some(bans) = &cx.cfg.bans {
            bans.with(|s| s.strip(filters));
        }
        Ok(())
    }

    fn on_req(&mut self, sub_id: &str, mut filters: Vec<Filter>, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        metrics::inc(&cx.m.reqs);
        bump(&cx.talk.reqs);
        cx.talk.shape.set(Shape::of(&filters));
        let started = std::time::Instant::now();
        if let Err(msg) = self.check_filters(&mut filters, cx) {
            return closed(out, sub_id, &msg);
        }
        self.moved(filters.iter().map(|f| f.ids.as_ref().map_or(0, |ids| ids.len() as u64)).sum());
        let replacing = cx.subs.count(self.conn) > 0 && cx.subs.remove(self.conn, sub_id);
        if !replacing && cx.subs.count(self.conn) >= cx.cfg.max_subscriptions {
            ReqRefused::Limits.count(cx.m, Some(cx.talk));
            return closed(out, sub_id, &format!("error: at most {} open subscriptions", cx.cfg.max_subscriptions));
        }
        cx.held.release(self.conn, sub_id);
        cx.store.refresh(cx.snap);
        let snap = cx.snap.clone();
        let limits: Vec<usize> = filters.iter().map(|f| f.limit.map_or(cx.cfg.default_limit, |l| (l as usize).min(cx.cfg.max_limit))).collect();
        // Live from the snapshot the stored results come from: nothing is missed
        // and nothing is sent twice.
        cx.subs.add_with(self.conn, sub_id, filters.clone(), snap.gen, self.trusted);
        // Batches relayed live before this subscription existed but published
        // after the snapshot: in neither the results nor the live stream so
        // far, so they go out after EOSE (exactly once).
        let any_broad = !self.trusted && filters.iter().any(broad);
        let mut early: Vec<Arc<[u8]>> = Vec::new();
        for batch in cx.pending.iter().filter(|b| b.gen > snap.gen) {
            for rec in &batch.events {
                let r = Record(rec);
                if filters.iter().any(|f| f.matches(r)) && !(any_broad && hides_wrap(&filters, r)) {
                    early.push(rec.clone());
                }
            }
        }

        let mut path = Path::Reactor;
        if snap.req_cost(&filters, &limits, INLINE_REQ_RANGES) > INLINE_REQ_COST {
            // A worker finds and encodes the stored events; live ones wait in
            // the hold until they have gone out.
            let token = cx.held.hold(self.conn, sub_id, early.clone());
            let (queued, took) = cx.took(&filters);
            let job = crate::ingest::ReqJob {
                snap: snap.clone(),
                filters: filters.clone(),
                limits: limits.clone(),
                now: cx.now,
                reactor: cx.reactor,
                conn: self.conn,
                sub: sub_id.to_string(),
                token,
                peer: self.trusted,
                max_outbound: cx.cfg.max_outbound,
                queued,
                took,
            };
            if (cx.offload)(crate::ingest::Job::Req(job)) {
                metrics::inc(&cx.m.reqs_offloaded);
                return;
            }
            cx.held.release(self.conn, sub_id);
            if snap.req_cost(&filters, &limits, FALLBACK_REQ_RANGES) > FALLBACK_REQ_COST {
                cx.subs.remove(self.conn, sub_id);
                ReqRefused::Busy.count(cx.m, Some(cx.talk));
                return closed(out, sub_id, "rate-limited: too many large requests in progress, try again shortly");
            }
            metrics::inc(&cx.m.reqs_inline_fallback);
            path = Path::Fallback;
        }

        let before = out.queued();
        let a = answer(&snap, &filters, &limits, sub_id, self.trusted, cx.now, cx.cfg.max_outbound, out);
        metrics::add(&cx.m.events_out, a.sent);
        if a.too_big {
            cx.note(What::Req, path, &filters, started.elapsed().as_micros() as u64, a.sent, out.queued().saturating_sub(before) as u64);
            ReqRefused::Limits.count(cx.m, Some(cx.talk));
            cx.subs.remove(self.conn, sub_id);
            return closed_too_big(out, sub_id, cx.cfg.max_outbound);
        }
        eose(out, sub_id);
        for rec in &early {
            event_msg(out, sub_id, Record(rec), self.trusted);
            metrics::inc(&cx.m.events_live);
        }
        let us = started.elapsed().as_micros() as u64;
        metrics::add(&cx.m.req_micros, us);
        cx.note(What::Req, path, &filters, us, a.sent + early.len() as u64, out.queued().saturating_sub(before) as u64);
    }

    /// Ends negentropy session `sub_id`, open or still with a worker.
    fn close_neg(&mut self, sub_id: &str, cx: &mut Ctx<'_>) {
        self.neg.retain(|n| &*n.sub != sub_id);
        if !cx.negs.is_empty() {
            cx.negs.release(self.conn, sub_id);
        }
    }

    /// Takes the sets workers built for this connection, whose answers have gone out.
    #[inline]
    fn adopt(&mut self, cx: &mut Ctx<'_>) {
        if !cx.negs.is_empty() {
            cx.negs.adopt(self.conn, &mut self.neg);
        }
    }

    fn on_neg_open(&mut self, sub_id: &str, filter: Filter, msg: &[u8], cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        metrics::inc(&cx.m.neg_opens);
        bump(&cx.talk.negs);
        let started = std::time::Instant::now();
        self.close_neg(sub_id, cx);
        let mut fs = [filter];
        if let Err(m) = self.check_filters(&mut fs, cx) {
            return neg_err(out, sub_id, &m);
        }
        let [filter] = fs;
        if let Some(l) = &self.link {
            self.bulk = true;
            l.touch(cx.now);
        }
        // Sets a worker is still building count as open.
        self.adopt(cx);
        if self.neg.len() + cx.negs.count(self.conn) >= MAX_NEG_SESSIONS {
            ReqRefused::Limits.count(cx.m, Some(cx.talk));
            return neg_err(out, sub_id, "blocked: too many open negentropy sessions");
        }
        cx.store.refresh(cx.snap);
        // `limit` does not apply to a set reconciliation: the whole matching set is the set.
        let mut f = filter;
        f.limit = None;
        // A peer's pass is bulk: what expires soon is left to the live link
        // (crate::sync::SHORT_LIVED), on its side and on ours.
        let horizon = if self.trusted { cx.now.saturating_add(crate::sync::SHORT_LIVED) } else { cx.now };

        let mut path = Path::Reactor;
        let fs = std::slice::from_ref(&f);
        let cost = cx.snap.count_cost(fs);
        if cost > INLINE_NEG_ITEMS {
            // A worker builds the set and answers; the set comes back to this
            // connection through the hold.
            let token = cx.negs.hold(self.conn, sub_id);
            let (queued, took) = cx.took(fs);
            let job = crate::ingest::NegJob {
                snap: cx.snap.clone(),
                filter: f.clone(),
                horizon,
                msg: msg.to_vec(),
                reactor: cx.reactor,
                conn: self.conn,
                sub: sub_id.to_string(),
                token,
                peer: self.trusted,
                queued,
                took,
            };
            if (cx.offload)(crate::ingest::Job::Neg(job)) {
                metrics::inc(&cx.m.negs_offloaded);
                return;
            }
            cx.negs.release(self.conn, sub_id);
            if cost > FALLBACK_NEG_ITEMS {
                ReqRefused::Busy.count(cx.m, Some(cx.talk));
                return neg_err(out, sub_id, NEG_BUSY);
            }
            metrics::inc(&cx.m.reqs_inline_fallback);
            path = Path::Fallback;
        }

        let before = out.queued();
        let opened = neg_open(cx.snap, &f, horizon, self.trusted, sub_id, msg, out);
        match opened.session {
            Ok(s) => self.neg.push(s),
            Err(why) => why.count(cx.m, Some(cx.talk)),
        }
        // Records in the set are not events sent: only its time and bytes make it heavy.
        let (us, bytes) = (started.elapsed().as_micros() as u64, out.queued().saturating_sub(before) as u64);
        if heavy::is_heavy(us, 0, bytes) {
            cx.note(What::Neg, path, fs, us, opened.items, bytes);
        }
    }

    fn on_neg_msg(&mut self, sub_id: &str, msg: &[u8], cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        if let Some(l) = &self.link {
            l.touch(crate::ingest::now());
        }
        self.adopt(cx);
        let Some(storage) = self.neg.iter().find(|n| &*n.sub == sub_id).map(|n| &n.storage) else {
            // A client that did not wait for the answer to its NEG-OPEN: that session ends here.
            let why = if cx.negs.release(self.conn, sub_id) { "closed: NEG-MSG before the answer to its NEG-OPEN" } else { "closed: no open negentropy session with this id" };
            return neg_err(out, sub_id, why);
        };
        match negentropy::reconcile(storage, msg, NEG_FRAME_LIMIT) {
            Ok(resp) => neg_msg(out, sub_id, &resp),
            Err(e) => {
                neg_err(out, sub_id, &format!("error: {e}"));
                self.neg.retain(|n| &*n.sub != sub_id);
            }
        }
    }

    fn on_count(&mut self, sub_id: &str, mut filters: Vec<Filter>, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        metrics::inc(&cx.m.counts);
        bump(&cx.talk.counts);
        if let Err(msg) = self.check_filters(&mut filters, cx) {
            return closed(out, sub_id, &msg);
        }
        cx.store.refresh(cx.snap);
        let started = std::time::Instant::now();
        let mut path = Path::Reactor;
        // Exact, always: Vector sizes its syncs with it.
        if cx.snap.count_cost(&filters) > INLINE_COUNT_KEYS {
            let (queued, took) = cx.took(&filters);
            let job = crate::ingest::CountJob { snap: cx.snap.clone(), filters: filters.clone(), now: cx.now, reactor: cx.reactor, conn: cx.conn, sub: sub_id.to_string(), queued, took };
            if (cx.offload)(crate::ingest::Job::Count(job)) {
                metrics::inc(&cx.m.counts_offloaded);
                return;
            }
            // The workers are busy: one Vector sizes a sync with is counted
            // here (slower for this reactor), a hostile one is refused.
            if cx.snap.count_cost(&filters) > FALLBACK_COUNT_KEYS {
                ReqRefused::Busy.count(cx.m, Some(cx.talk));
                return closed(out, sub_id, "rate-limited: too many large counts in progress, try again shortly");
            }
            metrics::inc(&cx.m.reqs_inline_fallback);
            path = Path::Fallback;
        }
        count_msg(out, sub_id, cx.snap.count_all(&filters, cx.now));
        cx.note(What::Count, path, &filters, started.elapsed().as_micros() as u64, 0, 0);
    }
}

/// `["COUNT", sub, {"count": n}]`.
pub fn count_msg(out: &mut dyn Outbox, sub_id: &str, n: u64) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"COUNT\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",{\"count\":");
        relay_proto::record::push_u64(b, n);
        b.extend_from_slice(b"}]");
    });
}

/// A filter that names no kinds, authors, recipients or ids is a broad scan.
/// Gift wraps are left out of broad scans (stored and live) rather than
/// refusing the whole request: they are found by author, recipient or id only.
#[inline]
pub fn broad(f: &Filter) -> bool {
    f.kinds.is_none() && f.ids.is_none() && f.authors.is_none() && !f.tags.iter().any(|t| t.name == b'p')
}

/// True when `rec` is a gift wrap that only broad filters matched.
pub fn hides_wrap(filters: &[Filter], rec: Record<'_>) -> bool {
    rec.kind() == kind::GIFT_WRAP && !filters.iter().any(|f| !broad(f) && f.matches(rec))
}

/// `["EVENT","sub",{...}]`. To a trusted peer, an event this relay took from
/// a client itself ends `,"first-hand"]`: the peer need not check its signature.
pub fn event_msg(out: &mut dyn Outbox, sub_id: &str, rec: Record<'_>, to_peer: bool) {
    let mark = to_peer && rec.is_first_hand();
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"EVENT\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",");
        rec.write_json(b);
        end_event(b, mark);
    });
}

/// [`event_msg`] with the event's JSON already encoded, for fan-out where it is
/// built once and shared by every subscriber.
pub fn event_msg_json(out: &mut dyn Outbox, sub_id: &str, json: &[u8], first_hand: bool) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"EVENT\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",");
        b.extend_from_slice(json);
        end_event(b, first_hand);
    });
}

#[inline]
fn end_event(b: &mut Vec<u8>, first_hand: bool) {
    if first_hand {
        b.extend_from_slice(b",\"");
        b.extend_from_slice(relay_proto::message::FIRST_HAND);
        b.push(b'"');
    }
    b.push(b']');
}

pub fn eose(out: &mut dyn Outbox, sub_id: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"EOSE\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\"]");
    });
}

pub fn ok(out: &mut dyn Outbox, id: &[u8; 32], accepted: bool, msg: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"OK\",\"");
        hex::encode_into(id, b);
        b.extend_from_slice(if accepted { b"\",true,\"" } else { b"\",false,\"" });
        escape_str(msg, b);
        b.extend_from_slice(b"\"]");
    });
}

/// The OK for an event the writer has finished with.
pub fn ok_reply(out: &mut dyn Outbox, r: &Reply) {
    let (accepted, msg) = match r.outcome {
        Some(Outcome::Stored(_)) => (true, ""),
        Some(Outcome::Duplicate) => (true, "duplicate: already have this event"),
        Some(Outcome::Superseded) => (false, "duplicate: a newer version of this event is already stored"),
        Some(Outcome::Deleted | Outcome::Vanished) => (false, "blocked: this event was deleted"),
        Some(Outcome::Rejected(m)) => (false, m),
        None => (false, "error: could not store the event, try again"),
    };
    ok(out, &r.id, accepted, msg);
}

pub fn closed(out: &mut dyn Outbox, sub_id: &str, msg: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"CLOSED\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",\"");
        escape_str(msg, b);
        b.extend_from_slice(b"\"]");
    });
}

pub fn notice(out: &mut dyn Outbox, msg: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"NOTICE\",\"");
        escape_str(msg, b);
        b.extend_from_slice(b"\"]");
    });
}

pub fn neg_msg(out: &mut dyn Outbox, sub_id: &str, msg: &[u8]) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"NEG-MSG\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",\"");
        hex::encode_into(msg, b);
        b.extend_from_slice(b"\"]");
    });
}

/// A gift wrap that a broad filter would match: left out of reconciliation too.
fn broad_wrap(f: &Filter, snap: &Version, seq: u64) -> bool {
    broad(f) && snap.record(seq).is_some_and(|r| r.kind() == kind::GIFT_WRAP)
}

pub fn neg_err(out: &mut dyn Outbox, sub_id: &str, msg: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"NEG-ERR\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",\"");
        escape_str(msg, b);
        b.extend_from_slice(b"\"]");
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{Job, LiveBatch};
    use relay_proto::negentropy::Initiator;
    use serde_json::{json, Value};
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::Ordering::Relaxed;

    /// `NEG_ITEMS` is the whole relay's: the tests that count it run one at a time.
    static NEG_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    const T0: u64 = 1_700_000_000;

    fn held() -> u64 {
        NEG_ITEMS.load(Relaxed)
    }

    /// A store of `n` kind-14 events, one a second from `T0`.
    fn store(tag: &str, n: u64) -> (Store, relay_store::Writer, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("relay-session-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (store, mut w) = Store::open(&dir, relay_store::Options::default()).unwrap();
        let mut parser = EventParser::new();
        let recs: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let json = format!(
                    r#"{{"id":"{:064x}","pubkey":"{:064x}","created_at":{},"kind":14,"tags":[],"content":"x","sig":"{}"}}"#,
                    i + 1,
                    1,
                    T0 + i,
                    "00".repeat(64)
                );
                let mut rec = Vec::new();
                relay_proto::event::parse_event_json(&json, &mut parser, &mut rec, false).unwrap();
                rec
            })
            .collect();
        for chunk in recs.chunks(4096) {
            let refs: Vec<&[u8]> = chunk.iter().map(Vec::as_slice).collect();
            w.write(&refs).unwrap();
        }
        (store, w, dir)
    }

    /// One reactor's context for its sessions. What it hands the workers is
    /// kept, for the test to run as a worker would.
    struct Rig {
        cfg: SessionCfg,
        store: Store,
        snap: Arc<Version>,
        subs: SubIndex,
        writer: SyncSender<WriteReq>,
        _writes: std::sync::mpsc::Receiver<WriteReq>,
        parser: EventParser,
        rec: Vec<u8>,
        sigs: SigQueue,
        m: Block,
        pending: std::collections::VecDeque<Arc<LiveBatch>>,
        jobs: RefCell<Vec<Job>>,
        /// The workers' queue is full.
        full: Cell<bool>,
        held: HeldReqs,
        negs: HeldNegs,
        talk: Talk,
        heavy: HeavyLog,
    }

    impl Rig {
        fn new(store: Store) -> Rig {
            let cfg = SessionCfg {
                max_subscriptions: 10,
                max_filters: 10,
                max_filter_values: 10,
                default_limit: 10,
                max_limit: 10,
                max_event_bytes: 65_536,
                max_future_seconds: 900,
                max_tags: 100,
                max_outbound: 1 << 20,
                kind_allowed: Box::new(|_| true),
                kind_denied: Box::new(|_| false),
                bans: None,
                allowed: None,
            };
            let (writer, _writes) = std::sync::mpsc::sync_channel(1);
            Rig {
                cfg,
                snap: store.snapshot(),
                store,
                subs: SubIndex::default(),
                writer,
                _writes,
                parser: EventParser::new(),
                rec: Vec::new(),
                sigs: SigQueue::default(),
                m: Block::default(),
                pending: Default::default(),
                jobs: RefCell::new(Vec::new()),
                full: Cell::new(false),
                held: HeldReqs::default(),
                negs: HeldNegs::default(),
                talk: Talk::default(),
                heavy: HeavyLog::default(),
            }
        }

        /// What `s` answers to `text` at once.
        fn text(&mut self, s: &mut Session, text: &str) -> Vec<Value> {
            let mut out = Collect::default();
            let offload = |job: Job| {
                let take = !self.full.get();
                if take {
                    self.jobs.borrow_mut().push(job);
                }
                take
            };
            let mut cx = Ctx {
                cfg: &self.cfg,
                store: &self.store,
                snap: &mut self.snap,
                subs: &mut self.subs,
                writer: &self.writer,
                reactor: 0,
                broadcast: &|_| {},
                allow_event: &|| true,
                parser: &mut self.parser,
                rec: &mut self.rec,
                sigs: &mut self.sigs,
                now: T0 + 1_000_000,
                m: &self.m,
                pending: &self.pending,
                offload: &offload,
                held: &mut self.held,
                negs: &mut self.negs,
                conn: s.conn,
                talk: &self.talk,
                ip: std::net::Ipv4Addr::LOCALHOST.into(),
                ua: "",
                heavy: &mut self.heavy,
            };
            s.on_text(text, &mut cx, &mut out);
            messages(out)
        }

        /// Runs the oldest job as a worker does, and settles its answer as the
        /// reactor does: what reaches the connection.
        fn work(&mut self) -> Vec<Value> {
            let Job::Neg(job) = self.jobs.borrow_mut().remove(0) else { panic!("not a NEG-OPEN") };
            let mut c = Collect::default();
            let opened = neg_open(&job.snap, &job.filter, job.horizon, job.peer, &job.sub, &job.msg, &mut c);
            if self.negs.settle(job.conn, &job.sub, job.token, opened.session.ok()) {
                messages(c)
            } else {
                Vec::new()
            }
        }
    }

    fn messages(c: Collect) -> Vec<Value> {
        let mut start = 0;
        c.ends
            .iter()
            .map(|&end| {
                let v = serde_json::from_slice(&c.buf[start..end]).unwrap();
                start = end;
                v
            })
            .collect()
    }

    fn open(sub: &str, f: Value, msg: &[u8]) -> String {
        json!(["NEG-OPEN", sub, f, hex::encode_string(msg)]).to_string()
    }

    fn reply(m: &Value, sub: &str) -> Vec<u8> {
        assert_eq!((m[0].as_str(), m[1].as_str()), (Some("NEG-MSG"), Some(sub)), "{m}");
        hex::decode_any_case(m[2].as_str().unwrap().as_bytes()).unwrap()
    }

    #[test]
    fn a_big_set_is_built_by_a_worker_and_comes_back_to_its_session() {
        let _one = NEG_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        const N: u64 = 30_000;
        let (store, _w, dir) = store("worker", N);
        let mut r = Rig::new(store);
        let mut s = Session::new(1, None);
        let base = held();
        let client = Initiator::new(VecStorage::new(Vec::new()), NEG_FRAME_LIMIT).unwrap();
        let first = client.initiate();
        let (big, small) = (json!({"kinds": [14]}), json!({"kinds": [14], "until": T0 + 99}));

        // Small: answered on the spot.
        let m = r.text(&mut s, &open("small", small.clone(), &first));
        reply(&m[0], "small");
        assert!(r.jobs.borrow().is_empty());
        assert_eq!(held(), base + 100);
        // Big: nothing yet, and nothing held until a worker has built it.
        assert!(r.text(&mut s, &open("big", big.clone(), &first)).is_empty());
        assert_eq!(r.m.negs_offloaded.load(Relaxed), 1);
        assert_eq!(held(), base + 100);
        let m = r.work();
        assert_eq!(m.len(), 1);
        assert_eq!(held(), base + 100 + N);
        // The rest of the reconciliation runs on the set the worker built.
        let (mut have, mut need) = (Vec::new(), Vec::new());
        let mut msg = reply(&m[0], "big");
        let mut rounds = 1;
        while let Some(next) = client.reconcile(&msg, &mut have, &mut need).unwrap() {
            let m = r.text(&mut s, &json!(["NEG-MSG", "big", hex::encode_string(&next)]).to_string());
            msg = reply(&m[0], "big");
            rounds += 1;
        }
        assert!(rounds > 1, "one frame cannot hold {N} ids");
        assert_eq!((have.len(), need.len()), (0, N as usize));
        r.text(&mut s, r#"["NEG-CLOSE","big"]"#);
        assert_eq!(held(), base + 100);

        // Closed while a worker builds it: the answer is dropped, the set given back.
        assert!(r.text(&mut s, &open("gone", big.clone(), &first)).is_empty());
        r.text(&mut s, r#"["NEG-CLOSE","gone"]"#);
        assert!(r.work().is_empty());
        assert_eq!(held(), base + 100);
        // Opened again with the same id: one answer, the second's.
        assert!(r.text(&mut s, &open("again", big.clone(), &first)).is_empty());
        reply(&r.text(&mut s, &open("again", small.clone(), &first))[0], "again");
        assert!(r.work().is_empty());
        assert_eq!(held(), base + 200);
        // A NEG-MSG before the answer ends it.
        assert!(r.text(&mut s, &open("early", big.clone(), &first)).is_empty());
        let m = r.text(&mut s, &json!(["NEG-MSG", "early", hex::encode_string(&first)]).to_string());
        assert_eq!(m, [json!(["NEG-ERR", "early", "closed: NEG-MSG before the answer to its NEG-OPEN"])]);
        assert!(r.work().is_empty());
        assert_eq!(held(), base + 200);

        // Sets still with a worker count against the connection's sessions.
        let mut t = Session::new(2, None);
        for i in 0..MAX_NEG_SESSIONS {
            assert!(r.text(&mut t, &open(&format!("n{i}"), big.clone(), &first)).is_empty());
        }
        let m = r.text(&mut t, &open("one-more", small.clone(), &first));
        assert_eq!(m, [json!(["NEG-ERR", "one-more", "blocked: too many open negentropy sessions"])]);
        // Half answered (built, not yet taken by the session), then the connection goes.
        for _ in 0..MAX_NEG_SESSIONS / 2 {
            assert_eq!(r.work().len(), 1);
        }
        assert_eq!(held(), base + 200 + N * MAX_NEG_SESSIONS as u64 / 2);
        r.negs.release_conn(2);
        drop(t);
        for _ in 0..MAX_NEG_SESSIONS / 2 {
            assert!(r.work().is_empty());
        }
        assert!(r.negs.is_empty());
        assert_eq!(held(), base + 200);

        // The workers' queue full: built on the spot instead.
        r.full.set(true);
        reply(&r.text(&mut s, &open("busy", big.clone(), &first))[0], "busy");
        assert_eq!(r.m.reqs_inline_fallback.load(Relaxed), 1);
        assert_eq!(held(), base + 200 + N);
        r.full.set(false);
        // The budget spent: the worker's refusal reaches the client, nothing is held.
        NEG_ITEMS.fetch_add(NEG_ITEMS_BUDGET, Relaxed);
        assert!(r.text(&mut s, &open("over", big, &first)).is_empty());
        let m = r.work();
        NEG_ITEMS.fetch_sub(NEG_ITEMS_BUDGET, Relaxed);
        assert_eq!(m, [json!(["NEG-ERR", "over", "rate-limited: too many records held by open sync sessions, try again shortly"])]);
        assert!(r.negs.is_empty());
        drop(s);
        assert_eq!(held(), base);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bad_first_message_gives_the_set_back() {
        let _one = NEG_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (store, _w, dir) = store("bad", 50);
        let snap = store.snapshot();
        let base = held();
        let mut c = Collect::default();
        let f = Filter { kinds: Some(vec![14]), ..Filter::default() };
        let opened = neg_open(&snap, &f, T0 + 1_000_000, false, "x", b"\x00", &mut c);
        assert!(matches!(opened.session, Err(ReqRefused::Invalid)));
        assert_eq!(opened.items, 50);
        assert_eq!(messages(c)[0][0], "NEG-ERR");
        assert_eq!(held(), base);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A peer splits a window only when told it is too large; being busy is
    /// not that, or a loaded relay would get four times the requests.
    #[test]
    fn only_a_set_too_large_tells_a_peer_to_split_its_window() {
        use crate::sync::remote::too_big;
        assert!(too_big("blocked: too many records to reconcile, narrow the filter"));
        assert!(!too_big(NEG_BUSY));
        assert!(!too_big("rate-limited: too many records held by open sync sessions, try again shortly"));
        assert!(!too_big("blocked: too many open negentropy sessions"));
    }
}

//! Heavy requests, for the operator only: what strained the relay lately, and
//! who asked. Read through the admin socket (`heavy`), never served over HTTP.
//!
//! A REQ, COUNT or NEG-OPEN is kept when it took long (on a reactor, or
//! waiting for a worker and running there) or sent a lot. A connection is
//! kept for each run of seconds in which it took a lot of bytes out: a burst
//! of small requests, which none of them shows alone.
//!
//! Cheap by construction, like `talk`: a request is held up against numbers
//! already at hand (its time, events and bytes); each reactor keeps its own
//! ring, which only it touches; and bursts are found by a look once a second
//! at the byte counts `top` keeps anyway. The worst also go to the log, at
//! most one line per reactor every ten seconds, and without the address: the
//! relay keeps no record of who connected.

use crate::talk::Shape;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// A request is heavy from this long, waiting for a worker and running.
pub const SLOW_US: u64 = 25_000;
/// ...or from this many events sent, or bytes.
pub const BIG_EVENTS: u64 = 2_000;
pub const BIG_BYTES: u64 = 2_000_000;
/// A connection is bursting while it takes this many bytes out a second.
pub const BURST_BYTES: u64 = 2_000_000;
/// How often each reactor looks for bursts.
pub const LOOK_US: u64 = 1_000_000;
/// Logged as well, from these (a burst: from its bytes).
const LOUD_US: u64 = 250_000;
const LOUD_EVENTS: u64 = 20_000;
const LOUD_BYTES: u64 = 20_000_000;
/// At most one line per reactor this often; the rest are counted into the next.
const LOUD_EVERY_MS: u64 = 10_000;
/// Kept per reactor, the oldest dropped first.
const RING: usize = 512;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

#[inline]
pub fn is_heavy(us: u64, events: u64, bytes: u64) -> bool {
    us >= SLOW_US || events >= BIG_EVENTS || bytes >= BIG_BYTES
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum What {
    Req,
    Count,
    Neg,
    Burst,
}

impl What {
    fn name(self) -> &'static str {
        match self {
            What::Req => "REQ",
            What::Count => "COUNT",
            What::Neg => "NEG-OPEN",
            What::Burst => "burst",
        }
    }
}

/// Where a request was answered: on its connection's reactor, by a worker,
/// or on the reactor because the workers' queue was full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    Reactor,
    Worker,
    Fallback,
}

impl Path {
    fn name(self) -> &'static str {
        match self {
            Path::Reactor => "reactor",
            Path::Worker => "worker",
            Path::Fallback => "fallback",
        }
    }
}

/// What a worker's request cost, sent back with its answer.
#[derive(Clone, Copy, Debug)]
pub struct Took {
    pub ip: IpAddr,
    pub shape: Shape,
    pub wait_us: u64,
    pub run_us: u64,
}

/// One heavy request, or one burst.
#[derive(Clone, Debug)]
pub struct Heavy {
    /// Unix ms: when it was answered (a burst: when it began).
    pub at: u64,
    pub ip: IpAddr,
    pub ua: Box<str>,
    pub what: What,
    pub path: Path,
    /// Waiting for a worker, then running (a burst: how long it has lasted).
    pub wait_us: u64,
    pub run_us: u64,
    /// Events sent; for a NEG-OPEN, records in its set; for a burst, REQs asked meanwhile.
    pub events: u64,
    /// Answered on a reactor: as framed (and compressed, if the client asked);
    /// by a worker: its JSON before that; a burst: as written to the socket.
    pub bytes: u64,
    /// The request's shape (a burst: the connection's last REQ).
    pub shape: Shape,
    /// A burst still going when the operator asked.
    pub ongoing: bool,
}

impl Heavy {
    fn loud(&self) -> bool {
        match self.what {
            What::Burst => self.bytes >= LOUD_BYTES,
            _ => self.wait_us + self.run_us >= LOUD_US || self.events >= LOUD_EVENTS || self.bytes >= LOUD_BYTES,
        }
    }

    /// For the log: everything but the address.
    fn line(&self) -> String {
        let ua = if self.ua.is_empty() { "-" } else { &self.ua };
        let mb = self.bytes as f64 / 1e6;
        if self.what == What::Burst {
            let s = self.run_us as f64 / 1e6;
            return format!("heavy burst: {mb:.1} MB in {s:.1} s, {} REQs, app {ua}, last request {}", self.events, self.shape);
        }
        let mut l = format!("heavy {} on a {}: {:.1} ms", self.what.name(), self.path.name(), (self.wait_us + self.run_us) as f64 / 1e3);
        if self.wait_us > 0 {
            let _ = write!(l, " ({:.1} ms waiting)", self.wait_us as f64 / 1e3);
        }
        let unit = if self.what == What::Neg { "records" } else { "events" };
        let _ = write!(l, ", {} {unit}, {mb:.1} MB, app {ua}, request {}", self.events, self.shape);
        l
    }
}

/// A reactor's heavy requests and bursts, newest last.
#[derive(Default)]
pub struct HeavyLog {
    ring: VecDeque<Heavy>,
    /// When this reactor last logged a line (Unix ms), and the loud ones left out since.
    logged: u64,
    unlogged: u64,
}

impl HeavyLog {
    pub fn push(&mut self, h: Heavy) {
        if h.loud() {
            let now = now_ms();
            if now >= self.logged + LOUD_EVERY_MS {
                let more = if self.unlogged > 0 { format!(" ({} more since the last line)", self.unlogged) } else { String::new() };
                eprintln!("{}{more}", h.line());
                (self.logged, self.unlogged) = (now, 0);
            } else {
                self.unlogged += 1;
            }
        }
        if self.ring.len() == RING {
            self.ring.pop_front();
        }
        self.ring.push_back(h);
    }

    /// Those answered (or bursts begun) from `from` (Unix ms) on.
    pub fn since(&self, from: u64, into: &mut Vec<Heavy>) {
        into.extend(self.ring.iter().filter(|h| h.at >= from).cloned());
    }
}

/// One connection's bytes and REQs at its reactor's last look, and the burst
/// under way: since when (Unix ms), how long, and its bytes and REQs.
#[derive(Clone, Copy, Debug, Default)]
pub struct Burst {
    bytes: u64,
    reqs: u32,
    on: Option<(u64, u64, u64, u64)>,
}

impl Burst {
    /// The reactor's look, `us` after its last: the connection's totals now.
    /// A burst that ends here (or, with `last`, on close) is returned.
    pub fn look(&mut self, now: u64, us: u64, bytes: u64, reqs: u32, last: bool) -> Option<(u64, u64, u64, u64)> {
        let (db, dr) = (bytes.saturating_sub(self.bytes), u64::from(reqs.saturating_sub(self.reqs)));
        (self.bytes, self.reqs) = (bytes, reqs);
        // Per second, without dividing: db / us >= BURST_BYTES / 1e6.
        if us > 0 && u128::from(db) * 1_000_000 >= u128::from(BURST_BYTES) * u128::from(us) {
            let on = self.on.get_or_insert((now.saturating_sub(us / 1000), 0, 0, 0));
            on.1 += us;
            on.2 += db;
            on.3 += dr;
            if !last {
                return None;
            }
        }
        self.on.take()
    }

    pub fn ongoing(&self) -> Option<(u64, u64, u64, u64)> {
        self.on
    }
}

/// A burst as a row: `on` from `Burst`.
pub fn burst(on: (u64, u64, u64, u64), ip: IpAddr, ua: &str, shape: Shape, ongoing: bool) -> Heavy {
    let (at, us, bytes, reqs) = on;
    Heavy { at, ip, ua: ua.into(), what: What::Burst, path: Path::Reactor, wait_us: 0, run_us: us, events: reqs, bytes, shape, ongoing }
}

/// What `heavy` sorts by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum By {
    Time,
    Ms,
    Events,
    Bytes,
}

impl By {
    pub const NAMES: [(By, &'static str); 4] = [(By::Time, "time"), (By::Ms, "ms"), (By::Events, "events"), (By::Bytes, "bytes")];

    pub fn parse(s: &str) -> Option<By> {
        By::NAMES.iter().find(|(_, n)| *n == s).map(|(b, _)| *b)
    }

    fn name(self) -> &'static str {
        By::NAMES.iter().find(|(b, _)| *b == self).map(|(_, n)| *n).expect("every order is named")
    }

    fn key(self, h: &Heavy) -> u64 {
        match self {
            By::Time => h.at,
            By::Ms => h.wait_us + h.run_us,
            By::Events => h.events,
            By::Bytes => h.bytes,
        }
    }
}

/// The table `heavy` prints: a summary line, a header, then the rows.
pub fn render(mut rows: Vec<Heavy>, minutes: u64, by: By, limit: usize) -> Vec<String> {
    let n = |w: What| rows.iter().filter(|h| h.what == w).count();
    let ongoing = rows.iter().filter(|h| h.ongoing).count();
    let mut addresses: Vec<IpAddr> = rows.iter().map(|h| h.ip).collect();
    addresses.sort_unstable();
    addresses.dedup();
    let mut out = vec![
        format!(
            "last {minutes} min: {} REQ, {} COUNT, {} NEG-OPEN heavy (from {} ms, {BIG_EVENTS} events or {:.0} MB), {} bursts (from {:.0} MB/s, {ongoing} going on), from {} addresses; by {}",
            n(What::Req),
            n(What::Count),
            n(What::Neg),
            SLOW_US / 1000,
            BIG_BYTES as f64 / 1e6,
            n(What::Burst),
            BURST_BYTES as f64 / 1e6,
            addresses.len(),
            by.name()
        ),
        format!("{:<8}  {:<40} {:<8} {:<8} {:>8} {:>9} {:>11} {:>8}  {:<28} request", "when UTC", "address", "what", "where", "wait ms", "ms", "sent", "MB", "app"),
    ];
    rows.sort_by(|a, b| by.key(b).cmp(&by.key(a)).then(b.at.cmp(&a.at)));
    for h in rows.into_iter().take(limit) {
        let s = h.at / 1000;
        let when = format!("{:02}:{:02}:{:02}", s / 3600 % 24, s / 60 % 60, s % 60);
        let ua: String = if h.ua.is_empty() { "-".into() } else { h.ua.chars().take(28).collect() };
        // Only a worker's requests wait in a queue.
        let wait = if h.what != What::Burst && h.path == Path::Worker { format!("{:.1}", h.wait_us as f64 / 1e3) } else { "-".to_string() };
        let (path, sent) = match h.what {
            What::Burst => (if h.ongoing { "ongoing" } else { "-" }, format!("{} REQ", h.events)),
            What::Count => (h.path.name(), "-".to_string()),
            What::Neg => (h.path.name(), format!("{} rec", h.events)),
            What::Req => (h.path.name(), format!("{} ev", h.events)),
        };
        out.push(format!(
            "{when:<8}  {:<40} {:<8} {path:<8} {wait:>8} {:>9.1} {sent:>11} {:>8.1}  {ua:<28} {}",
            h.ip.to_string(),
            h.what.name(),
            (h.wait_us + h.run_us) as f64 / 1e3,
            h.bytes as f64 / 1e6,
            h.shape
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(at: u64, us: u64, events: u64, bytes: u64) -> Heavy {
        Heavy {
            at,
            ip: "203.0.113.9".parse().unwrap(),
            ua: "app/1".into(),
            what: What::Req,
            path: Path::Worker,
            wait_us: 0,
            run_us: us,
            events,
            bytes,
            shape: Shape::default(),
            ongoing: false,
        }
    }

    #[test]
    fn a_request_is_heavy_by_time_events_or_bytes() {
        assert!(!is_heavy(SLOW_US - 1, BIG_EVENTS - 1, BIG_BYTES - 1));
        assert!(is_heavy(SLOW_US, 0, 0));
        assert!(is_heavy(0, BIG_EVENTS, 0));
        assert!(is_heavy(0, 0, BIG_BYTES));
    }

    #[test]
    fn the_ring_keeps_the_newest() {
        let mut log = HeavyLog::default();
        for i in 0..RING as u64 + 10 {
            log.push(req(i, SLOW_US, 0, 0));
        }
        let mut v = Vec::new();
        log.since(0, &mut v);
        assert_eq!(v.len(), RING);
        assert_eq!(v[0].at, 10);
        let mut v = Vec::new();
        log.since(RING as u64, &mut v);
        assert_eq!(v.len(), 10);
    }

    #[test]
    fn a_burst_runs_while_the_bytes_keep_coming() {
        let mut b = Burst::default();
        let mb = 1_000_000;
        // Quiet, then two seconds over the line, then quiet: one burst.
        assert_eq!(b.look(1_000, LOOK_US, mb, 1, false), None);
        assert_eq!(b.look(2_000, LOOK_US, 4 * mb, 3, false), None);
        assert!(b.ongoing().is_some());
        assert_eq!(b.look(3_000, LOOK_US, 7 * mb, 9, false), None);
        assert_eq!(b.look(4_000, LOOK_US, 7 * mb + 10, 9, false), Some((1_000, 2 * LOOK_US, 6 * mb, 8)));
        assert!(b.ongoing().is_none());
        // A short look still counts per second: 1.5 MB in half a second.
        assert_eq!(b.look(4_500, LOOK_US / 2, 8_500_000 + 10, 9, false), None);
        // Closing ends it, with what came since the last look.
        assert_eq!(b.look(4_700, LOOK_US / 5, 9_000_000 + 10, 10, true), Some((4_000, LOOK_US / 2 + LOOK_US / 5, 2 * mb, 1)));
        // Closing quietly ends nothing.
        assert_eq!(b.look(5_000, LOOK_US, 9_000_000 + 10, 10, true), None);
    }

    #[test]
    fn a_row_says_what_where_and_how_long() {
        let mut slow = req(45_296_000, 30_000, 120, 50_000);
        slow.wait_us = 2_000;
        let ip: IpAddr = "2001:db8::2".parse().unwrap();
        let big = burst((45_300_000, 7_000_000, 52_300_000, 112), ip, "nostr-sdk/0.45.1", Shape::default(), true);
        let lines = render(vec![slow, big], 60, By::Bytes, 10);
        assert!(lines[0].starts_with("last 60 min: 1 REQ, 0 COUNT, 0 NEG-OPEN heavy"), "{}", lines[0]);
        assert!(lines[0].contains("1 bursts (from 2 MB/s, 1 going on), from 2 addresses; by bytes"), "{}", lines[0]);
        assert!(lines[2].starts_with("12:35:00  2001:db8::2") && lines[2].contains("burst    ongoing") && lines[2].contains("112 REQ"), "{lines:?}");
        assert!(lines[2].contains(" 7000.0 ") && lines[2].contains("52.3"), "{lines:?}");
        assert!(lines[3].starts_with("12:34:56  203.0.113.9") && lines[3].contains("REQ      worker        2.0      32.0      120 ev"), "{lines:?}");
    }

    #[test]
    fn the_log_line_leaves_the_address_out() {
        let mut h = req(0, 300_000, 25_000, 30_000_000);
        h.wait_us = 4_000;
        assert!(h.loud());
        let l = h.line();
        assert_eq!(l, "heavy REQ on a worker: 304.0 ms (4.0 ms waiting), 25000 events, 30.0 MB, app app/1, request -");
        assert!(!l.contains("203.0.113.9"));
        assert!(!req(0, SLOW_US, 0, 0).loud());
    }
}

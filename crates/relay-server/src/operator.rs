//! `query`, `count` and `delete`: the operator's view of the stored events.
//!
//! With the relay stopped the commands open the data directory themselves, as
//! `export` does. With it running that directory is locked, so they ask the
//! relay over its admin socket instead (see `admin.rs`). Both ways run the
//! functions below on a snapshot, so the answers agree.

use crate::admin::{self, Client, Op, Request};
use crate::config::{store_options, Config};
use crate::ingest;
use relay_proto::filter::FilterError;
use relay_proto::json::Scanner;
use relay_proto::{hex, Filter, Record};
use relay_store::{Store, Version, Writer};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Events a dry run shows.
const SAMPLES: usize = 10;

/// One event a dry run shows.
pub struct Sample {
    pub id: [u8; 32],
    pub kind: u64,
    pub created_at: u64,
    pub pubkey: [u8; 32],
}

impl Sample {
    fn of(rec: Record<'_>) -> Sample {
        Sample { id: *rec.id(), kind: rec.kind(), created_at: rec.created_at(), pubkey: *rec.pubkey() }
    }

    fn line(&self) -> String {
        format!("{} kind {} created_at {} pubkey {}", hex::encode_string(&self.id), self.kind, self.created_at, &hex::encode_string(&self.pubkey)[..8])
    }
}

/// What a delete found, and how many of those it removed.
#[derive(Default)]
pub struct Deleted {
    pub matched: u64,
    pub deleted: u64,
    pub sample: Vec<Sample>,
}

/// `--filter`: one NIP-01 filter object, or an array of them (their union).
pub fn parse_filters(text: &str) -> Result<Vec<Filter>, String> {
    let mut s = Scanner::new(text);
    let mut filters = Vec::new();
    if s.peek() == Some(b'[') {
        s.array(|s| -> Result<(), FilterError> {
            filters.push(Filter::parse(s)?);
            Ok(())
        })
        .map_err(|e| e.to_string())?;
    } else {
        filters.push(Filter::parse(&mut s).map_err(|e| e.to_string())?);
    }
    s.end().map_err(|e| e.to_string())?;
    check_filters(&filters)?;
    Ok(filters)
}

/// What every operator request must satisfy, whichever way it arrives.
pub fn check_filters(filters: &[Filter]) -> Result<(), String> {
    if filters.is_empty() {
        return Err("no filters: an empty list matches nothing".into());
    }
    // Whether it would mean "the newest N of each" or "N in all" is a guess an
    // operator should not have to make, least of all for a delete.
    if filters.iter().any(|f| f.limit.is_some()) {
        return Err("\"limit\" inside a filter is not supported: query takes --limit".into());
    }
    Ok(())
}

/// A typo must not wipe a relay: a filter that names no condition matches
/// every event, so it needs `--all`.
pub fn check_delete(filters: &[Filter], all: bool) -> Result<(), String> {
    check_filters(filters)?;
    let open = |f: &Filter| f.ids.is_none() && f.authors.is_none() && f.kinds.is_none() && f.tags.is_empty() && f.since.is_none() && f.until.is_none();
    if !all && filters.iter().any(open) {
        return Err("a filter with no conditions matches every event; add --all if you mean to delete everything".into());
    }
    Ok(())
}

/// The `created_at` before which `--age` seconds count as old.
pub fn older_than(age: Option<u64>, now: u64) -> Option<u64> {
    age.map(|a| now.saturating_sub(a))
}

/// Hands each of up to `limit` matching events to `emit`, newest first.
/// Returns how many. Memory use does not grow with the number of matches.
pub fn stream(v: &Version, filters: &[Filter], limit: Option<u64>, now: u64, emit: &mut dyn FnMut(Record<'_>) -> io::Result<()>) -> io::Result<u64> {
    let mut n = 0;
    for hit in v.matching_seqs(filters, None, now) {
        if limit.is_some_and(|l| n >= l) {
            break;
        }
        // Deleted since the walk found it: gone.
        let Some(rec) = v.record(hit.seq) else { continue };
        emit(rec)?;
        n += 1;
    }
    Ok(n)
}

pub fn count_matching(v: &Version, filters: &[Filter], now: u64) -> u64 {
    v.matching_seqs(filters, None, now).count() as u64
}

/// What `delete` would remove: how many, and the newest few.
pub fn preview(v: &Version, filters: &[Filter], older_than: Option<u64>, now: u64) -> Deleted {
    let mut d = Deleted::default();
    for hit in v.matching_seqs(filters, older_than, now) {
        d.matched += 1;
        if d.sample.len() < SAMPLES {
            if let Some(rec) = v.record(hit.seq) {
                d.sample.push(Sample::of(rec));
            }
        }
    }
    d
}

/// Where the commands do their work.
enum Backend {
    /// The relay is not running: the store is ours.
    Local(Store, Box<Writer>),
    /// The relay holds the directory; its admin socket is the way in.
    Remote(Remote),
}

struct Remote {
    sock: PathBuf,
    /// The store's own account of who holds the directory.
    held: String,
}

impl Backend {
    fn open(cfg: &Config) -> Result<Backend, String> {
        match Store::open(&cfg.store.data, store_options(cfg)) {
            Ok((store, w)) => Ok(Backend::Local(store, Box::new(w))),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Backend::Remote(Remote { sock: admin::socket_path(&cfg.store.data), held: e.to_string() })),
            Err(e) => Err(e.to_string()),
        }
    }
}

impl Remote {
    fn connect(&self) -> Result<Client, String> {
        Client::connect(&self.sock).map_err(|e| format!("{}, and its admin socket {} did not answer: {e}", self.held, self.sock.display()))
    }
}

/// A reader that stopped listening (`| head`) is not a failure.
fn quiet_pipe(r: io::Result<()>) -> Result<(), String> {
    match r {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        r => r.map_err(|e| e.to_string()),
    }
}

/// `top`: who has been using the running relay (see `talk`).
pub fn run_top(cfg: &Config, minutes: Option<u64>, by: Option<String>, limit: Option<u64>) -> Result<(), String> {
    let Backend::Remote(r) = Backend::open(cfg)? else {
        return Err("top reports on a running relay's connections; this one is not running".into());
    };
    let req = Request { minutes, by, limit, ..Request::new(Op::Top, Vec::new()) };
    for line in r.connect()?.text(&req).map_err(|e| e.to_string())? {
        println!("{line}");
    }
    Ok(())
}

pub fn run_heavy(cfg: &Config, minutes: Option<u64>, by: Option<String>, limit: Option<u64>) -> Result<(), String> {
    let Backend::Remote(r) = Backend::open(cfg)? else {
        return Err("heavy reports on a running relay's requests; this one is not running".into());
    };
    let req = Request { minutes, by, limit, ..Request::new(Op::Heavy, Vec::new()) };
    for line in r.connect()?.text(&req).map_err(|e| e.to_string())? {
        println!("{line}");
    }
    Ok(())
}

pub fn run_query(cfg: &Config, filters: Vec<Filter>, limit: Option<u64>) -> Result<(), String> {
    check_filters(&filters)?;
    let backend = Backend::open(cfg)?;
    let stdout = io::stdout();
    let mut out = io::BufWriter::with_capacity(1 << 20, stdout.lock());
    let done = match backend {
        Backend::Local(store, _w) => {
            let v = store.snapshot();
            let mut buf = Vec::new();
            stream(&v, &filters, limit, ingest::now(), &mut |rec| {
                buf.clear();
                rec.write_json(&mut buf);
                buf.push(b'\n');
                out.write_all(&buf)
            })
            .map(|_| ())
        }
        Backend::Remote(r) => {
            let req = Request { limit, ..Request::new(Op::Query, filters) };
            r.connect()?
                .query(&req, &mut |line| {
                    out.write_all(line.as_bytes())?;
                    out.write_all(b"\n")
                })
                .map(|_| ())
        }
    };
    quiet_pipe(done.and_then(|()| out.flush()))
}

pub fn run_count(cfg: &Config, filters: Vec<Filter>) -> Result<(), String> {
    check_filters(&filters)?;
    let n = match Backend::open(cfg)? {
        Backend::Local(store, _w) => count_matching(&store.snapshot(), &filters, ingest::now()),
        Backend::Remote(r) => r.connect()?.count(&Request::new(Op::Count, filters)).map_err(|e| e.to_string())?,
    };
    println!("{n}");
    Ok(())
}

pub fn run_delete(cfg: &Config, filters: Vec<Filter>, age: Option<u64>, all: bool, dry_run: bool, yes: bool) -> Result<(), String> {
    match (dry_run, yes) {
        (false, false) => return Err("delete needs --dry-run (count what would go) or --yes (delete it); nothing was changed".into()),
        (true, true) => return Err("choose one of --dry-run and --yes, not both".into()),
        _ => {}
    }
    check_delete(&filters, all)?;
    let d = match Backend::open(cfg)? {
        Backend::Local(store, mut w) => {
            let now = ingest::now();
            let older = older_than(age, now);
            if dry_run {
                preview(&store.snapshot(), &filters, older, now)
            } else {
                let n = w.delete_matching(&filters, older, now).map_err(|e| e.to_string())? as u64;
                Deleted { matched: n, deleted: n, sample: Vec::new() }
            }
        }
        Backend::Remote(r) => {
            let req = Request { age, all, dry_run, ..Request::new(Op::Delete, filters) };
            r.connect()?.delete(&req).map_err(|e| e.to_string())?
        }
    };
    if dry_run {
        println!("would delete {} (dry run: nothing was changed)", events(d.matched));
        for s in &d.sample {
            println!("  {}", s.line());
        }
        let more = d.matched.saturating_sub(d.sample.len() as u64);
        if more > 0 {
            println!("  ... and {more} more");
        }
    } else if d.deleted == d.matched {
        println!("deleted {}", events(d.deleted));
    } else {
        println!("deleted {} ({} matched; the rest changed while the delete ran)", events(d.deleted), d.matched);
    }
    Ok(())
}

/// `backup`: a copy of the store at this moment, taken while the relay serves
/// if it is running. With `verify`, the copy is then opened as a store and a
/// spread of its events read back.
pub fn run_backup(cfg: &Config, dest: &Path, verify: bool) -> Result<(), String> {
    // The relay runs elsewhere (another directory, another user's view of
    // relative paths): it gets the path whole.
    let dest = std::path::absolute(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    let t = Instant::now();
    let mut meter = Meter::new();
    let (n, c) = match Backend::open(cfg)? {
        Backend::Local(_store, mut w) => {
            let plan = w.begin_backup().map_err(|e| e.to_string())?;
            let n = plan.events();
            let copied = relay_store::backup::copy(&plan, &dest, &mut |done, total| {
                meter.show(done, total);
                true
            });
            drop(plan);
            let ended = w.end_backup();
            let c = copied.map_err(|e| e.to_string())?;
            ended.map_err(|e| e.to_string())?;
            (n, c)
        }
        Backend::Remote(r) => {
            let path = dest.to_str().ok_or("the destination's path is not UTF-8, which the admin socket cannot carry")?;
            let req = Request { dest: Some(path.to_string()), ..Request::new(Op::Backup, Vec::new()) };
            r.connect()?.backup(&req, &mut |done, total| meter.show(done, total)).map_err(|e| e.to_string())?
        }
    };
    meter.finish();
    println!(
        "backed up {} to {} in {:.1}s ({:.2} GB read, {:.2} GB written)",
        events(n),
        dest.display(),
        t.elapsed().as_secs_f64(),
        c.bytes as f64 / 1e9,
        c.written as f64 / 1e9
    );
    if verify {
        let v = relay_store::backup::verify(&dest, store_options(cfg), n).map_err(|e| format!("the backup in {} did not verify: {e}", dest.display()))?;
        println!("verified: it opens as a store of {}; {} read back and matched their checksums", events(v.events), v.checked);
    }
    Ok(())
}

/// A long copy's progress on stderr: one updating line on a terminal, a line
/// per tenth otherwise.
struct Meter {
    tty: bool,
    shown: Option<u64>,
}

impl Meter {
    fn new() -> Meter {
        use std::io::IsTerminal;
        Meter { tty: io::stderr().is_terminal(), shown: None }
    }

    fn show(&mut self, done: u64, total: u64) {
        let pct = (done * 100).checked_div(total).unwrap_or(100).min(100);
        let step = if self.tty { pct } else { pct / 10 * 10 };
        if self.shown == Some(step) {
            return;
        }
        self.shown = Some(step);
        let line = format!("copying: {step}% ({:.2} of {:.2} GB)", done as f64 / 1e9, total as f64 / 1e9);
        if self.tty {
            eprint!("\r{line}");
        } else {
            eprintln!("{line}");
        }
    }

    fn finish(&self) {
        if self.tty && self.shown.is_some() {
            eprintln!();
        }
    }
}

fn events(n: u64) -> String {
    if n == 1 {
        "1 event".into()
    } else {
        format!("{n} events")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_are_one_object_or_a_list() {
        assert_eq!(parse_filters(r#"{"kinds":[1]}"#).unwrap().len(), 1);
        assert_eq!(parse_filters(r#" [ {"kinds":[1]}, {"authors":[]} ] "#).unwrap().len(), 2);
        assert!(parse_filters(r#"{"kinds":[1]"#).is_err());
        assert!(parse_filters(r#"{"kinds":[1]} {}"#).is_err());
        assert!(parse_filters(r#"{"nope":1}"#).unwrap_err().contains("unknown key"));
        assert!(parse_filters("[]").is_err());
        assert!(parse_filters(r#"{"kinds":[1],"limit":5}"#).unwrap_err().contains("limit"));
        assert!(parse_filters("5").is_err());
    }

    #[test]
    fn an_empty_filter_needs_all() {
        let f = |s: &str| parse_filters(s).unwrap();
        assert!(check_delete(&f("{}"), false).is_err());
        assert!(check_delete(&f("{}"), true).is_ok());
        // Any one empty filter of a union matches everything.
        assert!(check_delete(&f(r#"[{"kinds":[1]},{}]"#), false).is_err());
        assert!(check_delete(&f(r#"{"kinds":[1]}"#), false).is_ok());
        assert!(check_delete(&f(r#"{"until":5}"#), false).is_ok());
        assert!(check_delete(&f(r##"{"#t":["a"]}"##), false).is_ok());
    }

    #[test]
    fn age_is_a_cutoff() {
        assert_eq!(older_than(None, 1000), None);
        assert_eq!(older_than(Some(100), 1000), Some(900));
        assert_eq!(older_than(Some(5000), 1000), Some(0));
    }
}

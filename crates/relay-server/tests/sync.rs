//! Sync end to end: two of our relays, the real binary, real sockets.
//!
//! The one-shot command in every direction, both with the destination
//! stopped (it opens the store) and running (it goes through the admin
//! socket), over more than 100 000 events; deletions and vanish requests on
//! one side holding against the other's copies; and continuous sync keeping
//! two running relays in step, catching up after one of them restarts.

use relay_net::conn::{client_connect, Message};
use relay_proto::hex;
use secp256k1::{schnorr, Keypair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Relay {
    child: Option<Child>,
    port: u16,
    dir: PathBuf,
}

impl Relay {
    /// Writes `dir/relay.toml`: every kind accepted (less what `policy` lines
    /// say), no rate limits, plus `extra` sections.
    fn configure(dir: &Path, port: u16, policy: &str, extra: &str) -> Relay {
        std::fs::create_dir_all(dir).unwrap();
        let cfg = format!(
            "[relay]\nbind = \"127.0.0.1:{port}\"\nthreads = 2\n[policy]\nkinds = \"all\"\n{policy}\n[limits]\nevents_per_minute_per_ip = 0\nmax_connections_per_ip = 0\n[store]\ndata = \"{}\"\n{extra}",
            dir.join("data").display()
        );
        std::fs::write(dir.join("relay.toml"), cfg).unwrap();
        Relay { child: None, port, dir: dir.to_path_buf() }
    }

    fn start(&mut self) {
        let child = Command::new(env!("CARGO_BIN_EXE_magnitude-relay"))
            .arg("--config")
            .arg(self.dir.join("relay.toml"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.child = Some(child);
        let t = Instant::now();
        while std::net::TcpStream::connect(self.addr()).is_err() {
            assert!(t.elapsed() < Duration::from_secs(20), "relay did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else { return };
        unsafe { libc_kill(child.id() as i32, 15) };
        let t = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(t.elapsed() < Duration::from_secs(20), "relay did not stop on SIGTERM");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.port).parse().unwrap()
    }

    fn url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.port)
    }

    /// One of the binary's commands with this relay's settings: (success, stdout, stderr).
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(self.dir.join("relay.toml")).args(args).output().unwrap();
        (out.status.success(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
    }

    fn run_ok(&self, args: &[&str]) -> String {
        let (ok, out, err) = self.run(args);
        assert!(ok, "{args:?} failed:\n{err}\n{out}");
        out
    }

    /// Loads events from JSONL, verifying each (the relay must be stopped).
    fn import(&self, events: &[Value]) {
        let path = self.dir.join("import.jsonl");
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        for e in events {
            writeln!(f, "{e}").unwrap();
        }
        f.flush().unwrap();
        drop(f);
        self.run_ok(&["import", path.to_str().unwrap()]);
    }

    fn count(&self, filter: &str) -> u64 {
        self.run_ok(&["count", "--filter", filter]).trim().parse().unwrap()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// A port nothing listens on, found by a socket that never listens (see
/// `free_port` in e2e.rs).
fn free_port() -> u16 {
    let s = tokio::net::TcpSocket::new_v4().unwrap();
    s.set_reuseaddr(true).unwrap();
    s.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    s.local_addr().unwrap().port()
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("relay-sync-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

struct Signer(Keypair);
impl Signer {
    fn new(seed: u32) -> Signer {
        let mut sk = [7u8; 32];
        sk[..4].copy_from_slice(&seed.to_be_bytes());
        Signer(Keypair::from_secret_bytes(sk).unwrap())
    }
    fn pk(&self) -> String {
        hex::encode_string(&self.0.x_only_public_key().0.to_byte_array())
    }
    fn event(&self, created_at: u64, kind: u64, tags: Value, content: &str) -> Value {
        let pk = self.pk();
        let pre = serde_json::to_string(&json!([0, pk, created_at, kind, tags, content])).unwrap();
        let id: [u8; 32] = Sha256::digest(pre.as_bytes()).into();
        let sig = schnorr::sign_no_aux_rand(&id, &self.0);
        json!({"id": hex::encode_string(&id), "pubkey": pk, "created_at": created_at, "kind": kind, "tags": tags, "content": content, "sig": hex::encode_string(&sig.to_byte_array())})
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// `(only theirs, only ours)` from each filter's "compared ..." line a sync printed.
fn differences(out: &str) -> Vec<(u64, u64)> {
    out.lines()
        .take_while(|l| !l.starts_with("all filters"))
        .filter(|l| l.trim_start().starts_with("compared"))
        .map(|l| {
            let n = |key: &str| l.split(key).nth(1).unwrap().split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap();
            (n("only theirs "), n("only ours "))
        })
        .collect()
}

async fn publish(relay: &Relay, events: &[Value]) {
    let mut c = client_connect(relay.addr(), &format!("127.0.0.1:{}", relay.port), "/").await.unwrap();
    for e in events {
        c.queue_text(&json!(["EVENT", e]).to_string());
    }
    c.flush().await.unwrap();
    let mut oks = 0;
    while oks < events.len() {
        if let Message::Text(t) = tokio::time::timeout(Duration::from_secs(20), c.recv()).await.expect("no OK in time").unwrap() {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v[0] == "OK" {
                assert_eq!(v[2], true, "{v}");
                oks += 1;
            }
        }
    }
}

async fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let t = Instant::now();
    while !ok() {
        assert!(t.elapsed() < Duration::from_secs(60), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

const RECIPIENTS: u32 = 5;
const AUTHORS: u32 = 20;

/// A relay's worth of events over two years, in Vector's shapes and others:
/// notes, gift wraps to five recipients (from throwaway keys), profiles that
/// replace each other and addressable app data.
fn dataset(n: usize) -> Vec<Value> {
    let authors: Vec<Signer> = (1..=AUTHORS).map(Signer::new).collect();
    let recipients: Vec<String> = (0..RECIPIENTS).map(|i| Signer::new(1000 + i).pk()).collect();
    let wrap_keys: Vec<Signer> = (0..50).map(|i| Signer::new(2000 + i)).collect();
    let base = now() - 2 * 365 * 86_400;
    let step = (2 * 365 * 86_400) / n as u64;
    (0..n)
        .map(|i| {
            let at = base + i as u64 * step;
            let a = &authors[i % authors.len()];
            match i % 10 {
                0..=5 => a.event(at, 1, json!([]), &format!("note {i}")),
                6 | 7 => wrap_keys[i % wrap_keys.len()].event(at, 1059, json!([["p", recipients[i / 10 % recipients.len()]]]), &format!("wrap {i}")),
                8 => a.event(at, 0, json!([]), &format!("profile {i}")),
                _ => a.event(at, 30078, json!([["d", format!("app/{}", i % 7)]]), &format!("data {i}")),
            }
        })
        .collect()
}

fn wraps_filter() -> String {
    let ps: Vec<String> = (0..RECIPIENTS).map(|i| Signer::new(1000 + i).pk()).collect();
    json!({"kinds": [1059], "#p": ps}).to_string()
}

#[tokio::test]
async fn one_shot_sync_every_way() {
    let (da, db) = (tmp("a"), tmp("b"));
    let mut a = Relay::configure(&da, free_port(), "", "");
    let mut b = Relay::configure(&db, free_port(), "", "");
    let t = Instant::now();
    let data = dataset(120_000);
    eprintln!("signed {} events in {:.1}s", data.len(), t.elapsed().as_secs_f64());
    a.import(&data);

    // B holds what A never heard of: author 3 deleting ten of their notes,
    // recipient 0 deleting five wraps sent to them (Concord's rule: a wrap
    // answers to its recipient), and author 4 asking every relay to forget them.
    let author3 = Signer::new(3);
    let notes3: Vec<&Value> = data.iter().filter(|e| e["pubkey"] == author3.pk() && e["kind"] == 1).take(10).collect();
    let r0 = Signer::new(1000);
    let wraps0: Vec<&Value> = data.iter().filter(|e| e["kind"] == 1059 && e["tags"][0][1] == r0.pk()).take(5).collect();
    let del3 = author3.event(now(), 5, Value::Array(notes3.iter().map(|e| json!(["e", e["id"]])).collect()), "");
    let del0 = r0.event(now(), 5, Value::Array(wraps0.iter().map(|e| json!(["e", e["id"]])).collect()), "");
    let author4 = Signer::new(4);
    let vanish4 = author4.event(now(), 62, json!([["relay", "ALL_RELAYS"]]), "");
    assert_eq!((notes3.len(), wraps0.len()), (10, 5));
    b.import(&[del3, del0, vanish4]);
    // Replaceable events A keeps only the newest of; what A holds is the set.
    a.start();
    let held = a.count("{}");
    let wraps = a.count(&wraps_filter());
    let held4 = a.count(&json!({"authors": [author4.pk()]}).to_string());
    assert!(held4 > 1000 && wraps > 20_000, "{held4} {wraps}");
    let filters = format!("[{{}},{}]", wraps_filter());

    // A dry run counts and changes nothing. A lists wraps only by recipient,
    // so {} leaves them out on both sides and the second filter carries them.
    let out = b.run_ok(&["sync", &a.url(), "--filter", &filters, "--dry-run"]);
    assert_eq!(differences(&out), [(held - wraps, 3), (wraps, 0)], "{out}");
    assert!(out.contains("dry run"), "{out}");

    // Down, with B stopped: B opens its store itself.
    let t = Instant::now();
    let out = b.run_ok(&["sync", &a.url(), "--filter", &filters]);
    eprintln!("down sync of {held} events took {:.1}s:\n{out}", t.elapsed().as_secs_f64());
    // Per filter: author 3's ten notes are deleted and author 4 vanished...
    let (first, second) = out.split_once("filter {\"kinds\"").unwrap_or_else(|| panic!("{out}"));
    assert!(first.contains(&format!("deleted (kind 5) 10, vanished (NIP-62) {held4}")), "{out}");
    // ...and the five wraps to recipient 0 are deleted.
    assert!(second.contains("deleted (kind 5) 5\n") || second.contains("deleted (kind 5) 5,"), "{out}");
    // Run again: only what B refuses is still missing, and B's own three are its own.
    let out = b.run_ok(&["sync", &a.url(), "--filter", &filters, "--dry-run"]);
    assert_eq!(differences(&out), [(10 + held4, 3), (5, 0)], "{out}");

    // Up, from B (stopped) to A (running): B's deletions and vanish request
    // reach A, which applies them, and the two now agree exactly.
    let out = b.run_ok(&["sync", &a.url(), "--filter", &filters, "--dir", "up"]);
    assert!(out.contains("there: stored 3"), "{out}");
    let out = b.run_ok(&["sync", &a.url(), "--filter", &filters, "--dry-run"]);
    assert_eq!(differences(&out), [(0, 0), (0, 0)], "{out}");
    assert_eq!(a.count("{}"), held - 10 - 5 - held4 + 3);

    // Both ways with B running: the command goes through B's admin socket.
    b.start();
    let (x, y) = (Signer::new(70), Signer::new(71));
    let to_a: Vec<Value> = (0..300).map(|i| x.event(now() - i, 1, json!([]), &format!("to a {i}"))).collect();
    let to_b: Vec<Value> = (0..200).map(|i| y.event(now() - i, 1, json!([]), &format!("to b {i}"))).collect();
    publish(&a, &to_a).await;
    publish(&b, &to_b).await;
    let out = b.run_ok(&["sync", &a.url(), "--dir", "both"]);
    assert_eq!(differences(&out), [(300, 200)], "{out}");
    assert!(out.contains("here: stored 300") && out.contains("there: stored 200"), "{out}");
    let out = b.run_ok(&["sync", &a.url(), "--filter", &filters, "--dry-run"]);
    assert_eq!(differences(&out), [(0, 0), (0, 0)], "{out}");

    // A narrower filter syncs only its own events.
    let z = Signer::new(72);
    publish(&a, &[z.event(now(), 0, json!([]), "profile"), z.event(now(), 1, json!([]), "note")]).await;
    let out = b.run_ok(&["sync", &a.url(), "--filter", r#"{"kinds":[0]}"#]);
    assert_eq!(differences(&out), [(1, 0)], "{out}");
    assert_eq!(b.count(&json!({"authors": [z.pk()]}).to_string()), 1);

    a.stop();
    b.stop();
    let _ = std::fs::remove_dir_all(&da);
    let _ = std::fs::remove_dir_all(&db);
}

/// /stats of a running relay.
async fn stats(relay: &Relay) -> Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(relay.addr()).await.unwrap();
    s.write_all(b"GET /stats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut body = Vec::new();
    s.read_to_end(&mut body).await.unwrap();
    let text = String::from_utf8(body).unwrap();
    serde_json::from_str(text.split("\r\n\r\n").nth(1).unwrap()).unwrap()
}

#[tokio::test]
async fn continuous_sync_keeps_two_relays_in_step() {
    let (da, db) = (tmp("ca"), tmp("cb"));
    let pa = free_port();
    let mut a = Relay::configure(&da, pa, "", "");
    // B refuses reactions, which A holds ten of.
    let mut b = Relay::configure(&db, free_port(), "deny_kinds = [7]", &format!("[[sync]]\nurl = \"ws://127.0.0.1:{pa}\"\ndirection = \"both\"\nreconcile_seconds = 3600\n"));
    let mut first = dataset(3000);
    let r = Signer::new(82);
    first.extend((0..10).map(|i| r.event(now() - 1000 - i, 7, json!([]), "+")));
    a.import(&first);
    a.start();
    let held = a.count("{}");
    b.start();

    // The first reconcile copies everything A has (wraps included only when a
    // filter names them; this one is {}, and A hides wraps from it), less the
    // reactions B refuses.
    let wraps = a.count(&wraps_filter());
    wait_for("the first reconcile", || b.count("{}") == held - wraps - 10).await;

    // Live, both ways.
    let (x, y) = (Signer::new(80), Signer::new(81));
    publish(&a, &[x.event(now(), 1, json!([]), "from a")]).await;
    wait_for("a live event down", || b.count(&json!({"authors": [x.pk()]}).to_string()) == 1).await;
    publish(&b, &[y.event(now(), 1, json!([]), "from b")]).await;
    wait_for("a live event up", || a.count(&json!({"authors": [y.pk()]}).to_string()) == 1).await;

    // A goes away. Meanwhile B takes 20 events, and A gets 30 that never pass
    // through B's live stream (imported while A is stopped).
    a.stop();
    let while_down: Vec<Value> = (0..20).map(|i| y.event(now() - i, 1, json!([]), &format!("while a was down {i}"))).collect();
    publish(&b, &while_down).await;
    let behind_its_back: Vec<Value> = (0..30).map(|i| x.event(now() - 100 - i, 1, json!([]), &format!("imported {i}"))).collect();
    a.import(&behind_its_back);
    a.start();
    // B reconnects with backoff, reconciles, and both sides catch up.
    wait_for("B to catch up", || b.count(&json!({"authors": [x.pk()]}).to_string()) == 31).await;
    wait_for("A to catch up", || a.count(&json!({"authors": [y.pk()]}).to_string()) == 21).await;

    let s = stats(&b).await;
    let e = &s["sync"][0];
    eprintln!("B's sync counters: {e}");
    assert_eq!(e["url"], format!("ws://127.0.0.1:{pa}"), "{s}");
    assert_eq!((e["direction"].as_str(), e["filter"].as_str()), (Some("both"), Some("{}")), "{s}");
    assert!(e["reconciles"].as_u64().unwrap() >= 2, "a reconcile at start and one after the restart: {s}");
    assert!(e["reconnects"].as_u64().unwrap() >= 1, "{s}");
    assert_eq!(e["connected"], 1, "{s}");
    assert!(e["events_in"].as_u64().unwrap() >= held - wraps - 10 + 31, "{s}");
    assert!(e["events_out"].as_u64().unwrap() >= 21, "{s}");
    // The reactions were fetched and refused once; later passes skip them.
    assert_eq!(e["events_in_refused"], 10, "{s}");
    // The pass at start covered everything; the one after A came back, only
    // recent events, which is all that went missing.
    assert_eq!(e["full_reconciles"], 1, "{s}");
    assert!(e["events_in_skipped"].as_u64().unwrap() >= 10, "{s}");

    a.stop();
    b.stop();
    let _ = std::fs::remove_dir_all(&da);
    let _ = std::fs::remove_dir_all(&db);
}

/// Every text message on `c` until EOSE for `sub`: the EVENTs, as sent.
async fn raw_events(c: &mut relay_net::conn::ClientConn, sub: &str) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), c.recv()).await.expect("no answer in time").unwrap() {
            Message::Text(t) if t.starts_with("[\"EOSE\"") => return out,
            Message::Text(t) if t.starts_with(&format!("[\"EVENT\",\"{sub}\"")) => out.push(t),
            Message::Close(why) => panic!("closed: {why:?}"),
            _ => {}
        }
    }
}

#[tokio::test]
async fn a_trusted_peer_gets_everything_and_vouches_for_first_hand_events() {
    let secret = "a".repeat(20) + &"7".repeat(20);
    let elsewhere = "b".repeat(40);
    let peers = format!("[[peer]]\nname = \"here\"\nsecret = \"{secret}\"\nips = [\"127.0.0.1\"]\n[[peer]]\nname = \"far\"\nsecret = \"{elsewhere}\"\nips = [\"10.1.2.3\"]\n");
    let (da, db, dc) = (tmp("peer-a"), tmp("peer-b"), tmp("peer-c"));
    let mut a = Relay::configure(&da, free_port(), "", &peers);
    let b = Relay::configure(&db, free_port(), "", "");
    let c = Relay::configure(&dc, free_port(), "", "");
    // Imported: not taken from an app by A. Published: taken, and checked, by A.
    let data = dataset(2_000);
    a.import(&data);
    a.start();
    let fresh: Vec<Value> = dataset(40).into_iter().map(|e| Signer::new(77).event(now(), e["kind"].as_u64().unwrap(), e["tags"].clone(), "fresh")).collect();
    publish(&a, &fresh).await;
    let (held, wraps) = (a.count("{}"), a.count(&json!({"kinds": [1059]}).to_string()));
    assert!(wraps > 0);

    // Over the peer path from a listed address: wraps listed like any event,
    // and only what A took from an app itself marked first-hand.
    let host = format!("127.0.0.1:{}", a.port);
    let mut p = client_connect(a.addr(), &host, &format!("/peer/{secret}")).await.unwrap();
    let ids = json!([data[6]["id"], fresh[6]["id"]]);
    p.send_text(&json!(["REQ", "x", {"ids": ids}]).to_string()).await.unwrap();
    let got = raw_events(&mut p, "x").await;
    assert_eq!(got.len(), 2, "{got:?}");
    let marked = |id: &Value| got.iter().find(|t| t.contains(id.as_str().unwrap())).unwrap().ends_with(",\"first-hand\"]");
    assert!(!marked(&data[6]["id"]), "imported: not first-hand");
    assert!(marked(&fresh[6]["id"]), "published by an app: first-hand");
    p.send_text(&json!(["REQ", "all", {"kinds": [1059]}]).to_string()).await.unwrap();
    assert_eq!(raw_events(&mut p, "all").await.len() as u64, wraps, "every wrap, to a peer");
    // An EVENT the peer itself sends is stored, but not as A's own.
    let relayed = Signer::new(78).event(now(), 1, json!([]), "via the peer");
    p.send_text(&json!(["EVENT", relayed]).to_string()).await.unwrap();
    loop {
        if let Message::Text(t) = tokio::time::timeout(Duration::from_secs(10), p.recv()).await.expect("no OK").unwrap() {
            if t.starts_with("[\"OK\"") {
                assert!(t.contains(",true,"), "{t}");
                break;
            }
        }
    }
    p.send_text(&json!(["REQ", "r", {"ids": [relayed["id"]]}]).to_string()).await.unwrap();
    let back = raw_events(&mut p, "r").await;
    assert!(back.len() == 1 && !back[0].ends_with(",\"first-hand\"]"), "{back:?}");
    drop(p);

    // The other peer's secret from an address not its own, or a wrong secret:
    // turned away.
    for path in [format!("/peer/{elsewhere}"), format!("/peer/{}", "c".repeat(40))] {
        let mut x = client_connect(a.addr(), &host, &path).await.unwrap();
        let m = tokio::time::timeout(Duration::from_secs(5), x.recv()).await.expect("no answer");
        assert!(matches!(m, Ok(Message::Close(Some((1008, _))))), "{path}: {m:?}");
    }

    // A trusted sync copies everything; an ordinary one, everything but wraps.
    b.run_ok(&["sync", &format!("ws://{host}/peer/{secret}"), "--trusted"]);
    assert_eq!(b.count("{}"), held + 1, "everything, and the event relayed through the peer");
    assert_eq!(b.count(&json!({"kinds": [1059]}).to_string()), wraps);
    c.run_ok(&["sync", &a.url()]);
    assert_eq!(c.count(&json!({"kinds": [1059]}).to_string()), 0);
    drop(a);
    for d in [da, db, dc] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A bulk pass leaves events expiring within ten minutes to the live link: a
/// peer leaves them out of its set (so they are never even found missing), a
/// relay that is not ours sends them and they are dropped, and one published
/// while the link is up still crosses live. Both relays name the link in /stats.
#[tokio::test]
async fn short_lived_events_cross_only_live() {
    let secret = "c".repeat(20) + &"9".repeat(20);
    let (da, db, dc) = (tmp("short-a"), tmp("short-b"), tmp("short-c"));
    let pa = free_port();
    let mut a = Relay::configure(&da, pa, "", &format!("[[peer]]\nname = \"B relay\"\nsecret = \"{secret}\"\nips = [\"127.0.0.1\"]\n"));
    let sync = format!("[[sync]]\nname = \"A relay\"\nurl = \"ws://127.0.0.1:{pa}/peer/{secret}\"\ndirection = \"down\"\ntrusted = true\nreconcile_seconds = 3600\n");
    let mut b = Relay::configure(&db, free_port(), "", &sync);
    let c = Relay::configure(&dc, free_port(), "", "");
    a.start();
    let s = Signer::new(91);
    let expiring = |secs: u64, what: &str| s.event(now(), 1, json!([["expiration", (now() + secs).to_string()]]), what);
    let (plain, long, short) = (s.event(now(), 1, json!([]), "plain"), expiring(7200, "two hours"), expiring(300, "five minutes"));
    publish(&a, &[plain.clone(), long.clone(), short.clone()]).await;
    let has = |r: &Relay, e: &Value| r.count(&json!({"ids": [e["id"]]}).to_string()) == 1;

    b.start();
    let t = Instant::now();
    while stats(&b).await["sync"][0]["reconciles"].as_u64().unwrap_or(0) < 1 {
        assert!(t.elapsed() < Duration::from_secs(30), "B never finished a pass");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(has(&b, &plain) && has(&b, &long), "what outlives the pass is copied");
    assert!(!has(&b, &short), "what expires within ten minutes is not");
    assert_eq!(stats(&b).await["sync"][0]["last_need"], 2, "A left the short-lived one out of its set");

    // Each side names the other, and counts what the pass moved.
    let (sa, sb) = (stats(&a).await, stats(&b).await);
    let link = |st: &Value| st["links"][0].clone();
    assert_eq!((link(&sb)["name"].as_str(), link(&sb)["role"].as_str(), link(&sb)["moved"].as_u64()), (Some("A relay"), Some("running"), Some(2)), "{sb}");
    assert_eq!((link(&sa)["name"].as_str(), link(&sa)["role"].as_str(), link(&sa)["moved"].as_u64()), (Some("B relay"), Some("serving"), Some(2)), "{sa}");
    assert!(link(&sa)["last_at"].as_u64().unwrap() > 0 && link(&sb)["last_at"].as_u64().unwrap() > 0);

    // Live, a short-lived event crosses like any other.
    let fresh = expiring(300, "five minutes, live");
    publish(&a, std::slice::from_ref(&fresh)).await;
    let t = Instant::now();
    while !has(&b, &fresh) {
        assert!(t.elapsed() < Duration::from_secs(15), "the live link never brought it");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // A relay that is not a peer of A gets A's whole set, and drops the short-lived.
    c.run_ok(&["sync", &a.url()]);
    assert!(has(&c, &plain) && has(&c, &long));
    assert!(!has(&c, &short) && !has(&c, &fresh), "fetched, and dropped as expiring too soon");

    a.stop();
    b.stop();
    for d in [da, db, dc] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A two-way trusted link (as Asia runs against jskitty): once a pass is over,
/// what the live connection carries is not a pass. The peer used to be asked
/// about gift wraps on that connection, a negentropy session, and from then on
/// its side counted every live event as one pass that never ended.
#[tokio::test]
async fn a_two_way_live_link_is_not_counted_as_a_pass() {
    let secret = "d".repeat(20) + &"8".repeat(20);
    let (da, db) = (tmp("live-a"), tmp("live-b"));
    let pa = free_port();
    let mut a = Relay::configure(&da, pa, "", &format!("[[peer]]\nname = \"B relay\"\nsecret = \"{secret}\"\nips = [\"127.0.0.1\"]\n"));
    let sync = format!("[[sync]]\nname = \"A relay\"\nurl = \"ws://127.0.0.1:{pa}/peer/{secret}\"\ndirection = \"both\"\ntrusted = true\nreconcile_seconds = 3600\n");
    let mut b = Relay::configure(&db, free_port(), "", &sync);
    a.start();
    b.start();
    let t = Instant::now();
    while stats(&b).await["sync"][0]["reconciles"].as_u64().unwrap_or(0) < 1 {
        assert!(t.elapsed() < Duration::from_secs(30), "B never finished a pass");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let moved = |st: &Value| st["links"][0]["moved"].as_u64();
    let after_pass = moved(&stats(&a).await);

    // New events on B reach A over the live connection only.
    let s = Signer::new(93);
    let live: Vec<Value> = (0..5).map(|i| s.event(now(), 1, json!([]), &format!("live {i}"))).collect();
    publish(&b, &live).await;
    let ids: Vec<Value> = live.iter().map(|e| e["id"].clone()).collect();
    let filter = json!({"ids": ids}).to_string();
    wait_for("the live link to carry them", || a.count(&filter) == live.len() as u64).await;

    let sa = stats(&a).await;
    assert_eq!(moved(&sa), after_pass, "live events were counted as a pass: {sa}");

    a.stop();
    b.stop();
    for d in [da, db] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// Ephemeral events cross a sync both ways, as Asia's strfry router carried
/// typing and voice presence: delivered live on the other relay, once each,
/// never stored and never circling back, even when a client sends the same one
/// to both relays (as Vector publishes to several).
#[tokio::test]
async fn ephemeral_events_cross_a_sync_once_and_are_never_kept() {
    let (da, db) = (tmp("eph-a"), tmp("eph-b"));
    let pa = free_port();
    let mut a = Relay::configure(&da, pa, "", "");
    let mut b = Relay::configure(&db, free_port(), "", &format!("[[sync]]\nurl = \"ws://127.0.0.1:{pa}\"\ndirection = \"both\"\nreconcile_seconds = 3600\n"));
    a.start();
    b.start();
    let t = Instant::now();
    while stats(&b).await["sync"][0]["connected"] != 1 {
        assert!(t.elapsed() < Duration::from_secs(30), "B never connected to A");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // A listener on each relay, as a member of a community would be.
    async fn listen(r: &Relay) -> relay_net::conn::ClientConn {
        let mut c = client_connect(r.addr(), &format!("127.0.0.1:{}", r.port), "/").await.unwrap();
        c.send_text(&json!(["REQ", "eph", {"kinds": [21059], "limit": 0}]).to_string()).await.unwrap();
        raw_events(&mut c, "eph").await;
        c
    }
    async fn heard(c: &mut relay_net::conn::ClientConn, for_: Duration) -> Vec<String> {
        let mut ids = Vec::new();
        let until = Instant::now() + for_;
        while let Ok(m) = tokio::time::timeout(until.saturating_duration_since(Instant::now()), c.recv()).await {
            if let Message::Text(t) = m.unwrap() {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v[0] == "EVENT" {
                    ids.push(v[2]["id"].as_str().unwrap().to_string());
                }
            }
        }
        ids
    }
    let (mut la, mut lb) = (listen(&a).await, listen(&b).await);

    let s = Signer::new(90);
    let on_a = s.event(now(), 21059, json!([]), "typing on a");
    let on_b = s.event(now(), 21059, json!([]), "typing on b");
    let on_both = s.event(now(), 21059, json!([]), "typing on both");
    publish(&a, std::slice::from_ref(&on_a)).await;
    publish(&b, std::slice::from_ref(&on_b)).await;
    publish(&a, std::slice::from_ref(&on_both)).await;
    publish(&b, std::slice::from_ref(&on_both)).await;
    let (got_a, got_b) = (heard(&mut la, Duration::from_secs(3)).await, heard(&mut lb, Duration::from_secs(1)).await);
    for (relay, got) in [("A", &got_a), ("B", &got_b)] {
        for (ev, what) in [(&on_a, "the one sent to A"), (&on_b, "the one sent to B"), (&on_both, "the one sent to both")] {
            let n = got.iter().filter(|id| id.as_str() == ev["id"].as_str().unwrap()).count();
            assert_eq!(n, 1, "{relay}'s listener heard {what} {n} times: {got:?}");
        }
    }
    let kept = json!({"kinds": [21059]}).to_string();
    assert_eq!((a.count(&kept), b.count(&kept)), (0, 0), "ephemeral events are never stored");

    a.stop();
    b.stop();
    let _ = std::fs::remove_dir_all(&da);
    let _ = std::fs::remove_dir_all(&db);
}

/// Between full passes a comparison covers recent events only; an old event
/// that slipped past the stream (here, imported behind its back) waits for the
/// next full pass, and arrives with it.
#[tokio::test]
async fn an_old_event_the_recent_passes_miss_arrives_with_the_next_full_pass() {
    let (da, db) = (tmp("fa"), tmp("fb"));
    let pa = free_port();
    let mut a = Relay::configure(&da, pa, "", "");
    let mut b = Relay::configure(
        &db,
        free_port(),
        "",
        &format!("[[sync]]\nurl = \"ws://127.0.0.1:{pa}\"\ndirection = \"down\"\nreconcile_seconds = 1\nfull_reconcile_seconds = 6\n"),
    );
    a.start();
    b.start();
    let x = Signer::new(90);
    wait_for("the first, full, reconcile", || b.count("{}") == a.count("{}")).await;

    // Dated ten days ago, far outside the three-day window, and never streamed.
    a.stop();
    let old = x.event(now() - 10 * 86_400, 1, json!([]), "old");
    let recent = x.event(now() - 60, 1, json!([]), "recent");
    a.import(&[old, recent]);
    a.start();
    let author = json!({"authors": [x.pk()]}).to_string();
    wait_for("the recent event", || b.count(&author) >= 1).await;
    let s = stats(&b).await;
    if s["sync"][0]["full_reconciles"] == 1 {
        assert_eq!(b.count(&author), 1, "a recent pass reached back ten days: {s}");
    }
    wait_for("the old event, with a full pass", || b.count(&author) == 2).await;
    // The pass stores the event before it counts itself finished.
    let t = Instant::now();
    let s = loop {
        let s = stats(&b).await;
        if s["sync"][0]["full_reconciles"].as_u64().unwrap() >= 2 || t.elapsed() > Duration::from_secs(10) {
            break s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(s["sync"][0]["full_reconciles"].as_u64().unwrap() >= 2, "{s}");
    assert!(s["sync"][0]["reconciles"].as_u64().unwrap() > s["sync"][0]["full_reconciles"].as_u64().unwrap(), "{s}");

    a.stop();
    b.stop();
    let _ = std::fs::remove_dir_all(&da);
    let _ = std::fs::remove_dir_all(&db);
}

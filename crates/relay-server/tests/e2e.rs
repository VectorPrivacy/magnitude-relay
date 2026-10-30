//! End to end: the real binary, real sockets, Vector-shaped traffic.

use relay_net::conn::{client_connect, client_handshake, ClientConn, Message};
use relay_proto::hex;
use secp256k1::{schnorr, Keypair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

struct Relay {
    child: Child,
    addr: SocketAddr,
    dir: PathBuf,
}

impl Relay {
    fn start(dir: PathBuf, port: u16) -> Relay {
        Self::start_with(dir, port, "")
    }

    /// `store` is extra lines for the `[store]` section.
    fn start_with(dir: PathBuf, port: u16, store: &str) -> Relay {
        Self::start_limits(dir, port, "", store)
    }

    /// `limits` and `store` are extra lines for those sections.
    fn start_limits(dir: PathBuf, port: u16, limits: &str, store: &str) -> Relay {
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("relay.toml");
        std::fs::write(
            &cfg,
            format!(
                "[relay]\nbind = \"127.0.0.1:{port}\"\nthreads = 2\n[limits]\nevents_per_minute_per_ip = 0\n{limits}[store]\ndata = \"{}\"\n{store}",
                dir.join("data").display()
            ),
        )
        .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_magnitude-relay"))
            .arg("--config")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let t = Instant::now();
        while std::net::TcpStream::connect(addr).is_err() {
            assert!(t.elapsed() < Duration::from_secs(10), "relay did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        Relay { child, addr, dir }
    }

    fn stop(mut self) -> PathBuf {
        // SIGTERM: the graceful path.
        unsafe { libc_kill(self.child.id() as i32, 15) };
        let t = Instant::now();
        while self.child.try_wait().unwrap().is_none() {
            assert!(t.elapsed() < Duration::from_secs(10), "relay did not stop on SIGTERM");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::mem::take(&mut self.dir)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// A port nothing listens on. The socket that finds it is bound and never
/// listening: a child that another test's thread spawns meanwhile holds a copy
/// of it until its exec (Linux), and a listening copy took the readiness probe
/// and the first client_connect, then reset them when it closed. SO_REUSEADDR
/// lets the relay bind while such a copy is still open.
fn free_port() -> u16 {
    let s = tokio::net::TcpSocket::new_v4().unwrap();
    s.set_reuseaddr(true).unwrap();
    s.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    s.local_addr().unwrap().port()
}

struct Signer(Keypair);
impl Signer {
    fn new(seed: u8) -> Signer {
        Signer(Keypair::from_secret_bytes([seed; 32]).unwrap())
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

async fn send<S: AsyncRead + AsyncWrite + Unpin>(c: &mut ClientConn<S>, v: Value) {
    c.send_text(&v.to_string()).await.unwrap();
}

async fn recv<S: AsyncRead + AsyncWrite + Unpin>(c: &mut ClientConn<S>) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), c.recv()).await.expect("timed out waiting for a message").unwrap() {
            Message::Text(t) => return serde_json::from_str(&t).unwrap(),
            _ => continue,
        }
    }
}

/// Reads until EOSE (or CLOSED) for `sub`, returning the events.
async fn collect<S: AsyncRead + AsyncWrite + Unpin>(c: &mut ClientConn<S>, sub: &str) -> (Vec<Value>, Value) {
    let mut evs = Vec::new();
    loop {
        let m = recv(c).await;
        match m[0].as_str().unwrap() {
            "EVENT" if m[1] == sub => evs.push(m[2].clone()),
            "EOSE" | "CLOSED" if m[1] == sub => return (evs, m),
            _ => {}
        }
    }
}

async fn ok_of<S: AsyncRead + AsyncWrite + Unpin>(c: &mut ClientConn<S>) -> (bool, String) {
    loop {
        let m = recv(c).await;
        if m[0] == "OK" {
            return (m[2].as_bool().unwrap(), m[3].as_str().unwrap().to_string());
        }
    }
}

#[tokio::test]
async fn vector_flows_end_to_end() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir, port);
    let host = format!("127.0.0.1:{port}");

    let me = Signer::new(1);
    let sender = Signer::new(2);
    let mut a = client_connect(relay.addr, &host, "/").await.unwrap();
    let mut b = client_connect(relay.addr, &host, "/").await.unwrap();

    // A: live DM subscription, Vector's exact shape.
    send(&mut a, json!(["REQ", "dm", {"kinds": [1059], "#p": [me.pk()], "limit": 0}])).await;
    let (evs, end) = collect(&mut a, "dm").await;
    assert!(evs.is_empty());
    assert_eq!(end[0], "EOSE");

    // B publishes a wrap (backdated a day, as NIP-17 does); A gets it live.
    let wrap = sender.event(now() - 86_400, 1059, json!([["p", me.pk()]]), "ciphertext");
    let t = Instant::now();
    send(&mut b, json!(["EVENT", wrap])).await;
    assert_eq!(ok_of(&mut b).await, (true, String::new()));
    let live = recv(&mut a).await;
    let latency = t.elapsed();
    assert_eq!(live[0], "EVENT");
    assert_eq!(live[1], "dm");
    assert_eq!(live[2]["id"], wrap["id"]);
    eprintln!("publish -> OK -> live delivery: {latency:?}");

    // A resend is a duplicate, answered without storing again.
    send(&mut b, json!(["EVENT", wrap])).await;
    let (okv, msg) = ok_of(&mut b).await;
    assert!(okv && msg.starts_with("duplicate:"), "{msg}");

    // History and COUNT.
    send(&mut a, json!(["REQ", "hist", {"kinds": [1059], "#p": [me.pk()]}])).await;
    let (evs, _) = collect(&mut a, "hist").await;
    assert_eq!(evs.len(), 1);
    assert_eq!(serde_json::to_string(&evs[0]).unwrap().len(), wrap.to_string().len());
    send(&mut a, json!(["COUNT", "c", {"kinds": [1059], "#p": [me.pk()]}])).await;
    let m = recv(&mut a).await;
    assert_eq!(m, json!(["COUNT", "c", {"count": 1}]));

    // NIP-77: Vector's DM sync. The client holds the first wrap plus one the
    // relay never saw; the relay holds three more. The reference client must
    // learn exactly which three to fetch.
    let mut more = Vec::new();
    for i in 0..3 {
        let w = sender.event(now() - 3600 * (i + 2), 1059, json!([["p", me.pk()]]), &format!("w{i}"));
        send(&mut b, json!(["EVENT", w])).await;
        assert!(ok_of(&mut b).await.0);
        more.push(w["id"].as_str().unwrap().to_string());
    }
    {
        use negentropy::{Id, Negentropy, NegentropyStorageVector};
        let mut st = NegentropyStorageVector::new();
        let held = [(wrap["created_at"].as_u64().unwrap(), wrap["id"].as_str().unwrap().to_string()), (now() - 99_999, "ab".repeat(32))];
        for (t, id) in &held {
            st.insert(*t, Id::from_byte_array(hex::decode_32(id.as_bytes()).unwrap())).unwrap();
        }
        st.seal().unwrap();
        let mut neg = Negentropy::owned(st, 60_000).unwrap();
        let init = neg.initiate().unwrap();
        send(&mut a, json!(["NEG-OPEN", "neg", {"kinds": [1059], "#p": [me.pk()]}, hex::encode_string(&init)])).await;
        let (mut have, mut need) = (Vec::new(), Vec::new());
        loop {
            // The live "dm" subscription is still open, so the new wraps arrive too.
            let m = loop {
                let m = recv(&mut a).await;
                if m[0] != "EVENT" {
                    break m;
                }
            };
            assert_eq!(m[0], "NEG-MSG", "{m}");
            let bytes = hex::decode_any_case(m[2].as_str().unwrap().as_bytes()).unwrap();
            match neg.reconcile_with_ids(&bytes, &mut have, &mut need).unwrap() {
                Some(next) => send(&mut a, json!(["NEG-MSG", "neg", hex::encode_string(&next)])).await,
                None => break,
            }
        }
        send(&mut a, json!(["NEG-CLOSE", "neg"])).await;
        let mut need: Vec<String> = need.iter().map(|i| hex::encode_string(i.as_bytes())).collect();
        need.sort();
        more.sort();
        assert_eq!(need, more);
        assert_eq!(have.len(), 1, "the wrap the relay never saw");
    }

    // Ephemeral Concord wrap: delivered live, never stored.
    let plane = Signer::new(3);
    send(&mut a, json!(["REQ", "plane", {"kinds": [1059, 21059], "authors": [plane.pk()], "since": now() - 300, "limit": 0}])).await;
    collect(&mut a, "plane").await;
    let typing = plane.event(now(), 21059, json!([["p", Signer::new(9).pk()]]), "typing");
    send(&mut b, json!(["EVENT", typing])).await;
    assert_eq!(ok_of(&mut b).await, (true, String::new()));
    let m = recv(&mut a).await;
    assert_eq!((m[0].as_str(), m[1].as_str()), (Some("EVENT"), Some("plane")));
    send(&mut a, json!(["REQ", "plane2", {"kinds": [21059], "authors": [plane.pk()]}])).await;
    assert!(collect(&mut a, "plane2").await.0.is_empty(), "ephemeral events are not stored");

    // Policy: public notes are refused; forged signatures are refused.
    send(&mut b, json!(["EVENT", sender.event(now(), 1, json!([]), "hello world")])).await;
    let (okv, msg) = ok_of(&mut b).await;
    assert!(!okv && msg.starts_with("blocked:"), "{msg}");
    let mut forged = sender.event(now(), 1059, json!([["p", me.pk()]]), "x");
    forged["sig"] = json!("00".repeat(64));
    send(&mut b, json!(["EVENT", forged])).await;
    let (okv, msg) = ok_of(&mut b).await;
    assert!(!okv && msg.contains("signature"), "{msg}");

    // No bulk scraping of gift wraps.
    send(&mut a, json!(["REQ", "scrape", {"kinds": [1059], "limit": 10}])).await;
    let (_, end) = collect(&mut a, "scrape").await;
    assert_eq!(end[0], "CLOSED");
    assert!(end[2].as_str().unwrap().starts_with("restricted:"));

    // NIP-11 over plain HTTP.
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nAccept: application/nostr+json\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let body = &resp[resp.find("\r\n\r\n").unwrap() + 4..];
    let info: Value = serde_json::from_str(body).unwrap();
    assert!(info["supported_nips"].as_array().unwrap().contains(&json!(77)));
    assert!(!info["supported_nips"].as_array().unwrap().contains(&json!(42)));

    // Stats and metrics over plain HTTP.
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let stats: Value = serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert!(stats["events_stored"].as_u64().unwrap() >= 4, "{stats}");
    assert!(stats["reqs"].as_u64().unwrap() >= 4);
    assert_eq!(stats["store"]["live"].as_u64().unwrap(), 4);

    // A clean restart keeps everything.
    drop((a, b));
    let dir = relay.stop();
    let relay = Relay::start(dir, port);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["REQ", "again", {"ids": [wrap["id"]], "kinds": [1059], "#p": [me.pk()]}])).await;
    let (evs, _) = collect(&mut c, "again").await;
    assert_eq!(evs.len(), 1);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// Every log file under the relay's data directory, read whole.
fn log_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![dir.join("data").join("log")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            if e.path().is_dir() {
                stack.push(e.path());
            } else {
                out.extend(std::fs::read(e.path()).unwrap());
            }
        }
    }
    out
}

#[tokio::test]
async fn deleted_content_leaves_the_disk_with_idle_reactors() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-zero-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    // Small log segments, so the files can be read whole while polling.
    let relay = Relay::start_with(dir.clone(), port, "segment_mb = 16\n");
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(7);
    let secret = "SECRET-SETTINGS-QQQQ";
    let ev = me.event(now(), 30078, json!([["d", "vector/settings"]]), secret);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["EVENT", ev])).await;
    assert!(ok_of(&mut c).await.0);
    let del = me.event(now(), 5, json!([["e", ev["id"]]]), "");
    send(&mut c, json!(["EVENT", del])).await;
    assert!(ok_of(&mut c).await.0);
    drop(c);
    // Nothing else talks to the relay: its other reactor still holds the
    // snapshot it took at startup, from before the deletion.
    let t = Instant::now();
    while log_bytes(&dir).windows(secret.len()).any(|w| w == secret.as_bytes()) {
        assert!(t.elapsed() < Duration::from_secs(5), "deleted content still on disk after 5 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn compressing_clients_get_stateless_deflate() {
    use relay_net::conn::{client_connect_with, ClientDeflate};
    use relay_net::ws::Role;
    let dir = std::env::temp_dir().join(format!("relay-e2e-deflate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(9);

    // A browser-style offer (context takeover both ways): the relay answers
    // stateless, so it keeps no codec memory for this connection.
    let mut c = client_connect_with(relay.addr, &host, "/", Some(ClientDeflate::default())).await.unwrap();
    let p = *c.deflate_params().expect("deflate negotiated");
    assert!(!p.send(Role::Server).context_takeover && !p.send(Role::Client).context_takeover);

    // Big enough to be compressed both ways; repetitive enough to show it.
    let content = "vector settings ".repeat(400);
    let ev = me.event(now(), 30078, json!([["d", "vector/settings"]]), &content);
    send(&mut c, json!(["EVENT", ev])).await;
    assert!(ok_of(&mut c).await.0);
    send(&mut c, json!(["REQ", "s", {"kinds": [30078], "authors": [me.pk()]}])).await;
    let (evs, end) = collect(&mut c, "s").await;
    assert_eq!(end[0], "EOSE");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0]["content"], content);
    assert_eq!(evs[0]["id"], ev["id"]);

    // A client that offers nothing still gets plain frames.
    let mut plain = client_connect(relay.addr, &host, "/").await.unwrap();
    assert!(plain.deflate_params().is_none());
    send(&mut plain, json!(["REQ", "s", {"kinds": [30078], "authors": [me.pk()]}])).await;
    let (evs, _) = collect(&mut plain, "s").await;
    assert_eq!(evs[0]["content"], content);

    // Counted.
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let stats: Value = serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(stats["connections_deflate"].as_u64(), Some(1), "{stats}");
    // The plain client got the 6.4 KB event as is; the compressing one a few
    // hundred bytes for it.
    let out = stats["bytes_out"].as_u64().unwrap();
    eprintln!("bytes out: {out}");
    assert!(out < 9_000, "the event went out uncompressed to both: {out} bytes");

    drop((c, plain));
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn large_live_events_reach_every_subscriber_intact() {
    use relay_net::conn::{client_connect_with, ClientDeflate};
    let dir = std::env::temp_dir().join(format!("relay-e2e-share-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(11);
    let author = Signer::new(12);

    // Two plain subscribers (they share each large event's bytes), one that
    // compresses (it gets its own), and one that stops reading for a while.
    let filter = json!({"kinds": [1059], "#p": [me.pk()], "limit": 0});
    let mut subs = Vec::new();
    for i in 0..4 {
        let mut c = if i == 2 {
            client_connect_with(relay.addr, &host, "/", Some(ClientDeflate::default())).await.unwrap()
        } else {
            client_connect(relay.addr, &host, "/").await.unwrap()
        };
        send(&mut c, json!(["REQ", format!("s{i}"), filter])).await;
        let (_, end) = collect(&mut c, &format!("s{i}")).await;
        assert_eq!(end[0], "EOSE");
        subs.push(c);
    }

    // A burst of large wraps, interleaved with small ones (which are copied).
    let mut publisher = client_connect(relay.addr, &host, "/").await.unwrap();
    let mut sent = Vec::new();
    for n in 0..200u64 {
        let size = if n % 5 == 0 { 300 } else { 4000 + (n as usize * 37) % 3000 };
        let content: String = (0..size).map(|k| (b'a' + ((k as u64 + n) % 26) as u8) as char).collect();
        let ev = author.event(now() - n, 1059, json!([["p", me.pk()]]), &content);
        send(&mut publisher, json!(["EVENT", ev])).await;
        sent.push(ev);
    }
    for _ in 0..sent.len() {
        assert!(ok_of(&mut publisher).await.0);
    }

    // Every subscriber, the slow one included, gets every event, in order, byte for byte.
    for (i, c) in subs.iter_mut().enumerate() {
        if i == 3 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        for (n, ev) in sent.iter().enumerate() {
            let m = recv(c).await;
            assert_eq!(m[0], "EVENT", "subscriber {i}, event {n}: {m}");
            assert_eq!(m[1], format!("s{i}"));
            assert_eq!(&m[2], ev, "subscriber {i}, event {n}");
        }
    }

    // The large ones went out shared to the three plain subscribers.
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let stats: Value = serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(stats["events_shared"].as_u64(), Some(160 * 3), "{stats}");

    drop((subs, publisher));
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// Runs one of the binary's commands against the relay whose settings are in
/// `dir`: (success, stdout, stderr).
fn run(dir: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(dir.join("relay.toml")).args(args).output().unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

/// A command that must succeed; its stdout.
fn run_ok(dir: &std::path::Path, args: &[&str]) -> String {
    let (ok, out, err) = run(dir, args);
    assert!(ok, "{args:?} failed: {err}");
    out
}

/// A command that must be refused, whose complaint contains `why`.
fn run_refused(dir: &std::path::Path, args: &[&str], why: &str) {
    let (ok, out, err) = run(dir, args);
    assert!(!ok, "{args:?} should have been refused; it printed {out:?}");
    assert!(err.contains(why), "{args:?}: wanted {why:?} in {err:?}");
}

/// The ids of the JSONL events a command printed, in order.
fn ids_printed(out: &str) -> Vec<String> {
    out.lines().map(|l| serde_json::from_str::<Value>(l).unwrap()["id"].as_str().unwrap().to_string()).collect()
}

async fn ids_over_req(relay: &Relay, filter: Value) -> Vec<String> {
    let host = relay.addr.to_string();
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["REQ", "r", filter])).await;
    let (evs, _) = collect(&mut c, "r").await;
    evs.iter().map(|e| e["id"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn operator_commands_reach_a_running_relay_and_a_stopped_one() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("relay-e2e-adm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let (me, other) = (Signer::new(11), Signer::new(12));

    // Four wraps to `me`, 4000 to 1000 seconds old, and a profile each.
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    let mut wrap_events = Vec::new();
    for age in [4000, 3000, 2000, 1000] {
        let wrap = other.event(now() - age, 1059, json!([["p", me.pk()]]), &format!("wrap {age}"));
        send(&mut c, json!(["EVENT", wrap])).await;
        assert!(ok_of(&mut c).await.0);
        wrap_events.push(wrap);
    }
    let wraps: Vec<String> = wrap_events.iter().map(|w| w["id"].as_str().unwrap().to_string()).collect();
    let mut profiles = Vec::new();
    for s in [&me, &other] {
        let p = s.event(now() - 10, 0, json!([]), "{}");
        send(&mut c, json!(["EVENT", p])).await;
        assert!(ok_of(&mut c).await.0);
        profiles.push(p["id"].as_str().unwrap().to_string());
    }
    drop(c);
    let to_me = json!({"kinds": [1059], "#p": [me.pk()]});
    let newest_first = |ids: &[String]| ids.iter().rev().cloned().collect::<Vec<_>>();

    // The socket is there, and only its owner can open it.
    let sock = dir.join("data").join("admin.sock");
    assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(!dir.join("data").join("admin.tmp").exists(), "the staging directory is gone");

    // Reading through the running relay.
    assert_eq!(run_ok(&dir, &["count", "--filter", r#"{"kinds":[1059]}"#]), "4\n");
    assert_eq!(run_ok(&dir, &["count", "--filter", r#"[{"kinds":[1059]},{"kinds":[0]},{"kinds":[1059,0]}]"#]), "6\n", "a union counts an event once");
    let q = run_ok(&dir, &["query", "--filter", r#"{"kinds":[1059]}"#]);
    assert_eq!(ids_printed(&q), newest_first(&wraps));
    // The same bytes REQ would send for it.
    let first: Value = serde_json::from_str(q.lines().next().unwrap()).unwrap();
    assert_eq!(first["content"], "wrap 1000");
    assert_eq!(ids_printed(&run_ok(&dir, &["query", "--filter", r#"{"kinds":[1059]}"#, "--limit", "2"])), newest_first(&wraps)[..2]);

    // Refusals change nothing.
    run_refused(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#], "--dry-run");
    run_refused(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--dry-run", "--yes"], "not both");
    run_refused(&dir, &["delete", "--filter", "{}", "--yes"], "--all");
    run_refused(&dir, &["delete", "--filter", "{}", "--dry-run"], "--all");
    run_refused(&dir, &["delete", "--filter", r#"[{"kinds":[1059]},{}]"#, "--age", "5", "--yes"], "--all");
    run_refused(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--yes", "--agee", "5"], "unexpected argument");
    run_refused(&dir, &["delete", "--filter", r#"{"kinds":[1059],"limit":1}"#, "--yes"], "limit");
    run_refused(&dir, &["delete", "--yes"], "needs --filter");
    run_refused(&dir, &["query", "--filter", r#"{"kinds":[1059]"#], "bad");
    assert_eq!(run_ok(&dir, &["count", "--filter", "[{}]"]), "6\n");

    // A dry run says what would go and touches nothing.
    let dry = run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--dry-run"]);
    assert!(dry.starts_with("would delete 4 events"), "{dry}");
    for id in &wraps {
        assert!(dry.contains(id.as_str()), "{id} not among the samples: {dry}");
    }
    assert!(dry.contains("kind 1059") && dry.contains(&other.pk()[..8]), "{dry}");
    let aged = run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--age", "2500", "--dry-run"]);
    assert!(aged.starts_with("would delete 2 events"), "{aged}");
    run_refused(&dir, &["count", "--filter", "{}", "--age", "5"], "unexpected argument");
    assert_eq!(ids_over_req(&relay, to_me.clone()).await.len(), 4);

    // Delete the old ones, then the rest: gone for a client too, and the
    // profiles are never touched.
    assert_eq!(run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--age", "2500", "--yes"]), "deleted 2 events\n");
    assert_eq!(ids_over_req(&relay, to_me.clone()).await, newest_first(&wraps[2..]));
    assert_eq!(run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--yes"]), "deleted 2 events\n");
    assert!(ids_over_req(&relay, to_me.clone()).await.is_empty());
    assert_eq!(run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--yes"]), "deleted 0 events\n");
    assert_eq!(ids_over_req(&relay, json!({"kinds": [0]})).await.len(), 2);
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "2\n");
    assert_eq!(ids_printed(&run_ok(&dir, &["query", "--filter", "{}"])).len(), 2);

    // A deleted event can be published again: no tombstone is kept.
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["EVENT", wrap_events[3]])).await;
    assert!(ok_of(&mut c).await.0);
    drop(c);
    assert_eq!(ids_over_req(&relay, to_me.clone()).await, vec![wraps[3].clone()]);
    assert_eq!(run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--yes"]), "deleted 1 event\n");

    // Stopped cleanly, the relay takes its socket with it. The same commands
    // now open the data directory.
    let dir = relay.stop();
    assert!(!sock.exists(), "the socket is removed on clean shutdown");
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "2\n");
    let mut stored = ids_printed(&run_ok(&dir, &["query", "--filter", r#"{"kinds":[0]}"#]));
    stored.sort();
    let mut want = profiles.clone();
    want.sort();
    assert_eq!(stored, want);
    assert_eq!(run_ok(&dir, &["count", "--filter", r#"{"kinds":[1059]}"#]), "0\n");
    let dry = run_ok(&dir, &["delete", "--filter", &format!(r#"{{"authors":["{}"]}}"#, other.pk()), "--dry-run"]);
    assert!(dry.starts_with("would delete 1 event "), "{dry}");
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "2\n");
    assert_eq!(run_ok(&dir, &["delete", "--filter", &format!(r#"{{"authors":["{}"]}}"#, other.pk()), "--yes"]), "deleted 1 event\n");
    assert_eq!(ids_printed(&run_ok(&dir, &["query", "--filter", "{}"])), vec![profiles[0].clone()]);

    // Neither delete came back with a restart.
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    assert_eq!(ids_over_req(&relay, json!({"kinds": [0]})).await, vec![profiles[0].clone()]);
    assert!(ids_over_req(&relay, to_me).await.is_empty());
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn operator_deleted_content_leaves_the_disk() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-adm-zero-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start_with(dir.clone(), port, "segment_mb = 16\n");
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(31);
    let secret = "SECRET-NOTE-WWWW";
    let ev = me.event(now(), 30078, json!([["d", "notes"]]), secret);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["EVENT", ev])).await;
    assert!(ok_of(&mut c).await.0);
    drop(c);
    assert!(log_bytes(&dir).windows(secret.len()).any(|w| w == secret.as_bytes()));

    let by_id = format!(r#"{{"ids":["{}"]}}"#, ev["id"].as_str().unwrap());
    assert_eq!(run_ok(&dir, &["delete", "--filter", &by_id, "--yes"]), "deleted 1 event\n");
    // The relay's own readers and the command's snapshot are gone a moment
    // later, and then the bytes are too.
    let t = Instant::now();
    while log_bytes(&dir).windows(secret.len()).any(|w| w == secret.as_bytes()) {
        assert!(t.elapsed() < Duration::from_secs(5), "deleted content still on disk after 5 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_crashed_relays_admin_socket_is_replaced() {
    use std::os::unix::net::UnixListener;
    let dir = std::env::temp_dir().join(format!("relay-e2e-stale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // What a killed relay leaves: a socket file no one is listening on.
    let sock = dir.join("data").join("admin.sock");
    std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
    drop(UnixListener::bind(&sock).unwrap());
    assert!(sock.exists());

    let relay = Relay::start(dir.clone(), free_port());
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "0\n");
    let dir = relay.stop();
    assert!(!sock.exists());

    // A file that is not a socket is left alone, and the relay serves without it.
    std::fs::write(&sock, "mine").unwrap();
    let relay = Relay::start(dir.clone(), free_port());
    assert_eq!(std::fs::read_to_string(&sock).unwrap(), "mine");
    run_refused(&dir, &["count", "--filter", "{}"], "admin socket");
    let dir = relay.stop();
    assert_eq!(std::fs::read_to_string(&sock).unwrap(), "mine");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_big_delete_runs_beside_live_writes() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("relay-e2e-big-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Settings written by a first start; then 60,000 events loaded offline.
    drop(Relay::start(dir.clone(), free_port()).stop());
    let n = 60_000u64;
    let file = dir.join("in.jsonl");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&file).unwrap());
    for i in 0..n {
        let (id, pk) = (format!("{:064x}", i + 1), format!("{:064x}", i % 7 + 1));
        let (at, sig) = (1_700_000_000 + i, "00".repeat(64));
        writeln!(f, r#"{{"content":"x","created_at":{at},"id":"{id}","kind":1059,"pubkey":"{pk}","sig":"{sig}","tags":[]}}"#).unwrap();
    }
    // A public note: not a kind the relay accepts, so import leaves it out.
    writeln!(f, r#"{{"content":"x","created_at":1700000000,"id":"{:064x}","kind":1,"pubkey":"{:064x}","sig":"{}","tags":[]}}"#, n + 1, 1, "00".repeat(64)).unwrap();
    drop(f);
    run_ok(&dir, &["import", "--no-verify", file.to_str().unwrap()]);
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), format!("{n}\n"));

    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let mut delete = Command::new(env!("CARGO_BIN_EXE_magnitude-relay"))
        .arg("--config")
        .arg(dir.join("relay.toml"))
        .args(["delete", "--filter", r#"{"kinds":[1059]}"#, "--yes"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Writes made while it runs are all accepted.
    let me = Signer::new(21);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    let mut slowest = Duration::ZERO;
    for i in 0..40 {
        let ev = me.event(now(), 30078, json!([["d", format!("note-{i}")]]), "live");
        let t = Instant::now();
        send(&mut c, json!(["EVENT", ev])).await;
        assert!(ok_of(&mut c).await.0);
        slowest = slowest.max(t.elapsed());
    }
    eprintln!("slowest OK while the delete ran: {slowest:?} (delete still running afterwards: {})", delete.try_wait().unwrap().is_none());
    let out = delete.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("deleted {n} events\n"));
    assert_eq!(run_ok(&dir, &["count", "--filter", r#"{"kinds":[1059]}"#]), "0\n");
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "40\n", "the live writes are all there, and nothing else");
    assert_eq!(ids_over_req(&relay, json!({"kinds": [30078], "authors": [me.pk()]})).await.len(), 40);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn counts_are_exact_and_big_ones_leave_the_reactors() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-count-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    // Settings first, then a mailbox of 60 000 wraps loaded unsigned (signing
    // that many in a debug build would take minutes).
    relay_stop_quietly(Relay::start(dir.clone(), port));
    let hex = |b: u8, n: u64| {
        let mut v = [b; 32];
        v[..8].copy_from_slice(&n.to_le_bytes());
        hex::encode_string(&v)
    };
    let (big, small) = (hex(0xB1, 0), hex(0xB2, 0));
    let mut lines = String::new();
    for n in 0..60_100u64 {
        let to = if n < 60_000 { &big } else { &small };
        lines.push_str(&format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":{},"kind":1059,"tags":[["p","{to}"]],"content":"w","sig":"{}"}}"#,
            hex(0xEE, n),
            hex(0xC0, n),
            1_700_000_000 + n,
            "00".repeat(64)
        ));
        lines.push('\n');
    }
    let file = dir.join("wraps.jsonl");
    std::fs::write(&file, lines).unwrap();
    run_ok(&dir, &["import", "--no-verify", file.to_str().unwrap()]);

    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    let count = |sub: &str, filters: Vec<Value>| {
        let mut m = vec![json!("COUNT"), json!(sub)];
        m.extend(filters);
        Value::Array(m)
    };
    // Small: answered on the spot. Big: by a counting worker. Both exact.
    send(&mut c, count("s", vec![json!({"kinds": [1059], "#p": [small]})])).await;
    let m = recv(&mut c).await;
    assert_eq!(m, json!(["COUNT", "s", {"count": 100}]));
    send(&mut c, count("b", vec![json!({"kinds": [1059], "#p": [big]})])).await;
    let m = recv(&mut c).await;
    assert_eq!(m, json!(["COUNT", "b", {"count": 60_000}]), "exact, no approximation");
    // A union counts each event once.
    send(&mut c, count("u", vec![json!({"kinds": [1059], "#p": [big]}), json!({"kinds": [1059], "#p": [big, small]})])).await;
    assert_eq!(recv(&mut c).await, json!(["COUNT", "u", {"count": 60_100}]));
    // A window inside the big mailbox.
    send(&mut c, count("w", vec![json!({"kinds": [1059], "#p": [big], "since": 1_700_010_000u64, "until": 1_700_019_999u64})])).await;
    assert_eq!(recv(&mut c).await, json!(["COUNT", "w", {"count": 10_000}]));

    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let stats: Value = serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(stats["counts_offloaded"].as_u64(), Some(2), "{stats}");

    drop(c);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

fn relay_stop_quietly(r: Relay) {
    let _ = r.stop();
}

#[tokio::test]
async fn a_backup_runs_beside_live_writes_and_restores() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("relay-e2e-backup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    drop(Relay::start(dir.clone(), free_port()).stop());
    let n = 60_000u64;
    let file = dir.join("in.jsonl");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&file).unwrap());
    for i in 0..n {
        let (id, pk) = (format!("{:064x}", i + 1), format!("{:064x}", i % 7 + 1));
        let (at, sig) = (1_700_000_000 + i, "00".repeat(64));
        writeln!(f, r#"{{"content":"x","created_at":{at},"id":"{id}","kind":1059,"pubkey":"{pk}","sig":"{sig}","tags":[]}}"#).unwrap();
    }
    drop(f);
    run_ok(&dir, &["import", "--no-verify", file.to_str().unwrap()]);

    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let dest = dir.join("backup");
    let backup = Command::new(env!("CARGO_BIN_EXE_magnitude-relay"))
        .arg("--config")
        .arg(dir.join("relay.toml"))
        .args(["backup", dest.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Writes made while it runs are all accepted.
    let me = Signer::new(31);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    for i in 0..40 {
        send(&mut c, json!(["EVENT", me.event(now(), 30078, json!([["d", format!("note-{i}")]]), "live")])).await;
        assert!(ok_of(&mut c).await.0);
    }
    let out = backup.wait_with_output().unwrap();
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let held = said.lines().next().unwrap().strip_prefix("backed up ").unwrap().split(' ').next().unwrap().parse::<u64>().unwrap();
    assert!((n..=n + 40).contains(&held), "{said}");
    assert!(said.contains("verified: it opens as a store of"), "{said}");

    // The relay carries on; a second backup to the same place, or one into the
    // data directory, is refused and changes nothing.
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), format!("{}\n", n + 40));
    run_refused(&dir, &["backup", dest.to_str().unwrap()], "already exists");
    run_refused(&dir, &["backup", dir.join("data").join("copies").join("one").to_str().unwrap()], "inside the data directory");
    assert!(!dir.join("data").join("copies").exists());
    run_refused(&dir, &["backup"], "needs a destination");
    drop(c);
    let dir = relay.stop();

    // Offline too: the stopped relay's directory is opened directly.
    let offline = run_ok(&dir, &["backup", dir.join("backup-offline").to_str().unwrap(), "--no-verify"]);
    assert!(offline.starts_with(&format!("backed up {} events", n + 40)), "{offline}");

    // Restore: a relay started on the backup serves what it held, and takes new events.
    let restored = dir.join("restored");
    std::fs::create_dir_all(&restored).unwrap();
    std::fs::rename(&dest, restored.join("data")).unwrap();
    let port = free_port();
    let relay = Relay::start(restored.clone(), port);
    assert_eq!(run_ok(&restored, &["count", "--filter", r#"{"kinds":[1059]}"#]), format!("{n}\n"));
    assert_eq!(run_ok(&restored, &["count", "--filter", "{}"]), format!("{held}\n"));
    let mut c = client_connect(relay.addr, &format!("127.0.0.1:{port}"), "/").await.unwrap();
    send(&mut c, json!(["EVENT", me.event(now(), 30078, json!([["d", "after"]]), "after restore")])).await;
    assert!(ok_of(&mut c).await.0);
    assert_eq!(run_ok(&restored, &["count", "--filter", "{}"]), format!("{}\n", held + 1));
    drop(c);
    relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn overlapping_filters_send_each_event_once_newest_first() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-union-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let mut c = client_connect(relay.addr, &format!("127.0.0.1:{port}"), "/").await.unwrap();
    let me = Signer::new(41);
    let mut ids = Vec::new();
    for (i, kind) in [(0u64, 30078), (1, 1059), (2, 30078)] {
        let tags = if kind == 1059 { json!([["p", me.pk()]]) } else { json!([["d", format!("n{i}")]]) };
        let e = me.event(now() - 100 + i, kind, tags, "x");
        send(&mut c, json!(["EVENT", e])).await;
        assert!(ok_of(&mut c).await.0);
        ids.push(e["id"].as_str().unwrap().to_string());
    }
    // Every event matches two or three of these; the first id is listed twice.
    let all = json!({"authors": [me.pk()]});
    let by_kind = json!({"kinds": [30078, 1059], "authors": [me.pk()]});
    let by_id = json!({"ids": [ids[0], ids[2], ids[0]]});
    send(&mut c, json!(["REQ", "u", all, by_kind, by_id])).await;
    let (evs, _) = collect(&mut c, "u").await;
    let got: Vec<&str> = evs.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert_eq!(got, vec![ids[2].as_str(), ids[1].as_str(), ids[0].as_str()]);
    // One filter that lists an id twice.
    send(&mut c, json!(["REQ", "one", {"ids": [ids[1], ids[1]]}])).await;
    let (evs, _) = collect(&mut c, "one").await;
    assert_eq!(evs.len(), 1);
    // A broad filter leaves the gift wrap out, unless another names its recipient.
    send(&mut c, json!(["REQ", "broad", {}])).await;
    let (evs, _) = collect(&mut c, "broad").await;
    let got: Vec<&str> = evs.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert_eq!(got, vec![ids[2].as_str(), ids[0].as_str()]);
    send(&mut c, json!(["REQ", "named", {}, {"kinds": [1059], "#p": [me.pk()]}])).await;
    let (evs, _) = collect(&mut c, "named").await;
    assert_eq!(evs.len(), 3);
    drop(c);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_web_server_can_reach_the_relay_over_a_unix_socket() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let dir = std::env::temp_dir().join(format!("relay-e2e-unix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("r.sock");
    let port = free_port();
    let cfg = dir.join("relay.toml");
    std::fs::write(
        &cfg,
        format!(
            "[relay]\nbind = \"127.0.0.1:{port}\"\nunix_socket = \"{}\"\nunix_socket_mode = \"600\"\nreal_ip_header = \"x-real-ip\"\nthreads = 2\n[limits]\nevents_per_minute_per_ip = 0\n[store]\ndata = \"{}\"\n",
            sock.display(),
            dir.join("data").display()
        ),
    )
    .unwrap();
    let start = || {
        let child = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let t = Instant::now();
        while std::os::unix::net::UnixStream::connect(&sock).is_err() || std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(t.elapsed() < Duration::from_secs(10), "relay did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        child
    };
    let unix = || async { client_handshake(tokio::net::UnixStream::connect(&sock).await.unwrap(), "relay.example", "/").await.unwrap() };
    let mut child = start();
    let meta = std::fs::symlink_metadata(&sock).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    // Publish over the socket, read over TCP; a big live event to a socket
    // subscriber goes the shared (spliced) way.
    let me = Signer::new(51);
    let mut sub = unix().await;
    send(&mut sub, json!(["REQ", "live", {"kinds": [30078], "authors": [me.pk()], "limit": 0}])).await;
    let (_, eose) = collect(&mut sub, "live").await;
    assert_eq!(eose[0], "EOSE");
    let mut u = unix().await;
    let small = me.event(now(), 30078, json!([["d", "a"]]), "over the socket");
    send(&mut u, json!(["EVENT", small])).await;
    assert!(ok_of(&mut u).await.0);
    let mut t = client_connect(("127.0.0.1", port), &format!("127.0.0.1:{port}"), "/").await.unwrap();
    send(&mut t, json!(["REQ", "q", {"ids": [small["id"]]}])).await;
    assert_eq!(collect(&mut t, "q").await.0.len(), 1);
    let big = me.event(now(), 30078, json!([["d", "b"]]), &"x".repeat(6000));
    send(&mut t, json!(["EVENT", big])).await;
    assert!(ok_of(&mut t).await.0);
    let mut live = Vec::new();
    while live.len() < 2 {
        let m = recv(&mut sub).await;
        if m[0] == "EVENT" && m[1] == "live" {
            live.push(m[2]["id"].clone());
        }
    }
    assert_eq!(live, vec![small["id"].clone(), big["id"].clone()]);
    drop((sub, u, t));

    // A relay already listening keeps its socket.
    let second = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(&cfg).arg("serve").output().unwrap();
    assert!(!second.status.success());

    // Killed, the relay leaves its socket behind; the next start replaces it.
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(sock.exists());
    let mut child = start();
    let mut u = unix().await;
    send(&mut u, json!(["REQ", "after", {"ids": [big["id"]]}])).await;
    assert_eq!(collect(&mut u, "after").await.0.len(), 1);
    drop(u);
    // Stopped cleanly, it removes it.
    unsafe { libc_kill(child.id() as i32, 15) };
    child.wait().unwrap();
    assert!(!sock.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same event with its signature broken (one hex digit changed).
fn bad_sig(mut ev: Value) -> Value {
    let mut sig = ev["sig"].as_str().unwrap().as_bytes().to_vec();
    sig[10] = if sig[10] == b'0' { b'1' } else { b'0' };
    ev["sig"] = Value::String(String::from_utf8(sig).unwrap());
    ev
}

/// Many EVENTs (and a REQ) in one write, so they reach the relay in one read
/// and their signatures are checked as a batch: every event still gets its
/// own verdict, in order, including bad signatures among good ones, a
/// duplicate, an ephemeral event and a REQ between them.
#[tokio::test]
async fn bursts_of_events_are_verified_together() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-burst-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir, port);
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(31);
    let others: Vec<Signer> = (40..44).map(Signer::new).collect();

    // B listens for the ephemeral kind.
    let mut b = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut b, json!(["REQ", "eph", {"kinds": [21059], "authors": [me.pk()]}])).await;
    collect(&mut b, "eph").await;

    for round in 0..3u64 {
        let mut a = client_connect(relay.addr, &host, "/").await.unwrap();
        // (event, expected OK, expected message prefix)
        let mut burst: Vec<(Value, bool, &str)> = Vec::new();
        for i in 0..40u64 {
            // Mostly one author (merged in the batch), some others.
            let s = if i % 5 == 0 { &others[(i / 5) as usize % others.len()] } else { &me };
            let ev = s.event(now() - i - round * 100, 1059, json!([["p", hex::encode_string(&[i as u8; 32])]]), &format!("burst {round} {i}"));
            if round > 0 && i % 13 == 7 {
                burst.push((bad_sig(ev), false, "invalid: bad signature"));
            } else {
                burst.push((ev, true, ""));
            }
        }
        // A duplicate of the first event and an ephemeral one, mid-burst.
        let dup = burst[0].0.clone();
        burst.insert(20, (dup, true, "duplicate:"));
        burst.insert(25, (me.event(now(), 21059, json!([]), &format!("typing {round}")), true, ""));
        for (ev, _, _) in &burst[..30] {
            a.queue_text(&json!(["EVENT", ev]).to_string());
        }
        a.queue_text(&json!(["REQ", "mid", {"ids": ["00".repeat(32)]}]).to_string());
        for (ev, _, _) in &burst[30..] {
            a.queue_text(&json!(["EVENT", ev]).to_string());
        }
        a.flush().await.unwrap();

        // Refusals are written at once, the REQ's EOSE after everything sent
        // before it; stored events are answered after the sync.
        let mut oks: std::collections::HashMap<String, Vec<(bool, String)>> = std::collections::HashMap::new();
        let mut eose_after_refusals = None;
        let mut refusals_seen = 0;
        while oks.values().map(Vec::len).sum::<usize>() < burst.len() || eose_after_refusals.is_none() {
            let m = recv(&mut a).await;
            match m[0].as_str().unwrap() {
                "OK" => {
                    let accepted = m[2].as_bool().unwrap();
                    if !accepted {
                        refusals_seen += 1;
                    }
                    oks.entry(m[1].as_str().unwrap().to_string()).or_default().push((accepted, m[3].as_str().unwrap().to_string()));
                }
                "EOSE" => eose_after_refusals = Some(refusals_seen),
                _ => {}
            }
        }
        let refused_before_req = burst[..30].iter().filter(|(_, ok, _)| !ok).count();
        assert_eq!(eose_after_refusals, Some(refused_before_req), "round {round}: refusals before the REQ come before its EOSE");
        for (ev, want_ok, want_msg) in &burst {
            let id = ev["id"].as_str().unwrap();
            let got = oks.get(id).unwrap_or_else(|| panic!("round {round}: no OK for {id}"));
            if got.len() == 2 {
                // The duplicated event: the first copy and the duplicate each get an OK true.
                assert!(got.iter().all(|(ok, _)| *ok), "round {round}: {got:?}");
                assert!(got.iter().any(|(_, msg)| msg.starts_with("duplicate:")), "round {round}: {got:?}");
                continue;
            }
            assert_eq!(got.len(), 1, "round {round}: one OK for {id}");
            assert_eq!(got[0].0, *want_ok, "round {round}: verdict for {id}: {:?}", got[0]);
            assert!(got[0].1.starts_with(want_msg), "round {round}: message for {id}: {:?}", got[0]);
        }
        // The ephemeral event reached the listener.
        let live = recv(&mut b).await;
        assert_eq!(live[0], "EVENT");
        assert_eq!(live[2]["content"], format!("typing {round}"));
    }
    // Exactly the good stored events are there.
    let authors: Vec<String> = std::iter::once(me.pk()).chain(others.iter().map(Signer::pk)).collect();
    let stored = ids_over_req(&relay, json!({"kinds": [1059], "authors": authors, "limit": 1000})).await;
    assert_eq!(stored.len(), 40 + 2 * (40 - 3));
    // The clean round went through the batch check; the two with bad
    // signatures each failed a batch and fell back.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let stats: Value = serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert!(stats["sigs_batched"].as_u64().unwrap() >= 30, "{stats}");
    assert!(stats["sig_batches_failed"].as_u64().unwrap() >= 2, "{stats}");
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// The next text message, as sent.
async fn recv_text<S: AsyncRead + AsyncWrite + Unpin>(c: &mut ClientConn<S>) -> String {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), c.recv()).await.expect("timed out waiting for a message").unwrap() {
            Message::Text(t) => return t.to_string(),
            _ => continue,
        }
    }
}

#[tokio::test]
async fn gift_wraps_come_back_byte_for_byte() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let dir = std::env::temp_dir().join(format!("relay-e2e-b64-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let (me, author) = (Signer::new(21), Signer::new(22));

    // Payloads of every padding case (stored decoded), and text that only
    // looks like base64 (stored as it came).
    let bytes = |n: usize| -> Vec<u8> { (0..n).map(|i| (i * 131 + n) as u8).collect() };
    let good = STANDARD.encode(bytes(100));
    let mut contents: Vec<String> = [99, 100, 101, 1400, 1401, 1402, 20_000].iter().map(|&n| STANDARD.encode(bytes(n))).collect();
    contents.extend([
        good.trim_end_matches('=').to_string(),
        format!("{}BB==", &good[..good.len() - 4]),
        format!("{}\n{}", &good[..64], &good[64..]),
        good.replace('+', "-").replace('/', "_"),
        "dGVzdA==".to_string(),
        String::new(),
    ]);
    let mut events: Vec<(String, String)> = Vec::new(); // (what is sent, what must come back)
    for (i, content) in contents.iter().enumerate() {
        let ev = author.event(now() - 100 + i as u64, 1059, json!([["p", me.pk()]]), content);
        // serde_json writes keys sorted and escapes canonically: strfry's form, and ours.
        events.push((json!(["EVENT", ev]).to_string(), ev.to_string()));
    }
    // Signed over "\/": kept exactly as received.
    let escaped = STANDARD.encode([0xFFu8; 120]).replace('/', "\\/");
    let (pk, at) = (author.pk(), now() - 50);
    let pre = format!(r#"[0,"{pk}",{at},1059,[["p","{}"]],"{escaped}"]"#, me.pk());
    let id: [u8; 32] = Sha256::digest(pre.as_bytes()).into();
    let sig = hex::encode_string(&schnorr::sign_no_aux_rand(&id, &author.0).to_byte_array());
    let id = hex::encode_string(&id);
    let raw = format!(r#"{{"content":"{escaped}","created_at":{at},"id":"{id}","kind":1059,"pubkey":"{pk}","sig":"{sig}","tags":[["p","{}"]]}}"#, me.pk());
    events.push((format!(r#"["EVENT",{raw}]"#), raw));

    // Live, as each is stored.
    let mut sub = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut sub, json!(["REQ", "live", {"kinds": [1059], "#p": [me.pk()], "limit": 0}])).await;
    collect(&mut sub, "live").await;
    let mut publisher = client_connect(relay.addr, &host, "/").await.unwrap();
    for (sent, want) in &events {
        publisher.send_text(sent).await.unwrap();
        assert_eq!(ok_of(&mut publisher).await, (true, String::new()));
        assert_eq!(recv_text(&mut sub).await, format!(r#"["EVENT","live",{want}]"#));
    }
    let mut want: Vec<&str> = events.iter().map(|(_, w)| w.as_str()).collect();
    want.sort();

    // Stored: REQ, the operator's query, and after a restart, export and REQ again.
    let req = |c: &'static str| json!(["REQ", c, {"kinds": [1059], "#p": [me.pk()]}]);
    let stored = |frames: Vec<String>, sub: &str| -> Vec<String> {
        let prefix = format!(r#"["EVENT","{sub}","#);
        let mut v: Vec<String> = frames.iter().map(|f| f.strip_prefix(&prefix).and_then(|e| e.strip_suffix(']')).unwrap_or_else(|| panic!("{f}")).to_string()).collect();
        v.sort();
        v
    };
    async fn frames<S: AsyncRead + AsyncWrite + Unpin>(c: &mut ClientConn<S>, n: usize) -> Vec<String> {
        let mut out = Vec::new();
        while out.len() < n {
            let t = recv_text(c).await;
            if t.starts_with(r#"["EVENT""#) {
                out.push(t);
            }
        }
        out
    }
    send(&mut sub, req("hist")).await;
    assert_eq!(stored(frames(&mut sub, events.len()).await, "hist"), want);
    let mut q: Vec<String> = run_ok(&dir, &["query", "--filter", r#"{"kinds":[1059]}"#]).lines().map(String::from).collect();
    q.sort();
    assert_eq!(q, want);
    drop((sub, publisher));
    let dir = relay.stop();
    let mut exported: Vec<String> = run_ok(&dir, &["export"]).lines().map(String::from).collect();
    exported.sort();
    assert_eq!(exported, want);
    let relay = Relay::start(dir, port);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, req("again")).await;
    assert_eq!(stored(frames(&mut c, events.len()).await, "again"), want);

    // A quarter of a payload's size stays off the disk.
    let log = log_bytes(&relay.dir);
    assert!(!log.windows(64).any(|w| w == &contents[3].as_bytes()[..64]), "the 1400-byte payload is not stored as text");
    assert!(log.windows(64).any(|w| w == &bytes(1400)[..64]), "it is stored as its bytes");
    assert!(log.windows(good.len() - 2).any(|w| w == good.trim_end_matches('=').as_bytes()), "the unpadded one is stored as text");
    drop(c);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

async fn stats(relay: &Relay) -> Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {}\r\n\r\n", relay.addr).as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap()
}

/// Found by the adversarial suite's hostile clients: a subscriber that stops
/// reading kept its connection, and everything buffered for it, for as long
/// as it liked. The overflow that should close it was only looked at between
/// writes, and the write to a client that never reads never finishes. It is
/// now dropped once live events pile up past its limit, without it reading.
#[tokio::test]
async fn a_subscriber_that_never_reads_is_dropped() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-noread-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start_limits(dir.clone(), port, "outbound_buffer_bytes = 300000\n", "");
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(21);
    let author = Signer::new(22);
    // A small receive window, so the kernel cannot absorb what the relay
    // sends: the relay's write to it blocks, as it does for a real client
    // that stops reading once its buffers are full.
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.set_recv_buffer_size(4096).unwrap();
    let tcp = sock.connect(relay.addr).await.unwrap();
    let mut sink = relay_net::conn::client_handshake(tcp, &host, "/").await.unwrap();
    send(&mut sink, json!(["REQ", "all", {"kinds": [1059], "#p": [me.pk()], "limit": 0}])).await;
    assert_eq!(collect(&mut sink, "all").await.1[0], "EOSE");
    // From here on the sink reads nothing. First events one at a time, each
    // under its limit, until the kernel's buffers are full and the relay's
    // write to it waits; then a burst past the limit behind that write.
    let mut publisher = client_connect(relay.addr, &host, "/").await.unwrap();
    let body = "w".repeat(30_000);
    for n in 0..200u64 {
        send(&mut publisher, json!(["EVENT", author.event(now() - n, 1059, json!([["p", me.pk()]]), &body)])).await;
        assert!(ok_of(&mut publisher).await.0);
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    for n in 200..240u64 {
        send(&mut publisher, json!(["EVENT", author.event(now() - n, 1059, json!([["p", me.pk()]]), &body)])).await;
    }
    for _ in 200..240 {
        assert!(ok_of(&mut publisher).await.0);
    }
    let t = Instant::now();
    loop {
        if stats(&relay).await["slow_drops"].as_u64().unwrap_or(0) >= 1 {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(10), "the non-reading subscriber is still held: {}", stats(&relay).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop((sink, publisher));
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// Found by the adversarial suite's hostile clients: a REQ's stored results
/// were all built in memory before any went out (50 filters of 5000 events
/// can be hundreds of megabytes, held while the client does not read). They
/// now stop at the connection's outbound limit, with a CLOSED that says why.
#[tokio::test]
async fn an_answer_past_the_outbound_limit_ends_in_closed() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-bigreq-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start_limits(dir.clone(), port, "outbound_buffer_bytes = 300000\n", "");
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(23);
    let author = Signer::new(24);
    let mut publisher = client_connect(relay.addr, &host, "/").await.unwrap();
    let body = "v".repeat(30_000);
    for n in 0..30u64 {
        send(&mut publisher, json!(["EVENT", author.event(now() - n, 1059, json!([["p", me.pk()]]), &body)])).await;
    }
    for _ in 0..30 {
        assert!(ok_of(&mut publisher).await.0);
    }
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["REQ", "big", {"kinds": [1059], "#p": [me.pk()], "limit": 100}])).await;
    let (evs, end) = collect(&mut c, "big").await;
    assert_eq!(end[0], "CLOSED", "{end}");
    assert!(end[2].as_str().unwrap().contains("larger than"), "{end}");
    assert!(evs.len() < 30 && evs.len() >= 9, "{} events before the cut", evs.len());
    // A narrower request is answered whole, and the connection works on.
    send(&mut c, json!(["REQ", "small", {"kinds": [1059], "#p": [me.pk()], "limit": 5}])).await;
    let (evs, end) = collect(&mut c, "small").await;
    assert_eq!((evs.len(), end[0].as_str().unwrap()), (5, "EOSE"));
    drop((c, publisher));
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// Found by the adversarial suite: a REQ needing hundreds of index seeks ran
/// on its reactor, holding every other connection there. Over a cost it is
/// answered by a query worker: the same events, then EOSE, then live ones.
#[tokio::test]
async fn costly_reqs_are_answered_off_the_reactors_in_order() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-costly-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let relay = Relay::start(dir, free_port());
    let host = relay.addr.to_string();
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    let signers: Vec<Signer> = (1..=3).map(Signer::new).collect();
    let to = Signer::new(9).pk();
    let t = now();
    for (k, s) in signers.iter().enumerate() {
        for i in 0..10u64 {
            send(&mut c, json!(["EVENT", s.event(t - 100 - i * 3 - k as u64, 1059, json!([["p", to]]), &format!("wrap {k} {i}"))])).await;
            assert!(ok_of(&mut c).await.0);
        }
    }
    // 1100 authors (1097 with no events) x one kind: 1100 index ranges.
    let mut authors: Vec<String> = signers.iter().map(Signer::pk).collect();
    authors.extend((0..1097u32).map(|n| {
        let mut b = [0x5A; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        hex::encode_string(&b)
    }));
    let ids = |evs: &[Value]| evs.iter().map(|e| e["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    send(&mut c, json!(["REQ", "costly", {"authors": authors, "kinds": [1059]}])).await;
    let (costly, end) = collect(&mut c, "costly").await;
    assert_eq!(end[0], "EOSE");
    send(&mut c, json!(["REQ", "cheap", {"authors": authors[..3], "kinds": [1059]}])).await;
    let (cheap, _) = collect(&mut c, "cheap").await;
    assert_eq!(ids(&costly), ids(&cheap), "the worker's answer is the reactor's, newest first");
    assert_eq!(costly.len(), 30);
    // Live after EOSE, once (each subscription gets its copy).
    let live = signers[0].event(t, 1059, json!([["p", to]]), "live wrap");
    send(&mut c, json!(["EVENT", live])).await;
    let mut got = Vec::new();
    while got.len() < 3 {
        let m = recv(&mut c).await;
        match m[0].as_str() {
            Some("OK") => got.push("ok".to_string()),
            Some("EVENT") => {
                assert_eq!(m[2]["id"], live["id"]);
                got.push(m[1].as_str().unwrap().to_string());
            }
            _ => panic!("unexpected {m}"),
        }
    }
    got.sort();
    assert_eq!(got, ["cheap", "costly", "ok"]);
    assert_eq!(stats(&relay).await["reqs_offloaded"].as_u64(), Some(1));
    // A CLOSE while held, then the same id again: one answer, the second's.
    send(&mut c, json!(["REQ", "again", {"authors": authors, "kinds": [1059]}])).await;
    send(&mut c, json!(["CLOSE", "again"])).await;
    send(&mut c, json!(["REQ", "again", {"authors": authors, "kinds": [1059], "limit": 5}])).await;
    let (evs, end) = collect(&mut c, "again").await;
    assert_eq!((evs.len(), end[0].as_str()), (5, Some("EOSE")));
    send(&mut c, json!(["REQ", "probe", {"ids": [live["id"]]}])).await;
    let (evs, _) = collect(&mut c, "probe").await;
    assert_eq!(evs.len(), 1, "nothing left over from the closed one before this");
    drop(c);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// A reconnect burst of Concord clients: each subscribes to a community's
/// plane keys (1100 authors x 1059 and 21059, past what a reactor answers on
/// the spot) at the same moment, far more than the workers' queue holds.
/// Every one gets its history and EOSE; none is refused.
#[tokio::test]
async fn a_burst_of_concord_subscriptions_is_never_refused() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-concord-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let relay = Relay::start(dir, free_port());
    let host = relay.addr.to_string();
    let plane = Signer::new(31);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    let t = now();
    for i in 0..5u64 {
        send(&mut c, json!(["EVENT", plane.event(t - 10 - i, 1059, json!([]), &format!("stream wrap {i}"))])).await;
        assert!(ok_of(&mut c).await.0);
    }
    let mut authors = vec![plane.pk()];
    authors.extend((0..1099u32).map(|n| {
        let mut b = [0x3C; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        hex::encode_string(&b)
    }));
    let req = json!(["REQ", "plane", {"authors": authors, "kinds": [1059, 21059]}]);
    let mut clients = Vec::new();
    for _ in 0..200 {
        clients.push(client_connect(relay.addr, &host, "/").await.unwrap());
    }
    let tasks: Vec<_> = clients
        .into_iter()
        .map(|mut c| {
            let req = req.clone();
            tokio::spawn(async move {
                send(&mut c, req).await;
                let (evs, end) = collect(&mut c, "plane").await;
                (evs.len(), end[0].as_str().unwrap().to_string(), end.to_string())
            })
        })
        .collect();
    for t in tasks {
        let (n, kind, end) = t.await.unwrap();
        assert_eq!((n, kind.as_str()), (5, "EOSE"), "{end}");
    }
    let st = stats(&relay).await;
    eprintln!("offloaded {}, answered on a reactor for a full queue {}", st["reqs_offloaded"], st["reqs_inline_fallback"]);
    // The live subscription Concord keeps open asks for no history: however
    // many plane keys it names, it costs nothing and is answered on the spot.
    let before = st["reqs_offloaded"].as_u64().unwrap();
    send(&mut c, json!(["REQ", "live", {"authors": authors, "kinds": [1059, 21059], "since": t - 300, "limit": 0}])).await;
    let (evs, end) = collect(&mut c, "live").await;
    assert_eq!((evs.len(), end[0].as_str()), (0, Some("EOSE")));
    assert_eq!(stats(&relay).await["reqs_offloaded"].as_u64(), Some(before));
    drop(c);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// Loopback is never one client: everyone through Tor or I2P arrives as
/// 127.0.0.1 (the onion services connect from it), and so do a push server
/// and the operator's tools. Per-IP limits leave it alone; the one-address
/// limits still apply to every other address (see tls.rs for the header).
#[tokio::test]
async fn loopback_is_not_held_to_per_address_limits() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-loopback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let cfg = dir.join("relay.toml");
    std::fs::write(
        &cfg,
        format!(
            "[relay]\nbind = \"127.0.0.1:{port}\"\nthreads = 2\n[limits]\nmax_connections_per_ip = 1\nevents_per_minute_per_ip = 2\n[store]\ndata = \"{}\"\n",
            dir.join("data").display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let t = Instant::now();
    while std::net::TcpStream::connect(addr).is_err() {
        assert!(t.elapsed() < Duration::from_secs(10), "relay did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    let host = addr.to_string();
    // Three connections against a limit of one, each answering.
    let mut conns = Vec::new();
    for i in 0..3 {
        let mut c = client_connect(addr, &host, "/").await.unwrap();
        send(&mut c, json!(["REQ", format!("s{i}"), {"kinds": [30078], "limit": 1}])).await;
        assert_eq!(collect(&mut c, &format!("s{i}")).await.1[0], "EOSE", "connection {i} was turned away");
        conns.push(c);
    }
    // Five events against two a minute, all taken.
    let me = Signer::new(52);
    let c = &mut conns[0];
    for i in 0..5u64 {
        send(c, json!(["EVENT", me.event(now() - i, 30078, json!([["d", format!("k{i}")]]), "x")])).await;
        let (ok, msg) = ok_of(c).await;
        assert!(ok, "event {i}: {msg}");
    }
    drop(conns);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(dir);
}

/// A banned key's events, and gift wraps addressed to it, are answered OK like
/// anyone's and never stored; asking for it finds nothing; everyone else is
/// untouched; and editing the file takes effect without a restart.
#[tokio::test]
async fn a_banned_key_is_answered_ok_and_never_stored() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-bans-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (banned, friend, other) = (Signer::new(61), Signer::new(62), Signer::new(63));
    let list = dir.join("banlist");
    std::fs::write(&list, format!("# spam\n{}\n", banned.pk())).unwrap();
    let port = free_port();
    let relay = Relay::start_with(dir.clone(), port, &format!("[policy]\nbanlist = \"{}\"\n", list.display()));
    let host = relay.addr.to_string();
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();

    // Live: a subscription for the banned key's inbox ends at once and stays quiet.
    send(&mut c, json!(["REQ", "theirs", {"kinds": [1059], "#p": [banned.pk()], "limit": 0}])).await;
    assert_eq!(collect(&mut c, "theirs").await.1[0], "EOSE");

    let profile = banned.event(now(), 0, json!([]), "{}");
    let typing = banned.event(now(), 21059, json!([]), "x");
    let to_banned = friend.event(now() - 3600, 1059, json!([["p", banned.pk()]]), "ciphertext");
    let to_other = friend.event(now() - 3600, 1059, json!([["p", other.pk()]]), "ciphertext");
    for ev in [&profile, &typing, &to_banned, &to_other] {
        send(&mut c, json!(["EVENT", ev])).await;
        assert_eq!(ok_of(&mut c).await, (true, String::new()), "{}", ev["kind"]);
    }
    // A forgery is still refused as one: the ban answers nothing early.
    send(&mut c, json!(["EVENT", bad_sig(banned.event(now(), 0, json!([]), "{}"))])).await;
    assert_eq!(ok_of(&mut c).await, (false, "invalid: bad signature".into()));

    let found = |f: Value| ids_over_req(&relay, f);
    assert!(found(json!({"authors": [banned.pk()]})).await.is_empty());
    assert!(found(json!({"kinds": [1059], "#p": [banned.pk()]})).await.is_empty());
    assert!(found(json!({"ids": [profile["id"], to_banned["id"]]})).await.is_empty());
    assert_eq!(found(json!({"kinds": [1059], "#p": [banned.pk(), other.pk()]})).await, [to_other["id"].as_str().unwrap()]);
    send(&mut c, json!(["COUNT", "n", {"kinds": [1059], "#p": [banned.pk()]}])).await;
    assert_eq!(recv(&mut c).await[2]["count"], 0);
    // The operator sees every stored event: none of the banned ones are there.
    let stored = ids_printed(&run_ok(&dir, &["query", "--filter", "{}"]));
    assert_eq!(stored, [to_other["id"].as_str().unwrap()]);

    // Lifted by editing the file, with the relay running.
    std::fs::write(&list, "# nobody\n").unwrap();
    let t = Instant::now();
    loop {
        let ev = banned.event(now(), 30078, json!([["d", format!("t{}", t.elapsed().as_millis())]]), "back");
        send(&mut c, json!(["EVENT", ev])).await;
        assert!(ok_of(&mut c).await.0);
        if found(json!({"ids": [ev["id"]]})).await.len() == 1 {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(15), "the lifted ban was not picked up");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    drop(c);
    relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// An allowlisted key publishes kinds the policy refuses (not a denied one),
/// anyone reads them, and both lists change from the command line while the
/// relay runs: allowed, then banned (the ban wins), then off both again.
#[tokio::test]
async fn an_allowlisted_key_publishes_any_kind_and_both_lists_change_live() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-allow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (team, other) = (Signer::new(71), Signer::new(72));
    let (allow, ban) = (dir.join("allowlist"), dir.join("banlist"));
    std::fs::write(&allow, "# our own accounts\n").unwrap();
    std::fs::write(&ban, "").unwrap();
    let policy = format!("[policy]\nallowlist = \"{}\"\nbanlist = \"{}\"\ndeny_kinds = [9735]\n", allow.display(), ban.display());
    let relay = Relay::start_with(dir.clone(), free_port(), &policy);
    let host = relay.addr.to_string();
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    let refused = |kind: u64| (false, format!("blocked: kind {kind} is not accepted by this relay"));

    // Not yet listed: a public note is refused like anyone's.
    send(&mut c, json!(["EVENT", team.event(now(), 1, json!([]), "early")])).await;
    assert_eq!(ok_of(&mut c).await, refused(1));

    let out = run_ok(&dir, &["allowlist", "add", &team.pk(), "--note", "the official account"]);
    assert!(out.contains("added to the allowlist"), "{out}");
    assert!(run_ok(&dir, &["allowlist", "add", &team.pk()]).contains("already on the allowlist"));
    assert!(run_ok(&dir, &["allowlist"]).contains("the official account"));

    // Picked up while the relay runs.
    let t = Instant::now();
    let note = loop {
        let ev = team.event(now(), 1, json!([]), &format!("hello {}", t.elapsed().as_millis()));
        send(&mut c, json!(["EVENT", ev])).await;
        if ok_of(&mut c).await.0 {
            break ev;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "the allowlist was not picked up");
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let article = team.event(now(), 30023, json!([["d", "launch"], ["title", "Vector"]]), "# An article");
    send(&mut c, json!(["EVENT", article])).await;
    assert_eq!(ok_of(&mut c).await, (true, String::new()));
    // deny_kinds still refuses, and nobody else gets in.
    send(&mut c, json!(["EVENT", team.event(now(), 9735, json!([]), "")])).await;
    assert_eq!(ok_of(&mut c).await, refused(9735));
    send(&mut c, json!(["EVENT", other.event(now(), 1, json!([]), "me too")])).await;
    assert_eq!(ok_of(&mut c).await, refused(1));
    // Anyone reads them.
    let mut got = ids_over_req(&relay, json!({"authors": [team.pk()]})).await;
    got.sort();
    let mut want = vec![note["id"].as_str().unwrap().to_string(), article["id"].as_str().unwrap().to_string()];
    want.sort();
    assert_eq!(got, want);

    // Banned too: the ban wins (answered OK, never stored).
    assert!(run_ok(&dir, &["banlist", "add", &team.pk()]).contains("added to the banlist"));
    assert!(run_ok(&dir, &["allowlist", "add", &team.pk()]).contains("already on the allowlist"));
    let t = Instant::now();
    loop {
        let ev = team.event(now(), 1, json!([]), &format!("muted {}", t.elapsed().as_millis()));
        send(&mut c, json!(["EVENT", ev])).await;
        assert!(ok_of(&mut c).await.0);
        if ids_over_req(&relay, json!({"ids": [ev["id"]]})).await.is_empty() {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "the ban was not picked up");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Off both lists: refused again, like anyone's note.
    assert!(run_ok(&dir, &["banlist", "remove", &team.pk()]).contains("removed from the banlist"));
    assert!(run_ok(&dir, &["allowlist", "remove", &team.pk()]).contains("removed from the allowlist"));
    assert!(run_ok(&dir, &["allowlist", "remove", &team.pk()]).contains("is not on the allowlist"));
    let t = Instant::now();
    loop {
        send(&mut c, json!(["EVENT", team.event(now(), 1, json!([]), &format!("bye {}", t.elapsed().as_millis()))])).await;
        if ok_of(&mut c).await == refused(1) {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "the removal was not picked up");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    run_refused(&dir, &["allowlist", "add", "npub1nope"], "is not an npub");
    run_refused(&dir, &["allowlist", "frob"], "takes list, add or remove");
    drop(c);
    relay.stop();

    // A relay with no allowlist set says so.
    let bare = dir.join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::write(bare.join("relay.toml"), "").unwrap();
    run_refused(&bare, &["allowlist", "add", &team.pk()], "no allowlist is set");
    let _ = std::fs::remove_dir_all(dir);
}

/// A relay behind a pretend web server: it takes each connection's address
/// from X-Forwarded-For, so a test can speak from many addresses.
fn start_forwarded(dir: PathBuf, port: u16, sections: &str) -> Relay {
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("relay.toml");
    std::fs::write(
        &cfg,
        format!(
            "[relay]\nbind = \"127.0.0.1:{port}\"\nthreads = 2\nreal_ip_header = \"x-forwarded-for\"\n{sections}\n[store]\ndata = \"{}\"\n",
            dir.join("data").display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let t = Instant::now();
    while std::net::TcpStream::connect(addr).is_err() {
        assert!(t.elapsed() < Duration::from_secs(10), "relay did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Relay { child, addr, dir }
}

/// A WebSocket opened by hand, to send headers the client API does not (the
/// address a web server names, a user agent). Frames are masked with zeros.
struct RawWs {
    s: tokio::net::TcpStream,
    buf: Vec<u8>,
}

/// The status and head of the answer to an upgrade, and the socket when it was upgraded.
async fn raw_upgrade(addr: SocketAddr, headers: &str) -> (u16, String, Option<RawWs>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{headers}\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed before answering: {}", String::from_utf8_lossy(&buf));
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
    let rest = buf[end..].to_vec();
    (status, head, (status == 101).then_some(RawWs { s, buf: rest }))
}

impl RawWs {
    async fn send(&mut self, v: Value) {
        use tokio::io::AsyncWriteExt;
        let text = v.to_string();
        let mut f = vec![0x81];
        match text.len() {
            n if n < 126 => f.push(0x80 | n as u8),
            n => {
                f.push(0x80 | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
        }
        f.extend_from_slice(&[0, 0, 0, 0]);
        f.extend_from_slice(text.as_bytes());
        self.s.write_all(&f).await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        use tokio::io::AsyncReadExt;
        loop {
            if self.buf.len() >= 2 {
                let (op, len0) = (self.buf[0] & 0x0F, (self.buf[1] & 0x7F) as usize);
                let (hdr, len) = match len0 {
                    126 if self.buf.len() >= 4 => (4, u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize),
                    127 if self.buf.len() >= 10 => (10, u64::from_be_bytes(self.buf[2..10].try_into().unwrap()) as usize),
                    126 | 127 => (usize::MAX, 0),
                    n => (2, n),
                };
                if hdr != usize::MAX && self.buf.len() >= hdr + len {
                    let payload: Vec<u8> = self.buf.drain(..hdr + len).skip(hdr).collect();
                    if op == 1 {
                        return serde_json::from_slice(&payload).unwrap();
                    }
                    continue;
                }
            }
            let mut chunk = [0u8; 65536];
            let n = tokio::time::timeout(Duration::from_secs(5), self.s.read(&mut chunk)).await.expect("timed out waiting for a frame").unwrap();
            assert!(n > 0, "connection closed");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// The next message of one of `kinds` (OK, EOSE, CLOSED, ...).
    async fn next_of(&mut self, kinds: &[&str]) -> Value {
        loop {
            let m = self.recv().await;
            if kinds.contains(&m[0].as_str().unwrap()) {
                return m;
            }
        }
    }
}

/// An address that opens connections faster than its allowance is answered
/// 429 before the upgrade; other addresses are not; and reconnecting does not
/// refill the address's EVENT allowance.
#[tokio::test]
async fn an_address_past_its_connection_allowance_gets_429() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-connrate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = start_forwarded(dir.clone(), port, "[limits]\nconnections_per_minute_per_ip = 1\nconnection_burst_per_ip = 3\nevents_per_minute_per_ip = 2\n");
    let from = |ip: &str| format!("X-Forwarded-For: {ip}\r\n");

    for i in 0..3 {
        let (status, head, _) = raw_upgrade(relay.addr, &from("203.0.113.5")).await;
        assert_eq!(status, 101, "connection {i}: {head}");
    }
    let (status, head, _) = raw_upgrade(relay.addr, &from("203.0.113.5")).await;
    assert_eq!(status, 429, "{head}");
    assert!(head.contains("Retry-After: "), "{head}");
    assert_eq!(raw_upgrade(relay.addr, &from("203.0.113.6")).await.0, 101);

    // Two EVENTs a minute: spent on one connection, still spent on the next.
    let me = Signer::new(70);
    let (_, _, ws) = raw_upgrade(relay.addr, &from("203.0.113.7")).await;
    let mut ws = ws.unwrap();
    for i in 0..2 {
        ws.send(json!(["EVENT", me.event(now() - i, 30078, json!([["d", format!("k{i}")]]), "x")])).await;
        assert_eq!(ws.next_of(&["OK"]).await[2], true);
    }
    drop(ws);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (_, _, ws) = raw_upgrade(relay.addr, &from("203.0.113.7")).await;
    let mut ws = ws.unwrap();
    ws.send(json!(["EVENT", me.event(now(), 30078, json!([["d", "k2"]]), "x")])).await;
    let ok = ws.next_of(&["OK"]).await;
    assert_eq!((ok[2].as_bool(), ok[3].as_str().unwrap().starts_with("rate-limited:")), (Some(false), true), "{ok}");

    let s = stats(&relay).await;
    assert_eq!((s["connections_rate_limited"].as_u64(), s["events_refused_rate"].as_u64()), (Some(1), Some(1)), "{s}");
    // The operator sees whom it turned away.
    let out = run_ok(&dir, &["top", "--by", "refused"]);
    let line = out.lines().find(|l| l.starts_with("203.0.113.5 ")).unwrap_or_else(|| panic!("{out}"));
    assert_eq!(line.split_whitespace().nth(8), Some("1"), "{out}");
    drop(ws);
    relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// `top` names each address with its app, what it asked for (kinds and
/// counts, never keys) and what was refused; /stats says why things were.
#[tokio::test]
async fn top_shows_each_address_and_what_it_asked_for() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-top-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = start_forwarded(dir.clone(), port, "");
    let me = Signer::new(71);

    let (_, _, ws) = raw_upgrade(relay.addr, "X-Forwarded-For: 203.0.113.20\r\nUser-Agent: scraper/1\r\n").await;
    let mut scraper = ws.unwrap();
    scraper.send(json!(["REQ", "all", {"kinds": [1059], "limit": 10}])).await;
    let c = scraper.next_of(&["CLOSED", "EOSE"]).await;
    assert_eq!(c[0], "CLOSED", "{c}");
    scraper.send(json!(["EVENT", me.event(now(), 1, json!([]), "a note")])).await;
    assert_eq!(scraper.next_of(&["OK"]).await[2], false);

    let (_, _, ws) = raw_upgrade(relay.addr, "X-Forwarded-For: 203.0.113.21\r\nUser-Agent: reader/2\r\n").await;
    let mut reader = ws.unwrap();
    reader.send(json!(["REQ", "p", {"kinds": [0], "authors": [me.pk()], "limit": 1}])).await;
    assert_eq!(reader.next_of(&["EOSE"]).await[0], "EOSE");
    drop(reader);

    let t = Instant::now();
    let out = loop {
        let out = run_ok(&dir, &["top", "--by", "conns"]);
        if out.contains("reader/2") {
            break out;
        }
        assert!(t.elapsed() < Duration::from_secs(5), "{out}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let line = |ip: &str| out.lines().find(|l| l.starts_with(ip)).unwrap_or_else(|| panic!("no {ip} in\n{out}")).to_string();
    let (s, r) = (line("203.0.113.20"), line("203.0.113.21"));
    assert!(s.contains("scraper/1") && s.contains("kinds 1059 · limit 10"), "{s}");
    let cols: Vec<&str> = s.split_whitespace().collect();
    // address, conns, open, avg s, reqs, events, refused, scrapes
    assert_eq!(&cols[1..8], ["1", "1", "0", "1", "1", "1", "1"], "{s}");
    assert!(r.contains("reader/2") && r.contains("kinds 0 · authors×1 · limit 1") && !r.contains(&me.pk()), "{r}");
    assert!(out.lines().next().unwrap().contains("1 gift-wrap scrapes refused"), "{out}");
    run_refused(&dir, &["top", "--by", "nope"], "--by is one of");

    let st = stats(&relay).await;
    assert_eq!((st["reqs_refused_wraps"].as_u64(), st["events_refused_kind"].as_u64()), (Some(1), Some(1)), "{st}");
    drop(scraper);
    relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// `heavy` keeps a REQ that sent a lot and the burst it made, with who asked
/// and the request's shape (never a key); /stats counts both.
#[tokio::test]
async fn heavy_keeps_a_big_answer_and_its_burst() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-heavy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = start_forwarded(dir.clone(), port, "");
    let me = Signer::new(72);

    // 50 events of 60 KB: 3 MB, more than a heavy answer's 2 MB, and in well
    // under a second, more than a burst's 2 MB/s.
    let (_, _, ws) = raw_upgrade(relay.addr, "X-Forwarded-For: 203.0.113.30\r\nUser-Agent: writer/1\r\n").await;
    let mut writer = ws.unwrap();
    let body = "x".repeat(60_000);
    for i in 0..50 {
        writer.send(json!(["EVENT", me.event(now() - i, 30078, json!([["d", format!("big{i}")]]), &body)])).await;
        let ok = writer.next_of(&["OK"]).await;
        assert_eq!(ok[2], true, "{ok}");
    }
    let (_, _, ws) = raw_upgrade(relay.addr, "X-Forwarded-For: 203.0.113.31\r\nUser-Agent: reader/3\r\n").await;
    let mut reader = ws.unwrap();
    reader.send(json!(["REQ", "all", {"kinds": [30078], "authors": [me.pk()], "limit": 100}])).await;
    assert_eq!(reader.next_of(&["EOSE"]).await[0], "EOSE");
    // Closing ends the burst, whether or not its reactor has looked yet.
    drop(reader);

    let t = Instant::now();
    let out = loop {
        let out = run_ok(&dir, &["heavy", "--by", "bytes"]);
        if out.contains(" burst ") && out.contains(" REQ ") {
            break out;
        }
        assert!(t.elapsed() < Duration::from_secs(5), "{out}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let row = |what: &str| out.lines().find(|l| l.contains(what)).unwrap_or_else(|| panic!("no {what} in\n{out}")).to_string();
    let (req, burst) = (row(" REQ "), row(" burst "));
    assert!(req.contains("203.0.113.31") && req.contains(" reactor ") && req.contains("50 ev"), "{req}");
    assert!(req.contains("reader/3") && req.contains("kinds 30078 · authors×1 · limit 100") && !req.contains(&me.pk()), "{req}");
    assert!(burst.contains("203.0.113.31") && burst.contains("1 REQ") && burst.contains("reader/3"), "{burst}");
    assert!(!out.contains("203.0.113.30"), "the writer took little out:\n{out}");
    assert!(out.lines().next().unwrap().starts_with("last 60 min: 1 REQ, 0 COUNT, 0 NEG-OPEN heavy"), "{out}");
    run_refused(&dir, &["heavy", "--by", "nope"], "--by is one of");

    let st = stats(&relay).await;
    assert_eq!((st["requests_heavy"].as_u64(), st["bursts"].as_u64()), (Some(1), Some(1)), "{st}");
    drop(writer);
    relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// Reconciles the set `held` against what the relay holds for `filter`, as
/// Vector's client does. The ids only the client has, those only the relay
/// has, and any message for another id that came meanwhile.
async fn reconcile<S: AsyncRead + AsyncWrite + Unpin>(c: &mut ClientConn<S>, sub: &str, filter: &Value, held: &[(u64, [u8; 32])]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>, Vec<Value>) {
    use negentropy::{Id, Negentropy, NegentropyStorageVector};
    let mut st = NegentropyStorageVector::with_capacity(held.len());
    for (t, id) in held {
        st.insert(*t, Id::from_byte_array(*id)).unwrap();
    }
    st.seal().unwrap();
    let mut neg = Negentropy::owned(st, 60_000).unwrap();
    let init = neg.initiate().unwrap();
    send(c, json!(["NEG-OPEN", sub, filter, hex::encode_string(&init)])).await;
    let (mut have, mut need, mut others) = (Vec::new(), Vec::new(), Vec::new());
    loop {
        let m = recv(c).await;
        if m[1] != sub {
            others.push(m);
            continue;
        }
        assert_eq!(m[0], "NEG-MSG", "{m}");
        let bytes = hex::decode_any_case(m[2].as_str().unwrap().as_bytes()).unwrap();
        match neg.reconcile_with_ids(&bytes, &mut have, &mut need).unwrap() {
            Some(next) => send(c, json!(["NEG-MSG", sub, hex::encode_string(&next)])).await,
            None => break,
        }
    }
    send(c, json!(["NEG-CLOSE", sub])).await;
    let ids = |v: Vec<negentropy::Id>| {
        let mut v: Vec<[u8; 32]> = v.iter().map(|i| *i.as_bytes()).collect();
        v.sort_unstable();
        v
    };
    (ids(have), ids(need), others)
}

/// A trusted peer's pass reconciles windows of 100 000 to 500 000 records,
/// which held every other connection on a reactor while the set was built.
/// Sets that size are built by the query workers and reconcile exactly; one
/// closed, or written to, before its answer comes gets no answer; and every
/// set's records go back to the budget.
#[tokio::test]
async fn peer_sized_reconciles_are_built_off_the_reactors() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-neg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let secret = "e2e-peer-secret-0123456789abcdef";
    let sections = format!("[policy]\nkinds = \"all\"\n[[peer]]\nname = \"twin\"\nsecret = \"{secret}\"\nips = [\"127.0.0.1\"]\n");
    relay_stop_quietly(start_forwarded(dir.clone(), port, &sections));
    // 160 000 events, one a second, every tenth a gift wrap: loaded unsigned.
    const T: u64 = 1_700_000_000;
    let id = |b: u8, n: u64| {
        let mut v = [b; 32];
        v[..8].copy_from_slice(&n.to_le_bytes());
        v
    };
    let to = hex::encode_string(&id(0xB1, 0));
    let mut lines = String::new();
    for n in 0..160_000u64 {
        let (kind, tags) = if n % 10 == 0 { (1059, format!(r#"[["p","{to}"]]"#)) } else { (1, "[]".to_string()) };
        lines.push_str(&format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":{},"kind":{kind},"tags":{tags},"content":"n","sig":"{}"}}"#,
            hex::encode_string(&id(0xEE, n)),
            hex::encode_string(&id(0xC0, n % 500)),
            T + n,
            "00".repeat(64)
        ));
        lines.push('\n');
    }
    let file = dir.join("events.jsonl");
    std::fs::write(&file, lines).unwrap();
    run_ok(&dir, &["import", "--no-verify", file.to_str().unwrap()]);
    let relay = start_forwarded(dir.clone(), port, &sections);
    let host = relay.addr.to_string();

    // A window as a peer's pass asks for it: 150 000 records, 15 000 of them wraps.
    let window = json!({"since": T + 5_000, "until": T + 154_999});
    let in_window = (5_000..155_000u64).map(|n| (n, (T + n, id(0xEE, n))));
    let first = {
        use negentropy::{Negentropy, NegentropyStorageVector};
        let mut st = NegentropyStorageVector::new();
        st.seal().unwrap();
        hex::encode_string(&Negentropy::owned(st, 60_000).unwrap().initiate().unwrap())
    };
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    // Closed before the answer; written to before the answer: neither is answered later.
    send(&mut c, json!(["NEG-OPEN", "x", window, first])).await;
    send(&mut c, json!(["NEG-CLOSE", "x"])).await;
    send(&mut c, json!(["NEG-OPEN", "z", window, first])).await;
    send(&mut c, json!(["NEG-MSG", "z", first])).await;
    assert_eq!(recv(&mut c).await, json!(["NEG-ERR", "z", "closed: NEG-MSG before the answer to its NEG-OPEN"]));
    // A mailbox is answered on the spot, ahead of the big ones.
    send(&mut c, json!(["NEG-OPEN", "small", {"kinds": [1059], "#p": [to], "until": T + 9_999}, first])).await;
    let m = recv(&mut c).await;
    assert_eq!((m[0].as_str(), m[1].as_str()), (Some("NEG-MSG"), Some("small")), "{m}");
    send(&mut c, json!(["NEG-CLOSE", "small"])).await;
    // A client's broad window leaves the wraps out, built on a worker as on a reactor.
    let plain: Vec<(u64, [u8; 32])> = in_window.clone().filter(|(n, _)| n % 10 != 0).map(|(_, item)| item).collect();
    let (have, need, others) = reconcile(&mut c, "plain", &window, &plain).await;
    assert_eq!((have.len(), need.len()), (0, 0));
    assert!(others.is_empty(), "nothing for x or z: {others:?}");

    // The peer holds 90% of the window and five records the relay has not seen.
    let mut p = client_connect(relay.addr, &host, &format!("/peer/{secret}")).await.unwrap();
    let mut held: Vec<(u64, [u8; 32])> = in_window.clone().filter(|(n, _)| n % 10 != 3).map(|(_, item)| item).collect();
    let extra: Vec<[u8; 32]> = (0..5).map(|n| id(0xAB, n)).collect();
    held.extend(extra.iter().enumerate().map(|(i, x)| (T + 6_000 + i as u64, *x)));
    let (have, need, _) = reconcile(&mut p, "pass", &window, &held).await;
    let mut missing: Vec<[u8; 32]> = in_window.filter(|(n, _)| n % 10 == 3).map(|(_, (_, x))| x).collect();
    missing.sort_unstable();
    assert_eq!(have, extra);
    assert_eq!(need.len(), 15_000);
    assert!(need == missing, "exactly the records the peer lacks");

    // Each was kept as a worker's: its wait and run apart, its records, its shape.
    let out = run_ok(&dir, &["heavy", "--by", "events"]);
    let row = out.lines().find(|l| l.contains("150000 rec")).unwrap_or_else(|| panic!("no peer pass in\n{out}"));
    assert!(row.contains(" NEG-OPEN ") && row.contains(" worker ") && row.contains("any kind · since · until"), "{row}");
    assert!(out.lines().any(|l| l.contains("135000 rec") && l.contains(" worker ")), "{out}");

    let t = Instant::now();
    loop {
        let st = stats(&relay).await;
        assert_eq!(st["negs_offloaded"].as_u64(), Some(4), "x, z, plain and the pass; not the mailbox: {st}");
        if st["neg_items_held"] == 0 {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(5), "every set gives its records back: {st}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop((c, p));
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

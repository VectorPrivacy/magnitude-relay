//! HTTPS end to end: the real binary, certificates from an in-process ACME CA (or
//! from files), and wss:// clients that verify what they are given.

use relay_net::conn::{client_connect, client_handshake, ClientConn, Message};
use relay_proto::hex;
use relay_tls::mock::{MockCa, Settings};
use relay_tls::x509::{self, CertInfo, CertSpec, EcKey};
use relay_tls::{pem, time};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use secp256k1::{schnorr, Keypair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const DAY: i64 = 86_400;

/// A port nothing listens on, found by a socket that never listens (see
/// `free_port` in e2e.rs).
fn free_port() -> u16 {
    let s = tokio::net::TcpSocket::new_v4().unwrap();
    s.set_reuseaddr(true).unwrap();
    s.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    s.local_addr().unwrap().port()
}

struct Relay {
    child: Child,
    dir: PathBuf,
    plain: SocketAddr,
    https: SocketAddr,
    http: SocketAddr,
}

impl Relay {
    fn config_path(&self) -> PathBuf {
        self.dir.join("relay.toml")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("relay.log")).unwrap_or_default()
    }

    /// Stops it with SIGTERM, the graceful way.
    fn stop(mut self) {
        unsafe { libc_kill(self.child.id() as i32, 15) };
        let t = Instant::now();
        while self.child.try_wait().unwrap().is_none() {
            assert!(t.elapsed() < Duration::from_secs(10), "relay did not stop on SIGTERM");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
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

/// Writes `relay.toml` for a relay with its plain listener and the `[tls]` lines
/// given, and starts it.
fn start(dir: &Path, ports: (u16, u16, u16), extra: &str, limits: &str, tls: &str, env: &[(&str, &str)]) -> Relay {
    std::fs::create_dir_all(dir).unwrap();
    let (plain, https, http) = ports;
    let cfg = dir.join("relay.toml");
    std::fs::write(
        &cfg,
        format!(
            "[relay]\nbind = \"127.0.0.1:{plain}\"\nthreads = 2\n{extra}\n[limits]\nevents_per_minute_per_ip = 0\n{limits}\n[store]\ndata = \"{}\"\n[tls]\nenabled = true\nhttps_bind = \"127.0.0.1:{https}\"\nhttp_bind = \"127.0.0.1:{http}\"\n{tls}",
            dir.join("data").display()
        ),
    )
    .unwrap();
    let log = std::fs::File::create(dir.join("relay.log")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_magnitude-relay"));
    cmd.arg("--config").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::from(log));
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().unwrap();
    let plain_addr: SocketAddr = format!("127.0.0.1:{plain}").parse().unwrap();
    let t = Instant::now();
    while std::net::TcpStream::connect(plain_addr).is_err() {
        assert!(t.elapsed() < Duration::from_secs(10), "relay did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Relay {
        child,
        dir: dir.to_path_buf(),
        plain: plain_addr,
        https: format!("127.0.0.1:{https}").parse().unwrap(),
        http: format!("127.0.0.1:{http}").parse().unwrap(),
    }
}

/// Folders made by the test running on this thread, removed when the thread ends.
struct Folders(Vec<PathBuf>);

impl Drop for Folders {
    fn drop(&mut self) {
        for d in &self.0 {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

thread_local! {
    static FOLDERS: std::cell::RefCell<Folders> = const { std::cell::RefCell::new(Folders(Vec::new())) };
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("relay-tls-e2e-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    FOLDERS.with(|f| f.borrow_mut().0.push(d.clone()));
    d
}

fn client_config(roots: &[Vec<u8>]) -> Arc<ClientConfig> {
    let mut store = RootCertStore::empty();
    for r in roots {
        store.add(CertificateDer::from(r.clone())).unwrap();
    }
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(store)
            .with_no_client_auth(),
    )
}

/// TLS to `addr` as `name`, verifying against `roots`: the stream and the certificate seen.
async fn tls_connect(addr: SocketAddr, name: &str, roots: &[Vec<u8>]) -> io::Result<(TlsStream<TcpStream>, CertInfo)> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let tls = TlsConnector::from(client_config(roots)).connect(ServerName::try_from(name.to_string()).unwrap(), tcp).await?;
    let leaf = x509::parse_certificate(tls.get_ref().1.peer_certificates().unwrap().first().unwrap()).unwrap();
    Ok((tls, leaf))
}

/// A secure WebSocket: TLS, then the upgrade.
async fn wss(addr: SocketAddr, name: &str, roots: &[Vec<u8>]) -> io::Result<(ClientConn<TlsStream<TcpStream>>, CertInfo)> {
    let (tls, leaf) = tls_connect(addr, name, roots).await?;
    Ok((client_handshake(tls, name, "/").await?, leaf))
}

/// Retries `f` until it gives something, for up to `secs` seconds.
async fn until<T, F, Fut>(what: &str, secs: u64, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let start = Instant::now();
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(start.elapsed() < Duration::from_secs(secs), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct Signer(Keypair);

impl Signer {
    fn new(seed: u8) -> Signer {
        Signer(Keypair::from_secret_bytes([seed; 32]).unwrap())
    }

    fn pk(&self) -> String {
        hex::encode_string(&self.0.x_only_public_key().0.to_byte_array())
    }

    fn event(&self, created_at: u64, kind: u64, content: &str) -> Value {
        let pk = self.pk();
        let pre = serde_json::to_string(&json!([0, pk, created_at, kind, [], content])).unwrap();
        let id: [u8; 32] = Sha256::digest(pre.as_bytes()).into();
        let sig = schnorr::sign_no_aux_rand(&id, &self.0);
        json!({"id": hex::encode_string(&id), "pubkey": pk, "created_at": created_at, "kind": kind, "tags": [], "content": content, "sig": hex::encode_string(&sig.to_byte_array())})
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

async fn recv<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(c: &mut ClientConn<S>) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), c.recv()).await.expect("timed out waiting for a message").unwrap() {
            Message::Text(t) => return serde_json::from_str(&t).unwrap(),
            _ => continue,
        }
    }
}

/// Publishes a profile and reads it back, over whatever stream `c` is.
async fn publish_and_read<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(c: &mut ClientConn<S>, signer: &Signer, content: &str) {
    let ev = signer.event(now(), 0, content);
    c.send_text(&json!(["EVENT", ev]).to_string()).await.unwrap();
    let ok = recv(c).await;
    assert_eq!(ok[0], "OK", "{ok}");
    assert_eq!(ok[2], true, "{ok}");
    read_back(c, signer, content).await;
}

async fn read_back<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(c: &mut ClientConn<S>, signer: &Signer, content: &str) {
    c.send_text(&json!(["REQ", "s", {"authors": [signer.pk()], "kinds": [0], "limit": 1}]).to_string()).await.unwrap();
    let first = recv(c).await;
    assert_eq!((first[0].as_str(), first[1].as_str()), (Some("EVENT"), Some("s")), "{first}");
    assert_eq!(first[2]["content"], content);
    assert_eq!(recv(c).await[0], "EOSE");
    c.send_text(&json!(["CLOSE", "s"]).to_string()).await.unwrap();
}

#[tokio::test]
async fn an_acme_certificate_is_obtained_served_and_renewed_without_a_restart() {
    let dir = temp_dir("acme");
    let ports = (free_port(), free_port(), free_port());
    // Certificates last eight seconds, so the renewal (at two thirds) happens within the test.
    let ca = MockCa::start(Settings {
        https_target: Some(format!("127.0.0.1:{}", ports.1).parse().unwrap()),
        http_target: Some(format!("127.0.0.1:{}", ports.2).parse().unwrap()),
        lifetime: 8,
        tls: false,
    })
    .await;
    let tls = format!("domains = [\"relay.test\"]\nemail = \"ops@relay.test\"\ndirectory = \"{}\"\n", ca.directory());
    let mut relay = start(&dir, ports, "", "", &tls, &[]);
    let root = ca.root_der();

    // Nothing is listening for HTTPS with a certificate yet; the relay is up on plain ws://.
    let (mut c, first) = until("the first certificate to be served", 30, || async {
        wss(relay.https, "relay.test", std::slice::from_ref(&root)).await.ok()
    })
    .await;
    assert_eq!(first.names, ["relay.test"]);
    let signer = Signer::new(7);
    publish_and_read(&mut c, &signer, "over wss").await;
    assert_eq!(ca.validations(), ["tls-alpn-01 relay.test ok"]);
    assert_eq!(ca.contacts(), [["mailto:ops@relay.test"]]);

    // The same relay speaks plain ws:// too, and sees what arrived over wss://.
    let mut plain = client_connect(relay.plain, "relay.test", "/").await.unwrap();
    read_back(&mut plain, &signer, "over wss").await;

    // Renewal: a later connection is served a different certificate, by the same process.
    let second = until("the renewed certificate", 30, || async {
        let (_, leaf) = wss(relay.https, "relay.test", std::slice::from_ref(&root)).await.ok()?;
        (leaf.serial != first.serial).then_some(leaf)
    })
    .await;
    assert!(second.not_after > first.not_after);
    assert!(relay.alive());
    let (mut c2, again) = wss(relay.https, "relay.test", &[root]).await.unwrap();
    assert_eq!(again.serial, second.serial);
    read_back(&mut c2, &signer, "over wss").await;
    assert!(ca.issued() >= 2);
    assert_eq!(ca.accounts(), 1, "one account across renewals");
    // A connection open across the swap kept working.
    publish_and_read(&mut c, &signer, "after the renewal").await;

    let log = relay.log();
    assert!(log.contains("tls: obtained a certificate for relay.test"), "{log}");
    assert!(log.contains("tls: renewed a certificate for relay.test"), "{log}");
    assert!(log.contains("tls: https on 127.0.0.1:"), "{log}");
    assert!(log.contains("agrees to its terms of service"), "{log}");
    // Account and certificate are in the data directory, private to the owner.
    for f in ["account.key", "cert.pem", "key.pem", "directory"] {
        assert!(dir.join("data").join("tls").join(f).exists(), "{f}");
    }
}

#[tokio::test]
async fn the_cert_command_and_the_redirect_and_nip11_over_https() {
    let dir = temp_dir("misc");
    let ports = (free_port(), free_port(), free_port());
    let ca = MockCa::start(Settings {
        https_target: Some(format!("127.0.0.1:{}", ports.1).parse().unwrap()),
        http_target: Some(format!("127.0.0.1:{}", ports.2).parse().unwrap()),
        lifetime: 90 * DAY,
        tls: false,
    })
    .await;
    let tls = format!("domains = [\"relay.test\"]\ndirectory = \"{}\"\n", ca.directory());
    let relay = start(&dir, ports, "", "", &tls, &[]);
    let root = ca.root_der();
    let (mut s, _) =
        until("a certificate", 30, || async { tls_connect(relay.https, "relay.test", std::slice::from_ref(&root)).await.ok() }).await;

    // NIP-11 and the other plain GETs work over TLS.
    s.write_all(b"GET / HTTP/1.1\r\nHost: relay.test\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    let body: Value = serde_json::from_str(text.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["supported_nips"][0], 1);
    let (mut s, _) = tls_connect(relay.https, "relay.test", std::slice::from_ref(&root)).await.unwrap();
    s.write_all(b"GET /stats HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200 OK") && text.contains("\"connections_open\""), "{text}");

    // Port 80 sends everyone to the same path over https.
    let mut p = TcpStream::connect(relay.http).await.unwrap();
    p.write_all(b"GET /some/page?x=1 HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    p.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{text}");
    assert!(text.contains(&format!("Location: https://relay.test:{}/some/page?x=1\r\n", relay.https.port())), "{text}");

    // `cert` reads what the relay saved, without touching the running relay's store.
    let out = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(relay.config_path()).arg("cert").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        stdout.contains("names: relay.test") && stdout.contains("expires: ") && stdout.contains("in 89 days")
            || stdout.contains("in 90 days"),
        "{stdout}"
    );
    assert!(stdout.contains("issuer: Test Root"), "{stdout}");
}

#[tokio::test]
async fn a_restart_serves_the_saved_certificate_at_once() {
    let dir = temp_dir("restart");
    let ports = (free_port(), free_port(), free_port());
    let ca = MockCa::start(Settings {
        https_target: Some(format!("127.0.0.1:{}", ports.1).parse().unwrap()),
        http_target: Some(format!("127.0.0.1:{}", ports.2).parse().unwrap()),
        lifetime: 90 * DAY,
        tls: false,
    })
    .await;
    let tls = format!("domains = [\"relay.test\"]\ndirectory = \"{}\"\n", ca.directory());
    let first = start(&dir, ports, "", "", &tls, &[]);
    let root = ca.root_der();
    let (_, before) = until("a certificate", 30, || async { wss(first.https, "relay.test", std::slice::from_ref(&root)).await.ok() }).await;
    first.stop();
    assert_eq!(ca.issued(), 1);

    // Same data directory, same settings: the very first handshake succeeds, with the
    // same certificate, and the CA is not asked again.
    let second = start(&dir, ports, "", "", &tls, &[]);
    let (_, after) = wss(second.https, "relay.test", &[root]).await.expect("served at once from the saved certificate");
    assert_eq!(after.serial, before.serial);
    assert!(second.log().contains("tls: serving the saved certificate for relay.test"), "{}", second.log());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(ca.issued(), 1);
}

/// A CA and a certificate for `name`: `(root, chain pem, key pem)`.
fn pki(name: &str) -> (Vec<u8>, String, String) {
    let (ca, leaf) = (EcKey::generate().unwrap(), EcKey::generate().unwrap());
    let t = time::now();
    let root = x509::build_certificate(
        &CertSpec {
            serial: &x509::random_serial(),
            issuer_cn: "Files Root",
            subject_cn: "Files Root",
            not_before: t - 60,
            not_after: t + DAY,
            spki: &ca.spki(),
            dns_names: &[],
            ca: true,
            acme_identifier: None,
        },
        &ca,
    );
    let names = [name.to_string()];
    let leaf_der = x509::build_certificate(
        &CertSpec {
            serial: &x509::random_serial(),
            issuer_cn: "Files Root",
            subject_cn: name,
            not_before: t - 60,
            not_after: t + DAY,
            spki: &leaf.spki(),
            dns_names: &names,
            ca: false,
            acme_identifier: None,
        },
        &ca,
    );
    (root.clone(), pem::encode("CERTIFICATE", &leaf_der) + &pem::encode("CERTIFICATE", &root), pem::encode("PRIVATE KEY", leaf.pkcs8()))
}

fn replace(path: &Path, text: &str) {
    relay_tls::store::write_atomic(path, text.as_bytes()).unwrap();
}

#[tokio::test]
async fn your_own_certificate_files_are_served_and_picked_up_when_they_change() {
    let dir = temp_dir("files");
    std::fs::create_dir_all(&dir).unwrap();
    let (root1, chain1, key1) = pki("one.test");
    let (cert, key) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
    replace(&cert, &chain1);
    replace(&key, &key1);
    let ports = (free_port(), free_port(), free_port());
    let tls = format!("cert = \"{}\"\nkey = \"{}\"\n", cert.display(), key.display());
    // The relay checks the files every 50 ms here instead of every minute.
    let relay = start(&dir, ports, "", "", &tls, &[("RELAY_DEBUG_TLS_POLL_MS", "50")]);
    let (mut c, first) = wss(relay.https, "one.test", std::slice::from_ref(&root1)).await.expect("served at once");
    assert_eq!(first.names, ["one.test"]);
    let signer = Signer::new(9);
    publish_and_read(&mut c, &signer, "from files").await;
    assert!(relay.log().contains("tls: serving the certificate in "), "{}", relay.log());

    // Replace both files, as a renewal script would; the next handshake sees the new one.
    let (root2, chain2, key2) = pki("two.test");
    replace(&key, &key2);
    replace(&cert, &chain2);
    let second = until("the new certificate", 20, || async {
        let (_, leaf) = wss(relay.https, "two.test", std::slice::from_ref(&root2)).await.ok()?;
        Some(leaf)
    })
    .await;
    assert_eq!(second.names, ["two.test"]);
    assert!(wss(relay.https, "one.test", &[root1]).await.is_err(), "the old certificate is gone");
    // The connection that was open through the change still works.
    read_back(&mut c, &signer, "from files").await;

    // No CA was involved, and `cert` reads the file in use.
    let out = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(relay.config_path()).arg("cert").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("names: two.test") && stdout.contains(&format!("certificate: {}", cert.display())),
        "{stdout}"
    );
    assert!(!dir.join("data").join("tls").join("account.key").exists());
}

#[test]
fn bad_tls_setups_stop_the_start_with_a_message_that_says_what_to_fix() {
    let run = |tag: &str, tls: &str, files: &[(&str, String)]| {
        let dir = temp_dir(tag);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        let tls = tls.replace("{dir}", &dir.display().to_string());
        let cfg = dir.join("relay.toml");
        std::fs::write(&cfg, format!("[relay]\nbind = \"127.0.0.1:{}\"\n[store]\ndata = \"{}\"\n[tls]\nenabled = true\nhttps_bind = \"127.0.0.1:{}\"\nhttp_bind = \"127.0.0.1:{}\"\n{tls}", free_port(), dir.join("data").display(), free_port(), free_port())).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(&cfg).output().unwrap();
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).to_string()
    };
    let msg = run("nofile", "cert = \"/nonexistent/chain.pem\"\nkey = \"/nonexistent/key.pem\"\n", &[]);
    assert!(msg.contains("cannot read the certificate /nonexistent/chain.pem"), "{msg}");
    let (_, chain, _) = pki("a.test");
    let (_, _, other_key) = pki("b.test");
    let files = [("chain.pem", chain), ("key.pem", other_key)];
    let msg = run("mismatch", "cert = \"{dir}/chain.pem\"\nkey = \"{dir}/key.pem\"\n", &files);
    assert!(msg.contains("does not belong to the certificate"), "{msg}");
    let msg = run("names", "", &[]);
    assert!(msg.contains("no names to get a certificate for"), "{msg}");

    // A port that is taken.
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let taken_port = taken.local_addr().unwrap().port();
    let dir = temp_dir("taken");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("relay.toml");
    std::fs::write(&cfg, format!("[relay]\nbind = \"127.0.0.1:{}\"\n[store]\ndata = \"{}\"\n[tls]\nenabled = true\ndomains = [\"relay.test\"]\nhttps_bind = \"127.0.0.1:{taken_port}\"\nhttp_bind = \"127.0.0.1:{}\"\n", free_port(), dir.join("data").display(), free_port())).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(&cfg).output().unwrap();
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && msg.contains(&format!("cannot listen on 127.0.0.1:{taken_port}")), "{msg}");
}

#[test]
fn the_cert_command_without_a_certificate() {
    let dir = temp_dir("nocert");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("relay.toml");
    std::fs::write(&cfg, format!("[store]\ndata = \"{}\"\n", dir.join("data").display())).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(&cfg).arg("cert").output().unwrap();
    assert!(!out.status.success());
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(msg.contains("no certificate: HTTPS is off"), "{msg}");
}

/// Sends a WebSocket upgrade naming a client address in `X-Forwarded-For` and
/// returns what the relay sends back within a moment.
async fn upgrade_as<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, forged: &str) -> Vec<u8> {
    let req = format!("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Forwarded-For: {forged}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        let mut chunk = [0u8; 512];
        match tokio::time::timeout(Duration::from_millis(100), s.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => {}
        }
    }
    buf
}

/// Whether a reply is a successful upgrade followed straight away by a close frame,
/// which is how the relay turns away a connection it will not keep.
fn turned_away(reply: &[u8]) -> bool {
    assert!(reply.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(reply));
    let after = reply.windows(4).position(|w| w == b"\r\n\r\n").map_or(reply.len(), |i| i + 4);
    reply.get(after).is_some_and(|b| b & 0x0F == 8)
}

#[tokio::test]
async fn a_forged_address_header_counts_for_nothing_on_the_https_port() {
    let dir = temp_dir("forged");
    let ports = (free_port(), free_port(), free_port());
    let ca = MockCa::start(Settings {
        https_target: Some(format!("127.0.0.1:{}", ports.1).parse().unwrap()),
        http_target: None,
        lifetime: 90 * DAY,
        tls: false,
    })
    .await;
    // The header is trusted (as behind a proxy) and each address may hold one connection.
    let tls = format!("domains = [\"relay.test\"]\ndirectory = \"{}\"\n", ca.directory());
    let relay = start(&dir, ports, "real_ip_header = \"x-forwarded-for\"", "max_connections_per_ip = 1", &tls, &[]);
    let root = ca.root_der();

    // Plain port: the header names the client. Two claims of one address are one
    // client, and the second is over the limit.
    let mut a = TcpStream::connect(relay.plain).await.unwrap();
    let mut b = TcpStream::connect(relay.plain).await.unwrap();
    assert!(!turned_away(&upgrade_as(&mut a, "203.0.113.1").await));
    assert!(turned_away(&upgrade_as(&mut b, "203.0.113.1").await), "the plain port honours the header");

    // HTTPS: it is the relay's own front door, so the header is ignored. Both clients
    // are 127.0.0.1, which has no limit; had the header counted, the second would be
    // turned away as the same address.
    let (mut s1, _) =
        until("a certificate", 30, || async { tls_connect(relay.https, "relay.test", std::slice::from_ref(&root)).await.ok() }).await;
    let (mut s2, _) = tls_connect(relay.https, "relay.test", &[root]).await.unwrap();
    assert!(!turned_away(&upgrade_as(&mut s1, "203.0.113.1").await));
    assert!(!turned_away(&upgrade_as(&mut s2, "203.0.113.1").await), "a forged header must not name the client");
}

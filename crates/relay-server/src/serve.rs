//! `serve`: start the relay. Also what running the binary with no arguments does.

use crate::admin;
use crate::config::{store_options, Config};
use crate::ingest::{self, Sink};
use crate::reactor::{self, Shared};
use crate::session::SessionCfg;
use relay_store::Store;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tokio::sync::mpsc as tmpsc;

/// Events waiting for the writer before EVENTs are answered "busy". At group
/// commit rates this is well under a second of backlog.
const WRITE_QUEUE: usize = 65_536;

pub fn run(cfg: Config) -> Result<(), String> {
    let t = Instant::now();
    // Serve at once; every index block is checked on a thread of its own (a
    // damaged one stops the relay, and the next start refuses it up front).
    let opts = relay_store::Options { check_index_in_background: true, ..store_options(&cfg) };
    let (store, w) = Store::open(&cfg.store.data, opts).map_err(|e| format!("{}: {e}", cfg.store.data.display()))?;
    let checked = store.clone();
    let events = w.next_seq();
    let opened = w.open_phases.clone();
    let threads = if cfg.relay.threads == 0 { std::thread::available_parallelism().map_or(4, |n| n.get()) } else { cfg.relay.threads };
    let bind = cfg.relay.bind;
    let (unix_path, unix_mode) = (std::path::PathBuf::from(&cfg.relay.unix_socket), cfg.relay.unix_socket_mode);
    let data = cfg.store.data.clone();
    // HTTPS, when asked for: certificates first, so a saved one serves from the first connection.
    let tls = if cfg.tls.enabled { Some(start_tls(&cfg)?) } else { None };
    let https_bind = cfg.tls.enabled.then_some(cfg.tls.https_bind);
    let http_bind = cfg.tls.http_bind.filter(|_| cfg.tls.enabled);

    let scfg = Arc::new(SessionCfg::from_config(&cfg)?);
    for (label, list) in [("banlist", &scfg.bans), ("allowlist", &scfg.allowed)] {
        if let Some(list) = list {
            eprintln!("{label}: {} keys from {}", list.len(), list.path().display());
            list.watch();
        }
    }
    let syncs = cfg.sync.clone();

    let (wtx, wrx) = mpsc::sync_channel(WRITE_QUEUE);
    let shared = Arc::new(Shared::new(cfg, scfg.clone(), store.clone(), wtx, threads));
    let mut txs = Vec::with_capacity(threads);
    let mut rxs = Vec::with_capacity(threads);
    for _ in 0..threads {
        let (tx, rx) = tmpsc::unbounded_channel();
        txs.push(tx);
        rxs.push(rx);
    }
    assert!(shared.reactors.set(txs.clone()).is_ok(), "reactors are set once");
    // A quarter of the reactors' cores, at least one: big COUNTs are rare.
    reactor::count_workers(&shared, threads.div_ceil(4));

    let make_sinks = |txs: &[tmpsc::UnboundedSender<crate::ingest::ReactorMsg>]| -> Vec<Sink> {
        txs.iter()
            .cloned()
            .map(|tx| {
                let s: Sink = Box::new(move |m| {
                    let _ = tx.send(m);
                });
                s
            })
            .collect()
    };
    let sinks = make_sinks(&txs);
    let reply_sinks = make_sinks(&txs);
    let (ctl_tx, ctl_rx) = mpsc::channel();
    let admin_store = store.clone();
    let writer = std::thread::Builder::new()
        .name("writer".into())
        .spawn(move || ingest::run(w, store, wrx, ctl_rx, sinks, reply_sinks))
        .map_err(|e| e.to_string())?;

    // Ready before the relay's own port is, so that a script which waits for
    // the port can run operator commands at once. Not fatal: the relay serves
    // without it.
    let asks = shared.clone();
    let top: admin::TopFn = Arc::new(move |minutes| asks.top(minutes));
    let asks = shared.clone();
    let heavy: admin::HeavyFn = Arc::new(move |minutes| asks.heavy(minutes));
    let admin = match admin::start(&data, admin::Ctx { store: admin_store.clone(), ctl: ctl_tx.clone(), policy: scfg.clone(), top: Some(top), heavy: Some(heavy) }) {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("admin socket unavailable ({e}): query, count, delete and sync cannot reach this relay while it runs");
            None
        }
    };

    // The socket is set up through tokio, which needs a runtime in scope.
    let (l, tl) = {
        let setup = tokio::runtime::Builder::new_current_thread().enable_io().build().map_err(|e| e.to_string())?;
        let _enter = setup.enter();
        let stop_admin = || {
            if let Some(a) = &admin {
                a.stop();
            }
        };
        let l = reactor::listener(bind).map_err(|e| {
            stop_admin();
            listen_error(bind, &e)
        })?;
        let tl = https_bind
            .map(|a| {
                reactor::listener(a).map_err(|e| {
                    stop_admin();
                    listen_error(a, &e)
                })
            })
            .transpose()?;
        (l, tl)
    };
    let ul = Some(unix_path.as_path())
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| {
            reactor::unix_listener(p, unix_mode).map_err(|e| {
                if let Some(a) = &admin {
                    a.stop();
                }
                format!("cannot listen on {}: {e}", p.display())
            })
        })
        .transpose()?;
    let mut conn_txs = Vec::with_capacity(threads);
    for (i, rx) in rxs.into_iter().enumerate() {
        let (ctx, crx) = tmpsc::unbounded_channel();
        conn_txs.push(ctx);
        let sh = shared.clone();
        std::thread::Builder::new().name(format!("reactor-{i}")).spawn(move || reactor::run(i, sh, crx, rx)).map_err(|e| e.to_string())?;
    }
    if let (Some(tl), Some(tls)) = (tl, &tls) {
        let (conns, config) = (conn_txs.clone(), tls.config.clone());
        std::thread::Builder::new().name("acceptor-tls".into()).spawn(move || reactor::accept_loop(tl, conns, Some(config))).map_err(|e| e.to_string())?;
    }
    if let Some(ul) = ul {
        let conns = conn_txs.clone();
        std::thread::Builder::new().name("acceptor-unix".into()).spawn(move || reactor::accept_loop_unix(ul, conns)).map_err(|e| e.to_string())?;
        eprintln!("also listening on {}", unix_path.display());
    }
    std::thread::Builder::new().name("acceptor".into()).spawn(move || reactor::accept_loop(l, conn_txs, None)).map_err(|e| e.to_string())?;
    // Other relays to keep in step with, on a thread of their own.
    crate::sync::live::start(syncs, shared.sync.clone(), admin_store, ctl_tx, scfg, shared.clone()).map_err(|e| format!("cannot start syncing: {e}"))?;
    eprintln!(
        "{} {} ({}) listening on {bind}: {threads} reactors, {events} events, ready in {:.2}s",
        crate::brand::NAME,
        crate::brand::VERSION,
        crate::brand::BUILD,
        t.elapsed().as_secs_f64()
    );
    // A slow start says where its time went.
    if t.elapsed() >= Duration::from_millis(500) {
        let steps: Vec<String> = opened.steps.iter().filter(|s| s.1 >= Duration::from_millis(10)).map(|(name, d)| format!("{name} {:.2}s", d.as_secs_f64())).collect();
        let store: Duration = opened.steps.iter().map(|s| s.1).sum();
        eprintln!("startup: opening the store took {:.2}s ({}), the rest {:.2}s", store.as_secs_f64(), steps.join(", "), (t.elapsed() - store).as_secs_f64());
    }
    if let Some(a) = https_bind {
        let plain = http_bind.map_or(String::new(), |h| format!(", plain http on {h} (certificate checks and a redirect to https)"));
        eprintln!("tls: https on {a}{plain}");
    }
    watch_index_check(checked);

    wait_for_signal();
    eprintln!("shutting down: finishing the batch in flight");
    ingest::SHUTDOWN.store(true, Ordering::Release);
    if let Some(a) = &admin {
        a.stop();
    }
    if !unix_path.as_os_str().is_empty() {
        let _ = std::fs::remove_file(&unix_path);
    }
    let _ = writer.join();
    if INDEX_DAMAGED.load(Ordering::Acquire) {
        eprintln!("stopped: the index is damaged (see above)");
        std::process::exit(1);
    }
    eprintln!("stopped cleanly");
    std::process::exit(0);
}

/// Set when the background index check found a damaged block.
static INDEX_DAMAGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Reports the background index check. A damaged block stops the relay the
/// way SIGTERM does, then exits 1: a damaged index cannot answer correctly,
/// and the next start refuses it before serving (see `Options::check_index_in_background`).
fn watch_index_check(store: Store) {
    let spawned = std::thread::Builder::new().name("index-watch".into()).spawn(move || match store.wait_index_check() {
        relay_store::IndexCheck::Passed { blocks, took } => {
            eprintln!("index check: all {blocks} blocks sound ({:.2}s, while serving)", took.as_secs_f64());
        }
        relay_store::IndexCheck::Damaged(msg) => {
            eprintln!("{msg}");
            INDEX_DAMAGED.store(true, Ordering::Release);
            // SAFETY: signalling our own process; the handler in wait_for_signal shuts down cleanly.
            unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        }
        relay_store::IndexCheck::BeforeOpen | relay_store::IndexCheck::Running => {}
    });
    if let Err(e) = spawned {
        eprintln!("index check: cannot watch it ({e}); a damaged block will still be refused when a query reads it");
    }
}

/// Starts the HTTPS side: binds the plain-HTTP port, loads or begins obtaining a
/// certificate, and returns what the HTTPS acceptor needs.
fn start_tls(cfg: &Config) -> Result<relay_tls::Tls, String> {
    let t = &cfg.tls;
    let http = t.http_bind.map(|a| std::net::TcpListener::bind(a).map_err(|e| listen_error(a, &e))).transpose()?;
    let names = t.names(&cfg.relay.urls);
    let source = if t.uses_files() {
        relay_tls::Source::Files { cert: t.cert.clone().into(), key: t.key.clone().into() }
    } else {
        relay_tls::Source::Acme { domains: names.clone(), email: Some(t.email.clone()).filter(|e| !e.is_empty()), directory: t.directory_url().to_string() }
    };
    // Like RELAY_DEBUG_WRITER, a switch for tests: look at certificate files every N
    // milliseconds instead of every minute.
    let mut timing = relay_tls::Timing::default();
    if let Some(ms) = std::env::var("RELAY_DEBUG_TLS_POLL_MS").ok().and_then(|v| v.parse().ok()) {
        timing.files_poll = std::time::Duration::from_millis(ms);
    }
    relay_tls::Tls::start(relay_tls::Options {
        data_dir: cfg.store.data.clone(),
        source,
        http,
        https_port: t.https_bind.port(),
        redirect_hosts: names,
        user_agent: format!("{}/{}", crate::brand::SLUG, crate::brand::VERSION),
        ca_roots: Vec::new(),
        timing,
    })
}

/// "cannot listen on ADDR: why", with the usual fix for the usual reasons.
fn listen_error(addr: SocketAddr, e: &std::io::Error) -> String {
    let hint = match e.kind() {
        std::io::ErrorKind::PermissionDenied if addr.port() < 1024 => " (ports below 1024 need the program to run as root, or on Linux to hold the CAP_NET_BIND_SERVICE capability; or choose a higher port)",
        std::io::ErrorKind::AddrInUse => " (another program is using that port)",
        _ => "",
    };
    format!("cannot listen on {addr}: {e}{hint}")
}

fn wait_for_signal() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("signal runtime");
    rt.block_on(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    });
}

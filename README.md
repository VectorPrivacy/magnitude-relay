<p align="center">
  <img src="docs/assets/banner.png" alt="Vector Relays: Magnitude" width="820">
</p>

<h3 align="center">The fastest Nostr relay, built for Vector</h3>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--only-33DB98?style=flat" alt="License: AGPL-3.0-only"></a>
  <img src="https://img.shields.io/badge/rust-1.85%2B-5E5E5E?style=flat&logo=rust&logoColor=33DB98" alt="Rust 1.85+">
  <a href="https://vectorapp.io/blog/magnitude-relay/"><img src="https://img.shields.io/badge/read-the%20blog%20post-33DB98?style=flat" alt="Read the blog post"></a>
</p>

---

**Magnitude Relay** is the Nostr relay behind [Vector](https://vectorapp.io), the private messenger. It serves `wss://jskitty.com/nostr` and `wss://asia.vectorapp.io/nostr`, and replaced strfry on both without anyone needing to update a thing.

It's built around what Vector actually sends: gift-wrapped DMs, Concord Communities, NIP-77 sync and a constant stream of typing indicators. It's also a single program anyone can run, on hardware a lot smaller than they'd expect.

<p align="center">
  <img src="docs/assets/scoreboard.png" alt="300x headroom, 72x faster delivery, 38x faster requests, 59% less disk" width="820">
</p>

<p align="center"><sub>Against strfry, same machine, same cores, every answer checked. Full results in <a href="docs/BENCHMARKS.md">docs/BENCHMARKS.md</a>.</sub></p>

## Why Magnitude Relay

**Fast where it counts.** On 951 requests built from 4.9 million real Vector events, it answered in 0.45 ms on average against strfry's 17.4 ms. DM inboxes and Community channels open up to 10× faster, NIP-77 sync runs up to 6.7× faster, and a new message reaches a 1,000-member Community in 0.58 ms instead of 41.9 ms.

**Ready to scale.** On two CPU cores it stores 29,000+ new messages and opens 11,000+ DM inboxes a second: hundreds of times what Vector's busiest relay sees today.

**Built for Vector and Concord.** Indexes and storage are shaped around how Vector reads: gift wraps by recipient, Concord channels by plane key, NIP-77 fingerprints straight from the index. Concord's limits (thousands of authors per filter, deep paging, same-second walls) are first-class.

**Private by design.**
- No AUTH: nobody has to identify themselves to read or write.
- Typing indicators, push requests and other ephemeral events are relayed live and **never written to disk**.
- Deletions (NIP-09) and Requests to Vanish (NIP-62) are honoured, and deleted data is **overwritten on disk**, not just hidden.
- A gift wrap answers only to its recipient: nobody holding a shared Concord key can delete a Community's history.
- Bulk scraping of gift wraps is refused: a wrap query must name a recipient, an author or ids.
- Publishes its Tor and I2P addresses (NIP-11 `privacy_addresses`) so apps can find them.

**Small and self-hostable.** One program and one optional settings file. 4.9 million events take 11 GB where strfry needed 27 GB, a 13 GB database stays fast with 1 GB of memory, and a restart takes about half a second.

**Durable.** `OK` means on disk: every acknowledged event is `fdatasync`ed first. The log is checksummed, crashes are recovered by replaying only its tail, and a backup can be taken while the relay serves.

## Quick start

You need [Rust](https://rustup.rs) 1.85 or newer. Linux is the production platform; macOS works for development.

```bash
git clone https://github.com/VectorPrivacy/magnitude-relay
cd magnitude-relay
cargo build --release
./target/release/magnitude-relay
```

That's a working relay on `ws://127.0.0.1:7777`, storing data in `./data`, accepting what Vector uses. Point a web server at it for `wss://`, or let the relay do HTTPS itself (see [HTTPS](#https)).

To change anything, write a fully commented settings file and edit it:

```bash
./target/release/magnitude-relay init            # writes ./relay.toml, never overwrites
./target/release/magnitude-relay --config relay.toml
```

### Moving in from strfry

Magnitude Relay reads strfry's export format directly and checks every signature on the way in:

```bash
strfry export | magnitude-relay --config relay.toml import -
```

Or run both side by side while you try it, kept equal by NIP-77 sync, by adding this to `relay.toml`:

```toml
[[sync]]
url = "ws://127.0.0.1:7777"   # your strfry
direction = "both"
```

### With Docker

No Rust needed, only Docker:

```bash
git clone https://github.com/VectorPrivacy/magnitude-relay
cd magnitude-relay
docker compose up -d
```

That's the same relay on `ws://127.0.0.1:7777`, with its events in the `relay-data` volume. Its settings are the commented file `init` writes, with `bind` opened to `0.0.0.0:7777` so the relay can be reached from outside the container. To change them, copy that file out, edit it, and uncomment the `relay.toml` mount in [`compose.yaml`](compose.yaml):

```bash
docker compose cp relay:/etc/magnitude-relay/relay.toml ./relay.toml
docker compose up -d             # after editing, and uncommenting the mount
```

Behind a web server, set `real_ip_header` before going live. In a container every client arrives from Docker's gateway rather than its own address, so without it the per-IP limits treat all your users as one. In `relay.toml`:

```toml
[relay]
real_ip_header = "x-real-ip"
```

and in nginx, `proxy_set_header X-Real-IP $remote_addr;` (see [docs/nginx.md](docs/nginx.md)). Keep the published port on `127.0.0.1`, as `compose.yaml` does: the header is trusted from whoever connects.

Operator commands run inside the container, against the running relay:

```bash
docker compose exec relay magnitude-relay --config /etc/magnitude-relay/relay.toml --data /data count --filter '{}'
```

An import needs the store to itself, so stop the relay first. From a strfry running in Docker:

```bash
docker compose stop relay
docker exec <your-strfry-container> ./strfry export | docker compose run --rm -T relay import -
docker compose start relay
```

## Configuration

Every setting is optional; `magnitude-relay init` documents them all. The highlights:

| Section | What it controls |
|---|---|
| `[relay]` | `bind` address, a Unix `unix_socket` for a web server in front, `urls` (the relay's public addresses), `real_ip_header` behind a proxy, `compression` (permessage-deflate) |
| `[info]` | The NIP-11 identity: name, description, contact, icon, operator `pubkey`, and `privacy_addresses` for Tor and I2P twins |
| `[policy]` | Which kinds it accepts: `"vector"` (default), `"all"`, or a list; plus `allow_kinds`, `deny_kinds`, event size and future-timestamp limits, a `banlist` and an `allowlist` |
| `[limits]` | Message size, subscriptions, filters, `limit` caps, per-IP connections and events per minute |
| `[store]` | Data directory, durability, file size, memory for the newest index entries |
| `[tls]` | Built-in HTTPS: Let's Encrypt for your domains, or your own certificate files |
| `[[sync]]` | Other relays to keep in step with over NIP-77: down, up or both, continuously |
| `[[peer]]` | Your own relays that may sync with this one as trusted peers |

### Choosing what it accepts

By default it accepts only what Vector produces and reads (profiles, gift-wrapped DMs, Concord Communities, badges, lists, settings, and ephemeral events such as typing and Nostr Connect). Public notes are refused. To run a general relay, or Vector plus notes:

```toml
[policy]
kinds = "all"            # or keep "vector" and add: allow_kinds = [1, 7]
```

### Banning a key

```toml
[policy]
banlist = "/etc/magnitude-relay/banlist.txt"   # one npub or hex key per line, # for comments
```

The relay reads the file again within seconds of a change, no restart needed. A banned key's events, and gift wraps addressed to it, are answered `OK` and dropped, and the key is left out of every filter, so its owner sees an ordinary, empty relay. Without AUTH that is as far as a ban reaches: gift wraps the key sends are signed by one-time keys, and Concord events by shared plane keys. `delete --filter '{"authors":["<hex>"]}'` removes what it stored before the ban.

### Letting your own accounts publish anything

```toml
[policy]
allowlist = "/etc/magnitude-relay/allowlist.txt"   # the banlist's format
```

A listed key may publish events of any kind, even ones `kinds` refuses: your official account's notes and articles can live on a relay that otherwise carries only Vector's traffic, and anyone can read them. Every other rule still applies, `deny_kinds` still refuses, and a key on both lists is banned.

### Changing either list from the command line

```sh
magnitude-relay allowlist add npub1… --note "the official account"
magnitude-relay banlist add npub1…
magnitude-relay banlist remove npub1…
magnitude-relay allowlist list
```

Each edit rewrites the file in one step, keeping its owner and mode, and the running relay applies it within about 15 seconds. The setting that names a file is read when the relay starts; the file's contents never need a restart.

### HTTPS

Behind nginx or Caddy, keep the default and point the proxy at `[relay] bind` or, faster, at `unix_socket` (see [docs/nginx.md](docs/nginx.md)). With nothing in front:

```toml
[relay]
urls = ["wss://relay.example.com"]

[tls]
enabled = true            # wss:// on 443, certificates from Let's Encrypt, renewed in the background
email = "you@example.com"
```

`magnitude-relay cert` shows the certificate's names and expiry.

## Operating it

| Command | What it does |
|---|---|
| `serve` | Runs the relay (the default) |
| `init [FILE]` | Writes a fully commented settings file |
| `import <file\|->` | Loads a JSONL export (strfry's format), verifying every event |
| `export` | Writes every live event as JSONL |
| `backup <DIR>` | Copies the store while the relay keeps serving, then checks the copy |
| `query` / `count` | Prints or counts the events matching a filter |
| `delete` | Removes matching events (`--dry-run` first, then `--yes`) |
| `sync <url>` | Compares with another relay over NIP-77 and copies what one side lacks |
| `stats` / `cert` | Store statistics; the HTTPS certificate |
| `top` | Who has used the running relay in the last hour, by address: connections, requests, refusals, bytes out, app, and what their last request asked for (kinds and counts, never keys) |
| `heavy` | What strained the running relay lately: REQs, COUNTs and NEG-OPENs that took 25 ms or more (time waiting for a worker shown apart) or sent 2,000 events or 2 MB, and connections that took 2 MB/s or more out, with address, app and the request's shape. Held in memory, 512 per thread; the worst also go to the log, without the address |

While the relay runs, `query`, `count`, `delete`, `backup` and `sync` reach it through `<data>/admin.sock`, which only the relay's user can open. Run `magnitude-relay --help` for every option.

### Watching it

Every relay has a public dashboard at `/dashboard`, a landing page at `/`, JSON at `/stats`, a heartbeat at `/live`, and Prometheus metrics at `/metrics`. Behind a path such as `/nostr`, they live at `/nostr/dashboard` and so on. Refusals are counted by reason there (a kind not accepted, invalid, rate-limited, gift wraps asked for wholesale, and so on); which address did what is only for the operator, through `top` and `heavy`. While a bulk sync with another relay runs, the top of the dashboard says so ("JSKitty Relay is syncing with Vector Asia Relay"), and events that arrived over a sync link are charted apart from those apps sent.

<p align="center">
  <img src="docs/assets/dashboard.jpg" alt="The relay's live dashboard" width="820">
</p>

### Running more than one

[`deploy/relays/`](deploy/relays/) is how Vector runs its fleet: one tested build, the same bytes to every host, upgraded one relay at a time with health checks, a soak period and automatic rollback. It includes a hardened systemd unit and notes on tuning the host.

## Supported NIPs

[01](https://github.com/nostr-protocol/nips/blob/master/01.md) · [09](https://github.com/nostr-protocol/nips/blob/master/09.md) · [11](https://github.com/nostr-protocol/nips/blob/master/11.md) · [17](https://github.com/nostr-protocol/nips/blob/master/17.md) · [24](https://github.com/nostr-protocol/nips/blob/master/24.md) · [30](https://github.com/nostr-protocol/nips/blob/master/30.md) · [38](https://github.com/nostr-protocol/nips/blob/master/38.md) · [40](https://github.com/nostr-protocol/nips/blob/master/40.md) · [45](https://github.com/nostr-protocol/nips/blob/master/45.md) · [46](https://github.com/nostr-protocol/nips/blob/master/46.md) · [58](https://github.com/nostr-protocol/nips/blob/master/58.md) · [59](https://github.com/nostr-protocol/nips/blob/master/59.md) · [62](https://github.com/nostr-protocol/nips/blob/master/62.md) · [65](https://github.com/nostr-protocol/nips/blob/master/65.md) · [70](https://github.com/nostr-protocol/nips/blob/master/70.md) · [77](https://github.com/nostr-protocol/nips/blob/master/77.md) · [78](https://github.com/nostr-protocol/nips/blob/master/78.md)

Plus Vector's Concord protocol and push requests, and every ephemeral kind (20000-29999), relayed live.

## How it's built

Pure Rust on a small set of dependencies: `tokio` for the reactor, `libsecp256k1` for signatures, `rustls` and `ring` for HTTPS, and our own [nostr-parse](https://github.com/VectorPrivacy/nostr-parse) for reading events. The storage engine, WebSocket server, the rest of the JSON handling and the ACME client are written for this relay.

| Crate | What it is |
|---|---|
| `relay-proto` | Allocation-free JSON scanning, canonical events, id and signature checks, filters |
| `relay-store` | The storage engine: an append-only log regrouped by reader, an LSM index, NIP-77 fingerprints and COUNT straight from the index |
| `relay-net` | HTTP/1.1 and WebSocket, server and client |
| `relay-tls` | Built-in HTTPS: ACME, certificates and renewal over rustls |
| `relay-server` | The program: settings, reactors, subscriptions, sync, dashboard, operator commands |
| `relay-bench` | The load generator and differential tester used for every number above |

[docs/DESIGN.md](docs/DESIGN.md) explains the rules it takes from Vector and Concord, the storage engine and the decisions behind them. [docs/SIG_PERF.md](docs/SIG_PERF.md) covers batched signature checks and multi-lane SHA-256.

## Testing

```bash
cargo test --workspace
```

The [`adversarial/`](adversarial/) suite goes further: parser fuzzing, a hostile-client harness, crash torture with injected disk faults, and stress runs. See [docs/ADVERSARIAL.md](docs/ADVERSARIAL.md).

## License

Magnitude Relay is free software, released under the [GNU Affero General Public License, version 3](LICENSE) (AGPL-3.0-only).

In short: you may use, study, modify and share it for any purpose, including commercially. If you run a **modified** version that other people use over a network, such as a public relay, you must offer them its source under the same license. Running it unmodified, or changing it for your own private use, asks nothing of you.

---

**Trademark notice:** This license covers the source code only. The Vector and Magnitude names, logos, and branding are trademarks of Formless Labs and are not licensed under the AGPL. Forks are welcome under their own name. See [TRADEMARK.md](TRADEMARK.md).

## Credits

- [strfry](https://github.com/hoytech/strfry) and Doug Hoyte, for carrying Vector's messages from the start, and for [negentropy](https://github.com/hoytech/negentropy), the sync protocol this relay speaks
- The [Nostr](https://github.com/nostr-protocol/nips) community, for an open protocol anyone can build a relay for
- [Rust](https://www.rust-lang.org/), [Tokio](https://tokio.rs/), [rustls](https://github.com/rustls/rustls), [ring](https://github.com/briansmith/ring) and [libsecp256k1](https://github.com/bitcoin-core/secp256k1)

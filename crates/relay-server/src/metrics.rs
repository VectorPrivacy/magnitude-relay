//! Counters, kept per reactor and summed when read.
//!
//! A shared counter bumped by every core on every message bounces its cache
//! line between cores; Magnitude measured 142 ns → 81 ns for four counter
//! updates just from padding them apart. Here each reactor owns a block of
//! counters aligned to 128 bytes (two lines: Intel's adjacent-line prefetcher
//! pairs them) and writes only its own, with relaxed ordering. `/stats` and
//! `/metrics` add the blocks up.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

macro_rules! counters {
    ($( $(#[$doc:meta])* $name:ident ),* $(,)?) => {
        /// One reactor's counters.
        #[repr(align(128))]
        #[derive(Default)]
        pub struct Block {
            $( $(#[$doc])* pub $name: AtomicU64, )*
        }

        /// A summed snapshot.
        #[derive(Default, Debug, Clone, Copy)]
        pub struct Totals {
            $( pub $name: u64, )*
        }

        impl Totals {
            fn add(&mut self, b: &Block) {
                $( self.$name += b.$name.load(Ordering::Relaxed); )*
            }

            /// `(name, value)` pairs, for the text formats.
            pub fn fields(&self) -> Vec<(&'static str, u64)> {
                vec![ $( (stringify!($name), self.$name), )* ]
            }
        }
    };
}

counters! {
    /// WebSocket connections accepted.
    connections_total,
    /// Connections refused at the per-IP limit.
    connections_refused,
    /// Connections that negotiated permessage-deflate.
    connections_deflate,
    /// Text messages received.
    messages_in,
    /// EVENT messages received.
    events_in,
    /// Of those, from a trusted peer (`[[peer]]`): what reached this relay over
    /// a sync link rather than from an app.
    events_in_peer,
    /// Events stored (OK true, new).
    events_stored,
    /// Events already stored (OK true, duplicate).
    events_duplicate,
    /// Events refused (policy, invalid, deleted, superseded, rate limit).
    events_refused,
    /// The same, by reason (they add up to `events_refused`): a kind this
    /// relay does not accept; malformed, a bad id or signature, too large,
    /// too many tags, dated too far ahead or already expired; NIP-70
    /// protected; over the address's allowance or the relay busy; older than
    /// the version held of a replaceable event; deleted or vanished; other.
    events_refused_kind,
    events_refused_invalid,
    events_refused_protected,
    events_refused_rate,
    events_refused_superseded,
    events_refused_deleted,
    events_refused_other,
    /// REQs, COUNTs and NEG-OPENs refused, by reason: gift wraps asked for
    /// wholesale rather than by author, recipient or id (how a scraper shows
    /// itself); over a limit (filters, values, subscriptions, answer or sync
    /// size); a filter that does not parse; the relay too busy.
    reqs_refused_wraps,
    reqs_refused_limits,
    reqs_refused_invalid,
    reqs_refused_busy,
    /// AUTH messages, answered that this relay does not use AUTH.
    auth_refused,
    /// New connections turned away at the per-address rate (HTTP 429).
    connections_rate_limited,
    /// Ephemeral events relayed.
    events_ephemeral,
    /// Signatures accepted by a batch check (a read that brought several EVENTs).
    sigs_batched,
    /// Batch checks that passed (`sigs_batched` / this is the mean batch size;
    /// a batch can hold the EVENTs of many connections).
    sig_batches,
    /// Batch checks that failed, so each signature in them was checked alone.
    sig_batches_failed,
    /// EVENT messages sent to subscribers (stored replies and live delivery).
    events_out,
    /// Live deliveries (subset of events_out).
    events_live,
    /// Live deliveries whose bytes were shared with other subscribers, not copied.
    events_shared,
    /// REQ messages.
    reqs,
    /// COUNT messages.
    counts,
    /// COUNTs large enough to be handed to the counting workers.
    counts_offloaded,
    /// REQs costly enough to be answered by the query workers.
    reqs_offloaded,
    /// NEG-OPENs whose set was large enough to be built by the query workers.
    negs_offloaded,
    /// Costly REQs, COUNTs and NEG-OPENs answered on a reactor because the
    /// workers' queue was full (a burst of them: slower, but not refused).
    reqs_inline_fallback,
    /// NEG-OPEN messages.
    neg_opens,
    /// Sum of REQ time to EOSE, microseconds (with reqs: the mean).
    req_micros,
    /// REQs, COUNTs and NEG-OPENs that were slow or big (see `heavy`).
    requests_heavy,
    /// Runs of seconds in which one connection took a lot of bytes out.
    bursts,
    /// Bytes written to sockets.
    bytes_out,
    /// Bytes read from sockets.
    bytes_in,
    /// Connections dropped for falling behind.
    slow_drops,
}

pub struct Metrics {
    blocks: Box<[Block]>,
    started: Instant,
    /// Gauge: open connections.
    pub open: AtomicU64,
}

impl Metrics {
    pub fn new(reactors: usize) -> Metrics {
        Metrics { blocks: (0..reactors).map(|_| Block::default()).collect(), started: Instant::now(), open: AtomicU64::new(0) }
    }

    /// The block reactor `i` writes to.
    #[inline]
    pub fn of(&self, i: usize) -> &Block {
        &self.blocks[i]
    }

    pub fn totals(&self) -> Totals {
        let mut t = Totals::default();
        for b in self.blocks.iter() {
            t.add(b);
        }
        t
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

#[inline]
pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn add(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    #[test]
    fn blocks_are_padded_and_summed() {
        assert_eq!(std::mem::align_of::<super::Block>(), 128);
        let m = super::Metrics::new(3);
        super::inc(&m.of(0).reqs);
        super::add(&m.of(2).reqs, 4);
        assert_eq!(m.totals().reqs, 5);
        assert!(m.totals().fields().iter().any(|(n, v)| *n == "reqs" && *v == 5));
    }
}

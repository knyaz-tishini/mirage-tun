use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct StackMetrics {
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub active_tcp: AtomicU64,
    pub active_udp: AtomicU64,
    pub socks5_ok: AtomicU64,
    pub socks5_fail: AtomicU64,
    pub bypass_ok: AtomicU64,
    pub bypass_fail: AtomicU64,
}

impl StackMetrics {
    pub fn snapshot(&self) -> StackMetricsSnapshot {
        StackMetricsSnapshot {
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            active_tcp: self.active_tcp.load(Ordering::Relaxed),
            active_udp: self.active_udp.load(Ordering::Relaxed),
            socks5_ok: self.socks5_ok.load(Ordering::Relaxed),
            socks5_fail: self.socks5_fail.load(Ordering::Relaxed),
            bypass_ok: self.bypass_ok.load(Ordering::Relaxed),
            bypass_fail: self.bypass_fail.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StackMetricsSnapshot {
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub active_tcp: u64,
    pub active_udp: u64,
    pub socks5_ok: u64,
    pub socks5_fail: u64,
    pub bypass_ok: u64,
    pub bypass_fail: u64,
}

//! Per-process RSS memory pressure monitor — standalone copy for mirage2tun.
//!
//! Mirrors `mirage-runtime-guard` (mirage2app/crates/runtime-guard/) without
//! the separate crate dependency.  Keep in sync with the original when changing
//! thresholds or sampling logic.
//!
//! # Windows note
//! `sysinfo` reads RSS via `GetProcessMemoryInfo` (PSAPI).  No elevated
//! privileges are required for querying the **current** process.

use std::time::Duration;

use sysinfo::{Pid, System};
use tokio::sync::watch;
use tracing::{debug, warn};

// ── Public types ──────────────────────────────────────────────────────────────

pub struct MemoryGuardConfig {
    pub sample_interval: Duration,
    pub warn_threshold_pct: f32,
    pub critical_threshold_pct: f32,
    pub fatal_threshold_pct: f32,
}

impl Default for MemoryGuardConfig {
    fn default() -> Self {
        Self {
            sample_interval: Duration::from_secs(10),
            warn_threshold_pct: 0.70,
            critical_threshold_pct: 0.85,
            fatal_threshold_pct: 0.95,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PressureLevel {
    Ok,
    Warn,
    Critical,
    Fatal,
}

pub struct MemoryGuard {
    pub level_rx: watch::Receiver<PressureLevel>,
}

impl MemoryGuard {
    pub fn spawn(config: MemoryGuardConfig, on_fatal: Box<dyn FnOnce() + Send + 'static>) -> Self {
        let (level_tx, level_rx) = watch::channel(PressureLevel::Ok);
        tokio::spawn(guard_task(config, level_tx, on_fatal));
        Self { level_rx }
    }
}

// ── Background task ───────────────────────────────────────────────────────────

async fn guard_task(
    config: MemoryGuardConfig,
    level_tx: watch::Sender<PressureLevel>,
    on_fatal: Box<dyn FnOnce() + Send + 'static>,
) {
    let pid = Pid::from_u32(std::process::id());
    let mut on_fatal = Some(on_fatal);
    let mut current_level = PressureLevel::Ok;
    let mut interval = tokio::time::interval(config.sample_interval);

    loop {
        interval.tick().await;

        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);

        let total_ram = sys.total_memory();
        if total_ram == 0 {
            debug!("runtime-guard: total_memory=0, skipping sample");
            continue;
        }

        let rss = match sys.process(pid) {
            Some(p) => p.memory(),
            None => {
                tracing::error!("runtime-guard: could not find own process in sysinfo");
                continue;
            }
        };

        let pct = rss as f32 / total_ram as f32;

        let new_level = if pct >= config.fatal_threshold_pct {
            PressureLevel::Fatal
        } else if pct >= config.critical_threshold_pct {
            PressureLevel::Critical
        } else if pct >= config.warn_threshold_pct {
            PressureLevel::Warn
        } else {
            PressureLevel::Ok
        };

        if new_level != current_level {
            log_transition(current_level, new_level, pct, rss, total_ram);
            current_level = new_level;
            let _ = level_tx.send(new_level);
        } else {
            debug!(
                rss_mb = rss / 1024 / 1024,
                pct = format!("{:.1}%", pct * 100.0),
                level = ?new_level,
                "runtime-guard: sample"
            );
        }

        if new_level == PressureLevel::Fatal {
            if let Some(f) = on_fatal.take() {
                warn!("runtime-guard: fatal threshold crossed — invoking on_fatal");
                f();
            }
        }
    }
}

fn log_transition(from: PressureLevel, to: PressureLevel, pct: f32, rss: u64, total: u64) {
    let rss_mb = rss / 1024 / 1024;
    let total_mb = total / 1024 / 1024;
    let pct_str = format!("{:.1}%", pct * 100.0);
    match to {
        PressureLevel::Ok => {
            tracing::info!(
                from = ?from, to = ?to,
                rss_mb, total_mb, pct = %pct_str,
                "runtime-guard: pressure relieved"
            );
        }
        PressureLevel::Warn => {
            warn!(
                from = ?from, to = ?to,
                rss_mb, total_mb, pct = %pct_str,
                "runtime-guard: WARN memory pressure"
            );
        }
        PressureLevel::Critical => {
            warn!(
                from = ?from, to = ?to,
                rss_mb, total_mb, pct = %pct_str,
                "runtime-guard: CRITICAL memory pressure"
            );
        }
        PressureLevel::Fatal => {
            tracing::error!(
                from = ?from, to = ?to,
                rss_mb, total_mb, pct = %pct_str,
                "runtime-guard: FATAL memory pressure — on_fatal will be called"
            );
        }
    }
}

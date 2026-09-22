//! End-to-end integration test of the Linux per-process enforcement WIRING:
//! `attribute` (/proc) → `PlaneEngine::resolve` (real policy) → `enforce`
//! (eBPF cgroup) — i.e. exactly what `LinuxFirewall::enforce_flow` does and what
//! a real TUN accept loop calls per new connection.
//!
//! Run in a PRIVILEGED container with cgroup2 mounted + outbound internet:
//!     linux_integration <kill|bypass>
//!
//! 1. open an outbound TCP connection so this process is attributable by src_port;
//! 2. drive `enforce_flow` with a real `PlaneEngine` policy (kill → wire down →
//!    Kill plane; bypass → Bypass plane);
//! 3. open a SECOND outbound connection → BLOCKED (kill) / ALLOWED (bypass).
//!
//! Expected: kill → BLOCKED, bypass → ALLOWED.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use mirage_tun_core::plane_engine::PlaneEngine;
use mirage_tun_core::policy::{
    CompiledPolicy, FailurePolicy, PolicyDecision, PolicyEngine, PolicyRule, WireClass,
};
use mirage_tun_core::traits::FlowProto;
use mirage_tun_core::wire_health::WireHealthMap;
use mirage_tun_linux::firewall::LinuxFirewall;

const TARGET: &str = "1.1.1.1:80";
const WIRE: &str = "w";

/// Build a real `PlaneEngine`: every destination routes to wire `w` (kill: wire
/// marked DOWN → resolve yields Kill via fail-closed) or to Bypass.
fn build_engine(kill: bool) -> PlaneEngine {
    let action = if kill {
        PolicyDecision::Chain(WIRE.to_string())
    } else {
        PolicyDecision::Bypass
    };
    let rules = vec![PolicyRule::DestCidr {
        cidr: "0.0.0.0/0".to_string(),
        action,
        failure_policy: FailurePolicy::FailClosed,
        wire_class: WireClass::default(),
    }];
    let policy = CompiledPolicy::compile(rules, PolicyDecision::default_chain());
    let engine = Arc::new(PolicyEngine::new(policy));
    let health = WireHealthMap::new();
    if kill {
        // Wire down → resolve() fail-closes the flow to Kill.
        health.record_failure(WIRE);
        health.record_failure(WIRE);
    }
    PlaneEngine::new(engine, health)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "kill".into());
    let kill = match arg.as_str() {
        "kill" => true,
        "bypass" => false,
        other => {
            eprintln!("use kill|bypass (got {other})");
            std::process::exit(2);
        }
    };
    let target: SocketAddr = TARGET.parse().unwrap();

    // Arm the per-process eBPF layer (no nft needed for this test).
    let mut fw = LinuxFirewall::detect(7300);
    if let Err(e) = fw.arm_ebpf(0) {
        eprintln!("arm_ebpf failed: {e}");
        std::process::exit(1);
    }
    let engine = build_engine(kill);

    // 1. first outbound connection — establishes a socket we can attribute by port.
    let conn1 = match TcpStream::connect_timeout(&target, Duration::from_secs(4)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pre-connect failed ({e}) — the container needs outbound internet");
            std::process::exit(1);
        }
    };
    let src_port = conn1.local_addr().unwrap().port();

    // 2. THE INTEGRATION: attribute (finds this pid via /proc) → resolve (real
    //    policy) → enforce (move pid to a dedicated cgroup + set the plane tag).
    if let Err(e) = fw
        .enforce_flow(&engine, src_port, target, FlowProto::Tcp, None)
        .await
    {
        eprintln!("enforce_flow failed: {e}");
        std::process::exit(1);
    }
    drop(conn1); // kept alive through attribution; release now.

    // 3. second outbound connection — now subject to the enforced plane.
    let outcome = match TcpStream::connect_timeout(&target, Duration::from_secs(4)) {
        Ok(_) => "ALLOWED",
        Err(_) => "BLOCKED",
    };
    println!("policy={arg} RESULT={outcome}");
}

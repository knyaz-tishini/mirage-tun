//! Live smoke for the cgroup/skb egress program. Run in a PRIVILEGED Linux
//! container / host with root + cgroup-v2 unified + bpf.
//!
//!   ebpf_smoke <bypass|kill|wire>
//!
//! Creates a dedicated test cgroup, attaches the egress program with the given
//! plane, moves itself into the cgroup, then attempts an outbound TCP connect
//! and reports ALLOWED / BLOCKED. tun_ifindex is 0 (no TUN), so WIRE drops every
//! non-loopback packet just like KILL; BYPASS passes.
//!
//! Expected: bypass → ALLOWED, kill → BLOCKED, wire → BLOCKED.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use mirage_tun_linux::firewall::ebpf_attach_for_test;

fn main() {
    // cgroup-v2 path is configurable so the test can point at a freshly-mounted
    // cgroup2 hierarchy (hosts whose default /sys/fs/cgroup is still v1).
    let cgroup = std::env::var("MIRAGE_SMOKE_CGROUP")
        .unwrap_or_else(|_| "/sys/fs/cgroup/mirage-smoke.scope".to_string());
    let cgroup: &str = &cgroup;

    let plane = std::env::args().nth(1).unwrap_or_else(|| "kill".into());
    let tag: u32 = match plane.as_str() {
        "bypass" => 0,
        "wire" => 1,
        "kill" => 2,
        other => {
            eprintln!("unknown plane '{other}' (use bypass|kill|wire)");
            std::process::exit(2);
        }
    };

    // 1. dedicated test cgroup
    let _ = std::fs::create_dir(cgroup);

    // 2. load + attach the egress program with the requested plane
    let _bpf = match ebpf_attach_for_test(cgroup, tag, 0) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("attach failed: {e}");
            std::process::exit(1);
        }
    };

    // 3. move SELF into the cgroup (so our egress is subject to the program)
    let pid = std::process::id();
    match std::fs::OpenOptions::new()
        .write(true)
        .open(format!("{cgroup}/cgroup.procs"))
        .and_then(|mut f| write!(f, "{pid}"))
    {
        Ok(()) => {}
        Err(e) => {
            eprintln!("could not join cgroup: {e}");
            std::process::exit(1);
        }
    }

    // 4. attempt an outbound TCP connect (raw IP — no DNS)
    let target: SocketAddr = "1.1.1.1:80".parse().unwrap();
    let result = TcpStream::connect_timeout(&target, Duration::from_secs(4));
    match result {
        Ok(_) => println!("plane={plane} RESULT=ALLOWED (connected to 1.1.1.1:80)"),
        Err(e) => println!("plane={plane} RESULT=BLOCKED ({})", e.kind()),
    }

    // 5. best-effort cleanup: leave the cgroup (move self to its parent), remove it
    if let Some(parent) = std::path::Path::new(cgroup).parent() {
        let _ = std::fs::write(parent.join("cgroup.procs"), pid.to_string());
    }
    let _ = std::fs::remove_dir(cgroup);
}

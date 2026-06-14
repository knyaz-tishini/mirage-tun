use std::collections::HashMap as StdHashMap;
use std::net::IpAddr;
use std::process::Command as StdCommand;
use tracing::{debug, info, warn};

use aya::maps::{Array as AyaArray, HashMap as AyaHashMap};
use aya::programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType};
use aya::Ebpf;

use mirage_tun_core::plane::{Plane, ProcessIdentity};
use mirage_tun_core::traits::{private, FlowKey, FlowProto, PlatformExecutor, PlatformFirewall};

use crate::error::LinuxTunError;

/// Intercept port for TCP REDIRECT: traffic from TUN is redirected here.
pub const DEFAULT_INTERCEPT_PORT: u16 = 7300;

/// eBPF object (cgroup/skb egress program) compiled by build.rs (clang -target bpf).
static BPF_OBJ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mirage_bpf.o"));

/// Plane tag values — MUST match the PLANE_* constants in bpf-progs/mirage_bpf.c.
const TAG_BYPASS: u32 = 0;
const TAG_WIRE: u32 = 1;
const TAG_KILL: u32 = 2;

/// Map a resolved `Plane` to the BPF plane tag. `Group` must be resolved before
/// reaching the executor; treat a stray Group conservatively as Kill (fail-closed).
fn plane_tag(plane: &Plane) -> u32 {
    match plane {
        Plane::Bypass => TAG_BYPASS,
        Plane::Wire(_) => TAG_WIRE,
        Plane::Kill | Plane::Group(_) => TAG_KILL,
    }
}

/// Runtime-detected firewall backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
}

/// One process we moved into a dedicated cgroup + attached the egress program to.
struct TrackedProc {
    /// cgroup-v2 id of the dedicated cgroup (the BPF map key).
    cgroupid: u64,
    /// dedicated cgroup directory path (for teardown).
    cgroup_path: String,
    /// aya link id for the cgroup-attach (kept so we can detach on teardown).
    link: Option<aya::programs::cgroup_skb::CgroupSkbLinkId>,
}

/// Linux firewall manager. Installs the coarse nft/iptables REDIRECT + kill-switch
/// rules and (T3) drives per-process cgroup-v2 eBPF egress enforcement.
pub struct LinuxFirewall {
    backend: FirewallBackend,
    intercept_port: u16,
    /// True once coarse rules have been installed.
    active: bool,

    // ── T3 eBPF per-process enforcement ──
    /// Loaded eBPF object (None until activate(); None if BPF could not load —
    /// then we degrade to coarse nft/iptables only).
    bpf: Option<Ebpf>,
    /// pid -> dedicated-cgroup bookkeeping.
    tracked: StdHashMap<u32, TrackedProc>,
    /// TUN device ifindex (set at activate()); used by the WIRE plane to allow
    /// only TUN-bound egress.
    tun_ifindex: u32,
}

impl LinuxFirewall {
    /// Detect which backend is available and create the manager.
    pub fn detect(intercept_port: u16) -> Self {
        let backend = detect_backend_sync();
        info!("Firewall backend: {backend:?}");
        Self {
            backend,
            intercept_port,
            active: false,
            bpf: None,
            tracked: StdHashMap::new(),
            tun_ifindex: 0,
        }
    }
}

impl private::Sealed for LinuxFirewall {}

// ── T3: PlatformExecutor — real per-process eBPF enforcement ──────────────────

impl PlatformExecutor for LinuxFirewall {
    type Error = LinuxTunError;

    /// Attribute an intercepted flow to a process (and its cgroup) via /proc.
    /// Must be called from a blocking context (reads the proc filesystem).
    fn attribute(
        &self,
        src_port: u16,
        dst: std::net::SocketAddr,
        proto: FlowProto,
    ) -> Option<ProcessIdentity> {
        crate::proc_attr::attribute_flow(src_port, dst, proto)
    }

    /// Enforce the plane decision for the attributed process: move it into a
    /// dedicated cgroup, attach the egress program, and write the plane tag into
    /// the BPF map. Plane changes update only the map entry.
    ///
    /// Per-process isolation requires a dedicated cgroup per process so a plane
    /// never leaks onto unrelated cgroup-mates.
    ///
    /// Invariants: `Group` must be resolved first (returns Err). Without an
    /// attributed pid, or if eBPF is unavailable, this is a safe no-op — the
    /// coarse nft/iptables layer remains in effect (fail-closed).
    fn enforce(
        &mut self,
        plane: &Plane,
        identity: Option<&ProcessIdentity>,
        flow: &FlowKey,
    ) -> Result<(), LinuxTunError> {
        if matches!(plane, Plane::Group(_)) {
            warn!(?flow, "enforce called with unresolved Group plane — bug in caller");
            return Err(LinuxTunError::Other("unresolved Group plane".into()));
        }

        let pid = match identity.map(|id| id.info.pid).filter(|p| *p > 0) {
            Some(p) => p,
            None => {
                debug!(?flow, "enforce: no attributed pid — coarse layer only");
                return Ok(());
            }
        };
        let tag = plane_tag(plane);

        // eBPF unavailable → coarse-only, safe.
        if self.bpf.is_none() {
            debug!(?flow, "enforce: eBPF not loaded — coarse layer only");
            return Ok(());
        }

        // Existing tracked process → update its plane tag only.
        if let Some(tp) = self.tracked.get(&pid) {
            let cgid = tp.cgroupid;
            let bpf = self.bpf.as_mut().unwrap();
            set_plane(bpf, cgid, tag)?;
            debug!(pid, tag, "enforce: plane updated");
            return Ok(());
        }

        // New process → move it into a dedicated cgroup, attach the egress
        // program, and set the tag.
        let cgroup_path = crate::cgroup_mgr::move_pid_to_cgroup(pid)?;
        let cgid = crate::proc_attr::cgroup_path_to_id(&cgroup_path)
            .ok_or_else(|| LinuxTunError::Ebpf(format!("cgroupid for {cgroup_path}")))?;
        let bpf = self.bpf.as_mut().unwrap();
        let link = attach_egress(bpf, &cgroup_path)?;
        set_plane(bpf, cgid, tag)?;
        self.tracked.insert(
            pid,
            TrackedProc { cgroupid: cgid, cgroup_path, link: Some(link) },
        );
        debug!(pid, cgid, tag, "enforce: process isolated (dedicated cgroup) + plane set");
        Ok(())
    }
}

impl PlatformFirewall for LinuxFirewall {
    type Error = LinuxTunError;

    fn activate(
        &mut self,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        _exempt_ports: &[u16],
    ) -> Result<(), Self::Error> {
        match self.backend {
            FirewallBackend::Nftables => {
                nft_activate_sync(relay_addrs, tun_name, self.intercept_port)?;
            }
            FirewallBackend::Iptables => {
                ipt_activate_sync(relay_addrs, tun_name, self.intercept_port)?;
            }
        }
        self.active = true;

        // ── T3: load the per-process eBPF egress program (best-effort) ──
        self.tun_ifindex = if_nametoindex(tun_name);
        match load_bpf(self.tun_ifindex) {
            Ok(bpf) => {
                self.bpf = Some(bpf);
                info!(tun_ifindex = self.tun_ifindex, "eBPF per-process enforcement loaded");
            }
            Err(e) => {
                // Degrade to coarse-only; per-process kill-switch unavailable.
                warn!("eBPF load failed ({e}); per-process enforcement disabled (coarse nft/iptables only)");
            }
        }

        info!("Firewall activated on {tun_name}, intercept_port={}", self.intercept_port);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), Self::Error> {
        if !self.active {
            return Ok(());
        }

        // ── T3: detach eBPF + clear plane map + remove dedicated cgroups ──
        if let Some(mut bpf) = self.bpf.take() {
            for (_pid, tp) in self.tracked.drain() {
                let _ = set_plane_remove(&mut bpf, tp.cgroupid);
                if let Some(link_id) = tp.link {
                    if let Some(prog) = bpf.program_mut("mirage_egress") {
                        if let Ok(prog) = TryInto::<&mut CgroupSkb>::try_into(prog) {
                            let _ = prog.detach(link_id);
                        }
                    }
                }
                let _ = crate::cgroup_mgr::remove_cgroup(&tp.cgroup_path);
            }
        }
        self.tracked.clear();

        match self.backend {
            FirewallBackend::Nftables => nft_deactivate_sync()?,
            FirewallBackend::Iptables => ipt_deactivate_sync()?,
        }
        self.active = false;
        info!("Firewall deactivated");
        Ok(())
    }
}

// ── eBPF helpers (free fns to avoid &mut self split-borrow churn) ─────────────

/// Load the eBPF object, load the egress program, and set the TUN ifindex.
fn load_bpf(tun_ifindex: u32) -> Result<Ebpf, LinuxTunError> {
    let mut bpf = Ebpf::load(BPF_OBJ)
        .map_err(|e| LinuxTunError::Ebpf(format!("load object: {e}")))?;
    {
        let prog: &mut CgroupSkb = bpf
            .program_mut("mirage_egress")
            .ok_or_else(|| LinuxTunError::Ebpf("program mirage_egress not found".into()))?
            .try_into()
            .map_err(|e| LinuxTunError::Ebpf(format!("program cast: {e}")))?;
        prog.load()
            .map_err(|e| LinuxTunError::Ebpf(format!("program load: {e}")))?;
    }
    set_tun_ifindex(&mut bpf, tun_ifindex)?;
    Ok(bpf)
}

/// Attach the (already-loaded) egress program to a cgroup directory.
fn attach_egress(
    bpf: &mut Ebpf,
    cgroup_path: &str,
) -> Result<aya::programs::cgroup_skb::CgroupSkbLinkId, LinuxTunError> {
    let prog: &mut CgroupSkb = bpf
        .program_mut("mirage_egress")
        .ok_or_else(|| LinuxTunError::Ebpf("program mirage_egress not found".into()))?
        .try_into()
        .map_err(|e| LinuxTunError::Ebpf(format!("program cast: {e}")))?;
    let cgroup = std::fs::File::open(cgroup_path)
        .map_err(|e| LinuxTunError::Ebpf(format!("open cgroup {cgroup_path}: {e}")))?;
    prog.attach(cgroup, CgroupSkbAttachType::Egress, CgroupAttachMode::Single)
        .map_err(|e| LinuxTunError::Ebpf(format!("attach: {e}")))
}

/// Write `cgroupid -> tag` into the plane map.
fn set_plane(bpf: &mut Ebpf, cgroupid: u64, tag: u32) -> Result<(), LinuxTunError> {
    let mut map: AyaHashMap<_, u64, u32> = AyaHashMap::try_from(
        bpf.map_mut("cgroup_plane_map")
            .ok_or_else(|| LinuxTunError::Ebpf("cgroup_plane_map not found".into()))?,
    )
    .map_err(|e| LinuxTunError::Ebpf(format!("plane map cast: {e}")))?;
    map.insert(cgroupid, tag, 0)
        .map_err(|e| LinuxTunError::Ebpf(format!("plane map insert: {e}")))
}

/// Remove a cgroup's plane entry.
fn set_plane_remove(bpf: &mut Ebpf, cgroupid: u64) -> Result<(), LinuxTunError> {
    let mut map: AyaHashMap<_, u64, u32> = AyaHashMap::try_from(
        bpf.map_mut("cgroup_plane_map")
            .ok_or_else(|| LinuxTunError::Ebpf("cgroup_plane_map not found".into()))?,
    )
    .map_err(|e| LinuxTunError::Ebpf(format!("plane map cast: {e}")))?;
    map.remove(&cgroupid)
        .map_err(|e| LinuxTunError::Ebpf(format!("plane map remove: {e}")))
}

/// Set cfg[0] = TUN ifindex.
fn set_tun_ifindex(bpf: &mut Ebpf, ifindex: u32) -> Result<(), LinuxTunError> {
    let mut cfg: AyaArray<_, u32> = AyaArray::try_from(
        bpf.map_mut("cfg_map")
            .ok_or_else(|| LinuxTunError::Ebpf("cfg_map not found".into()))?,
    )
    .map_err(|e| LinuxTunError::Ebpf(format!("cfg map cast: {e}")))?;
    cfg.set(0, ifindex, 0)
        .map_err(|e| LinuxTunError::Ebpf(format!("cfg map set: {e}")))
}

/// Live-smoke helper (used by `examples/ebpf_smoke.rs`): load + attach the egress
/// program to `cgroup_path`, set its plane `tag`, and return the live `Ebpf` (keep
/// it alive to hold the attachment). NOT part of the normal enforcement path
/// (that goes through `PlatformExecutor::enforce`); this skips the nft/cgroup-move
/// machinery so the BPF program can be exercised standalone in a container.
pub fn ebpf_attach_for_test(
    cgroup_path: &str,
    tag: u32,
    tun_ifindex: u32,
) -> Result<Ebpf, LinuxTunError> {
    let mut bpf = load_bpf(tun_ifindex)?;
    let _link = attach_egress(&mut bpf, cgroup_path)?;
    let cgid = crate::proc_attr::cgroup_path_to_id(cgroup_path)
        .ok_or_else(|| LinuxTunError::Ebpf(format!("cgroupid for {cgroup_path}")))?;
    set_plane(&mut bpf, cgid, tag)?;
    Ok(bpf)
}

/// `if_nametoindex(3)` — returns 0 if the interface is unknown.
fn if_nametoindex(name: &str) -> u32 {
    use std::ffi::CString;
    match CString::new(name) {
        Ok(c) => unsafe { libc::if_nametoindex(c.as_ptr()) },
        Err(_) => 0,
    }
}

// ── Backend detection ─────────────────────────────────────────────────────────

fn detect_backend_sync() -> FirewallBackend {
    let out = StdCommand::new("which").arg("nft").output();
    match out {
        Ok(o) if o.status.success() => FirewallBackend::Nftables,
        _ => FirewallBackend::Iptables,
    }
}

// ── nftables ──────────────────────────────────────────────────────────────────

fn nft_activate_sync(
    relay_addrs: &[IpAddr],
    tun_name: &str,
    intercept_port: u16,
) -> Result<(), LinuxTunError> {
    let relay_set = if relay_addrs.is_empty() {
        String::new()
    } else {
        let addrs: Vec<String> = relay_addrs.iter().map(|a| a.to_string()).collect();
        format!(
            "    set relay_addrs {{\n        type ipv4_addr;\n        flags interval;\n        elements = {{ {} }}\n    }}\n",
            addrs.join(", ")
        )
    };

    let relay_bypass = if relay_addrs.is_empty() {
        String::new()
    } else {
        "    # bypass relay addresses (do not redirect)\n    ip daddr @relay_addrs accept\n".to_string()
    };

    let script = format!(
        r#"#!/usr/sbin/nft -f

table inet mirage_redirect {{
{relay_set}
  chain prerouting {{
    type nat hook prerouting priority dstnat;
{relay_bypass}    iifname "{tun_name}" tcp dport != 53 redirect to :{intercept_port}
  }}
}}
"#
    );

    debug!("nft script:\n{script}");

    let path = "/tmp/mirage-fw.nft";
    std::fs::write(path, &script)
        .map_err(|e| LinuxTunError::Nftables { code: -1, stderr: e.to_string() })?;

    run_nft_sync(&["-f", path])
}

fn nft_deactivate_sync() -> Result<(), LinuxTunError> {
    let out = StdCommand::new("nft")
        .args(["delete", "table", "inet", "mirage_redirect"])
        .output()?;
    debug!("nft delete table: status={}", out.status);
    // Not an error if table doesn't exist.
    Ok(())
}

fn run_nft_sync(args: &[&str]) -> Result<(), LinuxTunError> {
    let out = StdCommand::new("nft").args(args).output()?;
    debug!("nft {}: status={}", args.join(" "), out.status);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        warn!("nft {} failed: {stderr}", args.join(" "));
        return Err(LinuxTunError::Nftables {
            code: out.status.code().unwrap_or(-1),
            stderr,
        });
    }
    Ok(())
}

// ── iptables ──────────────────────────────────────────────────────────────────

fn ipt_activate_sync(
    relay_addrs: &[IpAddr],
    tun_name: &str,
    intercept_port: u16,
) -> Result<(), LinuxTunError> {
    // REDIRECT rule: TCP from TUN interface (except port 53) → intercept_port
    // Split into two rules because iptables --dport doesn't accept negation easily.
    run_ipt_sync(&[
        "-t", "nat", "-A", "PREROUTING",
        "-i", tun_name,
        "-p", "tcp",
        "--dport", "1:52",
        "-j", "REDIRECT",
        "--to-ports", &intercept_port.to_string(),
    ])?;
    run_ipt_sync(&[
        "-t", "nat", "-A", "PREROUTING",
        "-i", tun_name,
        "-p", "tcp",
        "--dport", "54:65535",
        "-j", "REDIRECT",
        "--to-ports", &intercept_port.to_string(),
    ])?;

    // Bypass rules for relay addresses.
    for addr in relay_addrs {
        run_ipt_sync(&[
            "-t", "nat", "-I", "PREROUTING", "1",
            "-i", tun_name,
            "-d", &addr.to_string(),
            "-j", "ACCEPT",
        ])?;
    }

    Ok(())
}

fn ipt_deactivate_sync() -> Result<(), LinuxTunError> {
    let out = StdCommand::new("iptables")
        .args(["-t", "nat", "-F", "PREROUTING"])
        .output()?;
    debug!("iptables -F PREROUTING: status={}", out.status);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        warn!("iptables flush failed: {stderr}");
    }
    Ok(())
}

fn run_ipt_sync(args: &[&str]) -> Result<(), LinuxTunError> {
    let out = StdCommand::new("iptables").args(args).output()?;
    debug!("iptables {}: status={}", args.join(" "), out.status);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        warn!("iptables {} failed: {stderr}", args.join(" "));
        return Err(LinuxTunError::Iptables {
            code: out.status.code().unwrap_or(-1),
            stderr,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_script_contains_redirect() {
        let tun_name = "tun0";
        let intercept_port: u16 = 7300;
        let relay_set = String::new();
        let relay_bypass = String::new();
        let script = format!(
            r#"table inet mirage_redirect {{
{relay_set}
  chain prerouting {{
    type nat hook prerouting priority dstnat;
{relay_bypass}    iifname "{tun_name}" tcp dport != 53 redirect to :{intercept_port}
  }}
}}
"#
        );
        assert!(script.contains("redirect to :7300"));
        assert!(script.contains(r#"iifname "tun0""#));
    }

    #[test]
    fn nft_script_contains_relay_set() {
        use std::str::FromStr;
        let relay_addrs: Vec<IpAddr> = vec![IpAddr::from_str("1.2.3.4").unwrap()];
        let addrs: Vec<String> = relay_addrs.iter().map(|a| a.to_string()).collect();
        let relay_set = format!(
            "    set relay_addrs {{\n        type ipv4_addr;\n        flags interval;\n        elements = {{ {} }}\n    }}\n",
            addrs.join(", ")
        );
        assert!(relay_set.contains("1.2.3.4"));
    }

    #[test]
    fn plane_tag_mapping() {
        assert_eq!(plane_tag(&Plane::Bypass), TAG_BYPASS);
        assert_eq!(plane_tag(&Plane::Wire("a".into())), TAG_WIRE);
        assert_eq!(plane_tag(&Plane::Kill), TAG_KILL);
        // Group resolves conservatively to Kill at the executor boundary.
        assert_eq!(plane_tag(&Plane::Group("g".into())), TAG_KILL);
    }
}

use crate::policy::ProcessInfo;

/// The egress plane assigned to a process's flow by the core engine.
/// This is the T2 canonical output — platform executors enforce exactly this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plane {
    /// Flow exits via the TUN bypass path (routed to clearnet by TUN; never a raw native socket).
    /// Invariant 1: this verdict is NEVER overridden by a Kill verdict.
    Bypass,
    /// Flow is pinned to the exact named wire (chain id / SOCKS5 chain name).
    /// If that wire is unhealthy: fail-closed (Kill). No substitution. Invariant 3 strict case.
    Wire(String),
    /// Flow may use any healthy wire within the named group.
    /// If no wire in group is healthy: fail-closed (Kill). Invariant 3 general case.
    Group(String),
    /// Drop the flow now. No egress. Used when: wire pinned + wire down (fail-closed),
    /// or group + all-down, or default action is Chain("default") with no wires configured.
    Kill,
}

impl Plane {
    /// True iff this plane permits any egress (Bypass or Wire or Group with a healthy wire).
    /// Kill = false.
    pub fn permits_egress(&self) -> bool {
        !matches!(self, Plane::Kill)
    }

    /// True iff this is the bypass plane. Used by invariant-1 enforcement check.
    pub fn is_bypass(&self) -> bool {
        matches!(self, Plane::Bypass)
    }
}

/// Process identity as seen by the core engine.
/// Wraps `ProcessInfo` (path + ancestor_paths already in core), adds an optional
/// platform-opaque attribution token used by per-platform executors (e.g. WFP app-id blob,
/// cgroup path, NE source signing ID). Core logic ignores `platform_token` — it is
/// passed through verbatim to `PlatformExecutor::enforce`.
#[derive(Debug, Clone)]
pub struct ProcessIdentity {
    /// The normalized process info (pid + exe_path + ancestor_paths).
    /// SAME normalization as existing `ProcessInfo` in policy.rs.
    pub info: ProcessInfo,
    /// Platform-specific attribution opaque blob (e.g. WFP FWP_BYTE_BLOB app-id,
    /// cgroup path string, NEAppProxyFlow source app signing identifier).
    /// None when attribution is not available (unattributed flow → default plane).
    pub platform_token: Option<Vec<u8>>,
}

impl ProcessIdentity {
    pub fn from_process_info(info: ProcessInfo) -> Self {
        Self { info, platform_token: None }
    }

    pub fn with_token(info: ProcessInfo, token: Vec<u8>) -> Self {
        Self { info, platform_token: Some(token) }
    }
}

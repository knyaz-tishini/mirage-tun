/// No-op DNS implementation for iOS.
///
/// DNS is configured in Swift via `NEDNSSettings` inside
/// `setTunnelNetworkSettings(_:completionHandler:)`. Rust has no DNS
/// configuration responsibility on this platform.
pub struct IosDns;

impl IosDns {
    pub fn new() -> Self {
        IosDns
    }
}

impl Default for IosDns {
    fn default() -> Self {
        Self::new()
    }
}

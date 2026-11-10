use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    #[serde(default = "default_api_bind")]
    pub api_bind: SocketAddr,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_tun_addr")]
    pub tun_addr: String,
    /// Optional IPv6 address for the TUN interface (e.g. "fd00:7::2/64").
    /// None = v4-only (backward-compat default).
    #[serde(default)]
    pub tun_addr_v6: Option<String>,
    /// Optional IPv6 address for the TUN interface, in CIDR form.
    ///
    /// This is the canonical name; [`TunConfig::tun_addr_v6`] is the older
    /// spelling and is still honoured.  When neither is set, the address is
    /// derived from `tun_addr` by [`derive_ipv6_addr`].
    #[serde(default)]
    pub ipv6_addr: Option<String>,
    #[serde(default = "default_dns_upstream")]
    pub dns_upstream: SocketAddr,
    #[serde(default = "default_dns_cache_ttl_secs")]
    pub dns_cache_ttl_secs: u64,
    #[serde(default = "default_dns_cache_max")]
    pub dns_cache_max: usize,
    #[serde(default = "default_dns_concurrency")]
    pub dns_concurrency: usize,
    #[serde(default = "default_socks5_concurrency")]
    pub socks5_concurrency: usize,
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,
    /// Optional: URL of mirage2monitor to pull chain config from.
    /// When set, mirage2tun spawns an internal MonitorLink and updates the
    /// chain registry automatically — no mirage2app required.
    /// Example: `"http://127.0.0.1:19410"`
    #[serde(default)]
    pub monitor_url: Option<String>,
    /// Optional Bearer token sent to the monitor on every request.
    #[serde(default)]
    pub monitor_api_key: Option<String>,
    /// Optional Bearer token required on all mutating control-API routes.
    ///
    /// When `Some`, every request to a guarded route must carry
    /// `Authorization: Bearer <api_key>`.  `/health` is always open.
    /// When `None` (default), the API is unauthenticated and a one-time
    /// warning is emitted at startup.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Per-connection TCP send buffer size inside smoltcp (bytes).
    /// Default: 524288 (512 KB).
    #[serde(default = "default_tcp_send_buffer_size")]
    pub tcp_send_buffer_size: u32,
    /// Per-connection TCP recv buffer size inside smoltcp (bytes).
    /// Default: 524288 (512 KB).
    #[serde(default = "default_tcp_recv_buffer_size")]
    pub tcp_recv_buffer_size: u32,
    /// Pinned bypass (direct-egress) DNS resolver.
    ///
    /// When set, `discover_native_dns` is skipped entirely and this address is used
    /// for all `dns_via_native` calls.  Useful when the native resolver is known
    /// (e.g. a LAN DNS server) and DHCP renewal would otherwise stale the
    /// auto-discovered value.  `None` (default) = discover at `/tun/start`.
    #[serde(default)]
    pub direct_dns: Option<SocketAddr>,
    /// Wintun tunnel-type string visible in Device Manager.
    ///
    /// Defaults to `"Mirage"`.  Configurable so the adapter type name can be
    /// set to a less distinctive string at deploy time.
    #[serde(default = "default_tunnel_type")]
    pub tunnel_type: String,
    /// Datapath mode.
    ///
    /// `"stack"` (default) terminates TCP/UDP in userspace and hands byte
    /// streams to the client over a SOCKS5 proxy.  `"raw_ip"` forwards whole
    /// IP packets to the client: the client tunnels them over QUIC and the
    /// box is a plain L3 forwarder.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Adapter MTU in bytes.
    ///
    /// Applied to the Wintun interface with `netsh`.  In raw-IP mode a
    /// packet larger than this is dropped - it cannot fit into a QUIC
    /// datagram on the far side.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Direct-egress bypass list.
    ///
    /// The destinations the person excluded from the tunnel.  In the raw-IP
    /// mode the box is a full L3 exit, so the exclusion is not a rule in the
    /// datapath: it is a HOLE in the routing, drilled through the gateway
    /// the machine had before the tunnel took the default.
    #[serde(default)]
    pub bypass: BypassConfig,
    /// How often the excluded names are resolved again, in seconds.
    ///
    /// The addresses of a CDN change under it, so the holes follow the
    /// names: the longer this is, the longer a name may point at an address
    /// that has no hole.
    #[serde(default = "default_bypass_refresh_secs")]
    pub bypass_refresh_secs: u64,
    /// The applications that leave the tunnel.
    ///
    /// The bypass above is about DESTINATIONS; this is about APPLICATIONS:
    /// the listed images keep using the physical interface while everything
    /// else goes through the tunnel.  It needs the Mullvad split-tunnel
    /// driver (`mullvad-split-tunnel.sys`), which must be installed and
    /// running; without it the list is ignored.
    ///
    /// Each entry is an image name (`node.exe`) or a full path.
    #[serde(default)]
    pub split_tunnel_apps: Vec<String>,
    /// The policy, as it was written into tun.json.
    ///
    /// The device reads the application rules from it: an application that
    /// the policy sends around the tunnel should leave the tunnel BY
    /// APPLICATION, not only by network.  Whoever writes tun.json may or may
    /// not fill in `split_tunnel_apps`; the policy is the fallback.
    #[serde(default)]
    pub policy: Option<mirage_tun_core::policy::PolicyConfigRequest>,
}

/// Direct-egress bypass list (`bypass` object in tun.json).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BypassConfig {
    /// CIDRs that must not enter the tunnel.
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// Domains that must not enter the tunnel.
    #[serde(default)]
    pub domains: Vec<String>,
}

fn default_api_bind() -> SocketAddr {
    "127.0.0.1:19485".parse().expect("static addr is valid")
}

fn default_tun_name() -> String {
    "mirage0".to_owned()
}

fn default_tun_addr() -> String {
    "10.0.85.1/24".to_owned()
}

fn default_dns_upstream() -> SocketAddr {
    "8.8.8.8:53".parse().expect("static addr is valid")
}

fn default_bypass_refresh_secs() -> u64 {
    // The addresses of a CDN live under a short TTL -- the ones we watch
    // answer in seconds.  A hole that follows a name has to follow it
    // faster than the name changes.
    10
}

fn default_dns_cache_ttl_secs() -> u64 {
    60
}

fn default_dns_cache_max() -> usize {
    1024
}

fn default_dns_concurrency() -> usize {
    8
}

fn default_socks5_concurrency() -> usize {
    100
}

fn default_drain_timeout_secs() -> u64 {
    5
}

fn default_tcp_send_buffer_size() -> u32 {
    mirage_tcpip_stack::tcp::DEFAULT_TCP_SEND_BUFFER_SIZE
}

fn default_tcp_recv_buffer_size() -> u32 {
    mirage_tcpip_stack::tcp::DEFAULT_TCP_RECV_BUFFER_SIZE
}

fn default_tunnel_type() -> String {
    "Mirage".to_owned()
}

fn default_mode() -> String {
    "stack".to_owned()
}

fn default_mtu() -> u16 {
    1500
}

/// The IPv6 prefix of the tunnel network: `fd77::/64`.
///
/// The tunnel carries whole IP packets, so the client gets an address in
/// this network and the box masquerades it (NAT66) towards the internet.
///
/// The prefix is a NAME here: the address is written by [`Ipv6Addr`], so
/// the last group is hex, exactly as IPv6 writes it.
pub const IPV6_PREFIX: &str = "fd77::";

/// The prefix length of the tunnel's IPv6 network.
pub const IPV6_PREFIX_LEN: u8 = 64;

/// Derive the IPv6 address of the tunnel from its IPv4 address.
///
/// The rule is fixed and shared with the box side: the IPv4 address
/// `10.77.0.N` becomes the IPv6 address `fd77::N/64`.  The last octet of
/// the IPv4 address is the host number; everything else is fixed.
///
/// Returns `None` when `tun_addr` is not a usable IPv4 address in CIDR
/// form, or when its host number does not fit the rule.
pub fn derive_ipv6_addr(tun_addr: &str) -> Option<String> {
    let (addr_str, prefix_str) = tun_addr.split_once('/')?;
    // The IPv4 side must be a well-formed CIDR: the prefix is not used, but
    // an address the adapter cannot take has no derived address either.
    let prefix: u8 = prefix_str.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let v4: Ipv4Addr = addr_str.trim().parse().ok()?;
    let octets = v4.octets();
    // The rule only covers the tunnel's own IPv4 network 10.77.0.0/24.
    if octets[0] != 10 || octets[1] != 77 || octets[2] != 0 {
        return None;
    }
    let host = octets[3];
    // 10.77.0.0 (network) and 10.77.0.255 (broadcast) are not hosts.
    if host == 0 || host == 255 {
        return None;
    }
    // The host number becomes the LAST GROUP of the IPv6 address, and the
    // address is written the way IPv6 writes it -- in hex. The box computes
    // the same address the same way, so the two ends agree without telling
    // each other anything: "10.77.0.10" is "fd77::a", NOT "fd77::10".
    let address = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, u16::from(host));
    Some(format!("{address}/{IPV6_PREFIX_LEN}"))
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            api_bind: default_api_bind(),
            tun_name: default_tun_name(),
            tun_addr: default_tun_addr(),
            tun_addr_v6: None,
            ipv6_addr: None,
            dns_upstream: default_dns_upstream(),
            dns_cache_ttl_secs: default_dns_cache_ttl_secs(),
            dns_cache_max: default_dns_cache_max(),
            dns_concurrency: default_dns_concurrency(),
            socks5_concurrency: default_socks5_concurrency(),
            drain_timeout_secs: default_drain_timeout_secs(),
            split_tunnel_apps: Vec::new(),
            policy: None,
            monitor_url: None,
            monitor_api_key: None,
            api_key: None,
            tcp_send_buffer_size: default_tcp_send_buffer_size(),
            tcp_recv_buffer_size: default_tcp_recv_buffer_size(),
            direct_dns: None,
            tunnel_type: default_tunnel_type(),
            mode: default_mode(),
            mtu: default_mtu(),
            bypass: BypassConfig::default(),
            bypass_refresh_secs: default_bypass_refresh_secs(),
        }
    }
}

impl TunConfig {
    /// True when the raw-IP datapath is selected.
    pub fn is_raw_ip(&self) -> bool {
        self.mode.eq_ignore_ascii_case("raw_ip")
    }

    /// The IPv6 address the TUN interface must carry, if any.
    ///
    /// The explicit [`TunConfig::ipv6_addr`] wins, then the legacy
    /// [`TunConfig::tun_addr_v6`], and finally the address derived from
    /// `tun_addr` by [`derive_ipv6_addr`].  `None` means the adapter stays
    /// IPv4-only.
    pub fn effective_ipv6_addr(&self) -> Option<String> {
        self.ipv6_addr
            .clone()
            .or_else(|| self.tun_addr_v6.clone())
            .or_else(|| derive_ipv6_addr(&self.tun_addr))
    }

    /// Load from a JSON object that may contain a `"config"` key.
    /// If the file is absent or the key is missing, defaults are used.
    pub fn load_from_tun_json(path: &std::path::Path) -> Self {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(&contents) else {
            return Self::default();
        };
        // Support both top-level config fields and a nested `"config"` object.
        let cfg_value = obj.get("config").cloned().unwrap_or(obj);
        serde_json::from_value(cfg_value).unwrap_or_default()
    }
}

// --- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tunnel_address_becomes_fd77() {
        assert_eq!(
            derive_ipv6_addr("10.77.0.7/24").as_deref(),
            Some("fd77::7/64")
        );
        assert_eq!(
            derive_ipv6_addr("10.77.0.2/24").as_deref(),
            Some("fd77::2/64")
        );
        // The box's own address follows the same rule.
        assert_eq!(
            derive_ipv6_addr("10.77.0.254/24").as_deref(),
            Some("fd77::fe/64")
        );
    }

    /// The last group of an IPv6 address is hex, not decimal: the client
    /// and the box must write the SAME address, or the box drops the
    /// client's IPv6 packets as coming from a stranger.
    #[test]
    fn the_host_number_is_written_in_hex() {
        assert_eq!(
            derive_ipv6_addr("10.77.0.10/24").as_deref(),
            Some("fd77::a/64")
        );
        assert_eq!(
            derive_ipv6_addr("10.77.0.16/24").as_deref(),
            Some("fd77::10/64")
        );
        assert_eq!(
            derive_ipv6_addr("10.77.0.253/24").as_deref(),
            Some("fd77::fd/64")
        );
    }

    #[test]
    fn an_address_outside_the_tunnel_network_derives_nothing() {
        assert_eq!(derive_ipv6_addr("10.0.85.1/24"), None);
        assert_eq!(derive_ipv6_addr("192.168.1.5/24"), None);
        assert_eq!(derive_ipv6_addr("fd00::1/64"), None);
    }

    #[test]
    fn a_malformed_address_derives_nothing() {
        assert_eq!(derive_ipv6_addr(""), None);
        assert_eq!(derive_ipv6_addr("10.77.0.7"), None);
        assert_eq!(derive_ipv6_addr("not-an-address/24"), None);
        assert_eq!(derive_ipv6_addr("10.77.0.7/"), None);
        assert_eq!(derive_ipv6_addr("10.77.0.7/x"), None);
        assert_eq!(derive_ipv6_addr("10.77.0.7/64"), None);
    }

    #[test]
    fn the_network_and_broadcast_addresses_derive_nothing() {
        assert_eq!(derive_ipv6_addr("10.77.0.0/24"), None);
        assert_eq!(derive_ipv6_addr("10.77.0.255/24"), None);
    }

    #[test]
    fn the_explicit_address_wins_over_the_derived_one() {
        let mut cfg = TunConfig {
            tun_addr: "10.77.0.7/24".to_owned(),
            ..Default::default()
        };
        // With nothing set the address is derived.
        assert_eq!(cfg.effective_ipv6_addr().as_deref(), Some("fd77::7/64"));

        // An explicit address wins.
        cfg.ipv6_addr = Some("fd77::99/64".to_owned());
        assert_eq!(cfg.effective_ipv6_addr().as_deref(), Some("fd77::99/64"));
    }

    #[test]
    fn the_legacy_field_is_still_honoured() {
        let cfg = TunConfig {
            tun_addr: "10.77.0.7/24".to_owned(),
            tun_addr_v6: Some("fd00:7::2/64".to_owned()),
            ..Default::default()
        };
        assert_eq!(cfg.effective_ipv6_addr().as_deref(), Some("fd00:7::2/64"));
    }
}

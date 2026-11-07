use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use async_trait::async_trait;
use crate::error::TunError;
use crate::stack_config::StackConfig;

// ── Sealed trait boilerplate ──────────────────────────────────────────────────
//
// `pub` so platform crates can add `impl private::Sealed for MyType {}`.
// The module is intentionally not re-exported at crate root — callers must
// name it explicitly as `mirage_tun_core::traits::private::Sealed`.

pub mod private {
    pub trait Sealed {}
}

// ── TunDevice: L3 packet I/O ──────────────────────────────────────────────────

/// Raw IP packet read/write. Each platform implements this once.
/// Platform crates own the concrete type; core owns the trait.
#[async_trait]
pub trait TunDevice: Send + Sync + private::Sealed {
    /// Interface name as assigned by the OS (e.g. "utun3", "tun0", "mirage0").
    fn name(&self) -> &str;

    /// Bring the interface up with `addr` (CIDR notation) and `mtu`.
    /// Idempotent — may be called again after a network change.
    async fn configure(&mut self, addr: &str, mtu: u16) -> Result<(), TunError>;

    /// Close the interface. Called on graceful stop.
    async fn close(self) -> Result<(), TunError>;
}

// ── TcpAcceptor / UdpSocket: stack-level types returned by TunStack ──────────

/// Yields accepted TCP streams, each tagged with (local_addr, peer_addr).
/// On smoltcp platforms: backed by mirage_tcpip_stack::TcpListener.
/// On kernel platforms: backed by tokio::net::TcpListener bound to TUN addr.
#[async_trait]
pub trait TcpAcceptor: Send + 'static {
    /// Wait for the next incoming TCP connection from a device app.
    async fn accept(&mut self) -> Option<(TcpStream, SocketAddr, SocketAddr)>;
}

/// Yields incoming UDP datagrams (payload, src, dst).
/// Sending a response: call `send(payload, dst, src)`.
#[async_trait]
pub trait UdpSocket: Send + 'static {
    async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)>;
    async fn send(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), TunError>;
}

// ── TunStack: the single type the consumer instantiates ──────────────────────

/// Platform-agnostic stack entry point.
/// Returns a handle; consumer calls `handle.tcp` and `handle.udp`.
#[async_trait]
pub trait TunStack: Send + Sync + private::Sealed + Sized {
    type Device: TunDevice;
    type Tcp: TcpAcceptor;
    type Udp: UdpSocket;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Build and start the stack. Blocks until the TUN device is up.
    async fn start(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<StackHandle<Self::Tcp, Self::Udp>, Self::Error>;
}

// ── StackHandle ───────────────────────────────────────────────────────────────

pub struct StackHandle<Tcp: TcpAcceptor, Udp: UdpSocket> {
    pub tcp: Tcp,
    pub udp: Udp,
    /// Metrics: bytes tx/rx, active conns.
    pub metrics: Arc<crate::metrics::StackMetrics>,
}

// ── Firewall ──────────────────────────────────────────────────────────────────
//
// Kept as a synchronous trait at this phase to preserve backward compatibility
// with the existing WfpKillSwitch impl in mirage-tun-windows. Will be migrated
// to async (with `#[async_trait]`) in Step 3 of the refactoring.

// Note: `private::Sealed` bound intentionally omitted here so the existing
// mirage-tun-windows WfpKillSwitch impl continues to compile without changes.
// It will be added back in Step 3 once Windows adds `impl Sealed for WfpKillSwitch`.
pub trait PlatformFirewall: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn activate(
        &mut self,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        exempt_ports: &[u16],
    ) -> Result<(), Self::Error>;

    fn deactivate(&mut self) -> Result<(), Self::Error>;
}

// ── Routing ───────────────────────────────────────────────────────────────────
//
// New async trait for future platform impls (Linux, macOS, Android, iOS).
// Windows uses its own `Routing` struct without implementing this trait for now.

#[async_trait]
pub trait PlatformRouting: Send + Sync + private::Sealed {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn set_default_route(&mut self, tun_name: &str) -> Result<(), Self::Error>;
    async fn restore_routes(&mut self) -> Result<(), Self::Error>;
    async fn add_bypass_host(&mut self, addr: IpAddr) -> Result<(), Self::Error>;
    fn original_gateway(&self) -> Option<IpAddr>;
}

// ── DnsOverride ───────────────────────────────────────────────────────────────

#[async_trait]
pub trait PlatformDns: Send + Sync + private::Sealed {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Push DNS servers for the tunnel interface. Called after TUN is up.
    async fn set_dns(
        &mut self,
        tun_name: &str,
        servers: &[IpAddr],
    ) -> Result<(), Self::Error>;

    async fn revert_dns(&mut self) -> Result<(), Self::Error>;
}

// ── PlatformExecutor: T2 kill-switch execution interface ──────────────────────

/// Transport protocol for attribution and enforcement context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowProto {
    Tcp,
    Udp,
}

/// Minimal flow key passed to enforce — enough to identify the connection for logging.
#[derive(Debug, Clone)]
pub struct FlowKey {
    pub src_port: u16,
    pub dst: std::net::SocketAddr,
    pub proto: FlowProto,
}

/// Platform executor — the ONLY interface platforms implement for T2+.
///
/// Core (`PlaneEngine`) does all policy logic. Platforms do exactly two things:
///   (a) attribute a packet/flow to a `ProcessIdentity`
///   (b) enforce the `Plane` decision from the engine
///
/// Both methods are synchronous. Attribution is called from `spawn_blocking`
/// where Win32 table lookup happens; enforcement installs/removes firewall rules
/// synchronously (WFP transaction, pfctl shell, nft ruleset).
///
/// Sealed — not implementable outside the mirage-tun-* crates.
/// Add `impl mirage_tun_core::traits::private::Sealed for YourType {}` in the platform crate.
pub trait PlatformExecutor: Send + Sync + private::Sealed {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Attribute a flow (identified by src_port + dst) to a ProcessIdentity.
    /// Returns None when attribution is unavailable (coarse-granularity platforms).
    /// Must be called from a blocking context (synchronous OS API calls).
    fn attribute(
        &self,
        src_port: u16,
        dst: std::net::SocketAddr,
        proto: FlowProto,
    ) -> Option<crate::plane::ProcessIdentity>;

    /// Enforce the plane decision for a flow / process pair.
    ///
    /// Invariant contract (core guarantees, platform must not violate):
    ///   - `Plane::Bypass` → permit the flow via the TUN bypass path; NEVER drop.
    ///   - `Plane::Wire(id)` → route flow into the named SOCKS5 chain.
    ///   - `Plane::Kill` → drop the flow (RST TCP / ICMP unreachable UDP / silent drop).
    ///   - `Plane::Group` MUST NOT reach enforce — caller resolves group first via
    ///     `PlaneEngine::resolve_group`.
    ///
    /// `identity` is None for unattributed flows (coarse platforms use None always).
    fn enforce(
        &mut self,
        plane: &crate::plane::Plane,
        identity: Option<&crate::plane::ProcessIdentity>,
        flow: &FlowKey,
    ) -> Result<(), Self::Error>;
}

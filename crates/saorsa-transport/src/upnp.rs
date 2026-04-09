// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.

//! Best-effort UPnP IGD port mapping.
//!
//! This module asks the local Internet Gateway Device (typically a home
//! router) to forward a single UDP port to our endpoint. When successful,
//! the gateway provides a deterministic public `ip:port` reachable from
//! the open internet, which is then surfaced as a high-priority NAT
//! traversal candidate alongside locally-discovered and peer-observed
//! addresses.
//!
//! # Best-effort contract
//!
//! Everything in this module is **strictly additive**. The endpoint must
//! behave identically to a non-UPnP build when the gateway:
//!
//! * does not exist (no router on the LAN, or it does not speak SSDP),
//! * has UPnP IGD disabled in its administrative settings,
//! * supports UPnP but refuses the mapping request,
//! * accepts the request but later forgets it / reboots / changes IPs.
//!
//! Concretely this means:
//!
//! 1. [`UpnpMappingService::start`](crate::upnp::UpnpMappingService::start) never returns an error and never blocks
//!    on network I/O — it spawns a background task and returns immediately.
//! 2. All failures are swallowed and logged at `debug` level. The only
//!    `info` log line is the success path.
//! 3. Discovery is single-shot per service lifetime. A router that did not
//!    answer once is left alone for the rest of the session — there is no
//!    periodic re-probe.
//! 4. The lease is finite (one hour by default), so a crashed process
//!    cannot leak a permanent mapping on the gateway.
//!
//! Callers consume the service by polling [`UpnpMappingService::current`](crate::upnp::UpnpMappingService::current)
//! when they want the most recent state. The poll is a lock-free atomic
//! load on the underlying `tokio::sync::watch` channel, so it is cheap to
//! call from the candidate discovery hot path.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
#[cfg(feature = "upnp")]
use tracing::{debug, info, warn};

/// Default lease duration requested from the gateway.
///
/// One hour balances two concerns: short enough that a crashed process
/// cannot leak a permanent mapping on the router, long enough that the
/// refresh task does not generate noticeable network churn.
const DEFAULT_LEASE: Duration = Duration::from_secs(3600);

/// Default budget for the initial gateway discovery probe.
///
/// SSDP M-SEARCH multicasts and waits for responses; without a hard
/// deadline a non-UPnP LAN would force the background task to wait the
/// full SSDP timeout (~10s) before giving up. Two seconds is enough for
/// any cooperating gateway on the same broadcast domain.
const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Best-effort budget for the cleanup `DeletePortMapping` request issued
/// during graceful shutdown. The lease is the ultimate safety net, so
/// blocking shutdown waiting for an unresponsive router would be wrong.
#[cfg(feature = "upnp")]
const SHUTDOWN_UNMAP_BUDGET: Duration = Duration::from_millis(500);

/// Configuration for [`UpnpMappingService`].
///
/// Defaults are tuned for the common case (residential broadband + a
/// consumer router) and should rarely need to be overridden. Use
/// [`UpnpConfig::disabled`] to explicitly opt out at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpnpConfig {
    /// Master switch. When `false`, [`UpnpMappingService::start`] returns
    /// a service that is permanently in [`UpnpState::Unavailable`] and
    /// performs no network I/O.
    pub enabled: bool,

    /// Lease duration to request from the gateway. The refresh task will
    /// renew at half this interval.
    #[serde(with = "duration_secs")]
    pub lease_duration: Duration,

    /// Maximum time to wait for the initial gateway discovery probe.
    /// After this deadline elapses with no gateway response, the service
    /// transitions to [`UpnpState::Unavailable`] and stops trying.
    #[serde(with = "duration_millis")]
    pub discovery_timeout: Duration,
}

impl Default for UpnpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            lease_duration: DEFAULT_LEASE,
            discovery_timeout: DEFAULT_DISCOVERY_TIMEOUT,
        }
    }
}

impl UpnpConfig {
    /// Construct a configuration that permanently disables UPnP.
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            lease_duration: DEFAULT_LEASE,
            discovery_timeout: DEFAULT_DISCOVERY_TIMEOUT,
        }
    }
}

/// Snapshot of the UPnP mapping state at a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpnpState {
    /// Initial discovery is still in flight or has not yet started.
    Probing,
    /// No usable gateway is available for this session. This is a sticky
    /// state — once entered, the service stays here until shut down.
    /// Reached when SSDP discovery times out, the gateway refuses the
    /// mapping, returns a non-public external IP, or otherwise fails.
    Unavailable,
    /// Gateway is forwarding `external` to our local UDP port.
    Mapped {
        /// Public address that remote peers can dial to reach this
        /// endpoint via the gateway-managed mapping.
        external: SocketAddr,
        /// Wall-clock instant at which the current lease expires. The
        /// background refresh task renews the lease before this point;
        /// callers should treat the value as informational.
        lease_expires_at: Instant,
    },
}

/// Background service that maintains a single UDP UPnP mapping for the
/// endpoint's local port.
///
/// Construct with [`UpnpMappingService::start`]. Read state with
/// [`UpnpMappingService::current`] or hand a [`UpnpStateRx`] to consumers
/// via [`UpnpMappingService::subscribe`]. Tear down with
/// [`UpnpMappingService::shutdown`] (the implementation also has a
/// best-effort `Drop` fallback for the panic path).
pub struct UpnpMappingService {
    state: watch::Receiver<UpnpState>,
    inner: Arc<ServiceInner>,
}

/// Read-only handle to the current [`UpnpState`].
///
/// Cloneable, lock-free, and decoupled from service ownership: callers
/// that only need to observe the mapping (for example, the candidate
/// discovery manager) take a `UpnpStateRx` instead of an
/// `Arc<UpnpMappingService>`, leaving the endpoint as the sole owner of
/// the service so graceful shutdown can reclaim and unmap it.
#[derive(Clone)]
pub struct UpnpStateRx {
    inner: watch::Receiver<UpnpState>,
}

impl UpnpStateRx {
    /// Lock-free snapshot of the most recent state.
    pub fn current(&self) -> UpnpState {
        self.inner.borrow().clone()
    }

    /// Test-only constructor that pins the receiver to a fixed state.
    #[cfg(test)]
    pub(crate) fn for_test(state: UpnpState) -> Self {
        let (_tx, rx) = watch::channel(state);
        Self { inner: rx }
    }
}

struct ServiceInner {
    shutdown: tokio::sync::Notify,
    /// Once the background task observes the shutdown notification it
    /// stores the active mapping (if any) here so [`UpnpMappingService::shutdown`]
    /// can issue the final `DeletePortMapping` from the caller's task.
    /// We deliberately keep the cleanup off the background task so that
    /// dropping the runtime in tests does not block on the unmap RPC.
    last_mapping: parking_lot::Mutex<Option<ActiveMapping>>,
    handle: parking_lot::Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "upnp"), allow(dead_code))]
struct ActiveMapping {
    external_port: u16,
    gateway: GatewayHandle,
}

impl UpnpMappingService {
    /// Spawn the UPnP service for `local_udp_port`.
    ///
    /// This is infallible by design — even when UPnP is unsupported on
    /// the host, this returns a service stuck in [`UpnpState::Unavailable`].
    /// The returned service starts in [`UpnpState::Probing`] when enabled.
    pub fn start(local_udp_port: u16, config: UpnpConfig) -> Self {
        let (tx, rx) = watch::channel(UpnpState::Probing);
        let inner = Arc::new(ServiceInner {
            shutdown: tokio::sync::Notify::new(),
            last_mapping: parking_lot::Mutex::new(None),
            handle: parking_lot::Mutex::new(None),
        });

        if !config.enabled {
            // Permanently unavailable — never touches the network.
            let _ = tx.send(UpnpState::Unavailable);
            return Self { state: rx, inner };
        }

        let handle = spawn_background_task(local_udp_port, config, tx, Arc::clone(&inner));
        *inner.handle.lock() = handle;
        Self { state: rx, inner }
    }

    /// Lock-free snapshot of the most recent state.
    ///
    /// Cheap enough to call from a discovery hot path on every poll.
    pub fn current(&self) -> UpnpState {
        self.state.borrow().clone()
    }

    /// Clone the watch receiver so callers can poll state without owning
    /// a reference to the service itself.
    ///
    /// Use this when the consumer only needs to read the current mapping
    /// (for example, the candidate discovery manager) — it keeps service
    /// lifetime cleanly owned by the endpoint and lets graceful shutdown
    /// reclaim the unique `Arc` for `try_unwrap`.
    pub fn subscribe(&self) -> UpnpStateRx {
        UpnpStateRx {
            inner: self.state.clone(),
        }
    }

    /// Best-effort graceful teardown.
    ///
    /// Signals the background task to stop, then attempts a single
    /// `DeletePortMapping` against the gateway with a 500ms budget.
    /// All errors are swallowed — if the router has gone away, the lease
    /// expires naturally. Mutex guards are released before the awaits so
    /// the resulting future stays `Send` for callers running on a
    /// multi-threaded tokio runtime.
    pub async fn shutdown(self) {
        self.inner.shutdown.notify_waiters();

        let handle = self.inner.handle.lock().take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }

        let active = self.inner.last_mapping.lock().take();
        if let Some(active) = active {
            best_effort_unmap(active).await;
        }
    }
}

impl Drop for UpnpMappingService {
    fn drop(&mut self) {
        // Crash-path safety: notify any background task and abort it.
        // We deliberately do *not* attempt async unmap here — the lease
        // is the ultimate safety net.
        self.inner.shutdown.notify_waiters();
        if let Some(handle) = self.inner.handle.lock().take() {
            handle.abort();
        }
    }
}

/// Returns true if `addr` looks like a publicly routable IP address.
///
/// We require this check because misbehaving routers will sometimes return
/// their LAN-side address as the "external" IP via `GetExternalIP`. Trusting
/// such a value would poison NAT traversal candidate selection — the
/// endpoint would advertise an unreachable RFC1918 address as if it were
/// public.
#[cfg_attr(not(feature = "upnp"), allow(dead_code))]
pub(crate) fn is_plausibly_public(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_plausibly_public_v4(v4),
        IpAddr::V6(v6) => is_plausibly_public_v6(v6),
    }
}

#[cfg_attr(not(feature = "upnp"), allow(dead_code))]
fn is_plausibly_public_v4(addr: Ipv4Addr) -> bool {
    if addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_broadcast()
        || addr.is_multicast()
        || addr.is_link_local()
        || addr.is_documentation()
    {
        return false;
    }
    if addr.is_private() {
        return false;
    }
    // CGNAT range (RFC 6598) — addresses here are NAT'd by the carrier and
    // are not directly reachable from the public internet, so a UPnP
    // mapping against a 100.64/10 "external" IP is useless.
    let octets = addr.octets();
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return false;
    }
    true
}

#[cfg_attr(not(feature = "upnp"), allow(dead_code))]
fn is_plausibly_public_v6(addr: std::net::Ipv6Addr) -> bool {
    // Reject the standard garbage: loopback, unspecified, multicast,
    // link-local unicast, documentation. Anything else (global unicast,
    // ULA) is acceptable — ULAs are not routable but a misconfigured
    // gateway returning a ULA is rare enough that we let the candidate
    // validator catch it later.
    //
    // Mirrors the IPv4 classifier's rejection of RFC 5737 documentation
    // space so a misbehaving router cannot poison candidate discovery by
    // returning an RFC 3849 `2001:db8::/32` address as its "external" IP.
    !(addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || addr.is_unicast_link_local()
        || is_ipv6_documentation(addr))
}

/// First 16-bit group of the RFC 3849 IPv6 documentation prefix
/// `2001:db8::/32`.
const IPV6_DOCUMENTATION_PREFIX_HI: u16 = 0x2001;
/// Second 16-bit group of the RFC 3849 IPv6 documentation prefix
/// `2001:db8::/32`.
const IPV6_DOCUMENTATION_PREFIX_LO: u16 = 0x0db8;

/// RFC 3849 documentation prefix — `2001:db8::/32`.
///
/// Stdlib does not expose an `is_documentation` helper for `Ipv6Addr`, so
/// we match the prefix manually. Kept separate to mirror the v4
/// `Ipv4Addr::is_documentation` call path at the classifier site.
#[cfg_attr(not(feature = "upnp"), allow(dead_code))]
fn is_ipv6_documentation(addr: std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    segments[0] == IPV6_DOCUMENTATION_PREFIX_HI && segments[1] == IPV6_DOCUMENTATION_PREFIX_LO
}

// ---------------------------------------------------------------------------
// Backend selection: real `igd-next` implementation when the `upnp` feature
// is enabled, no-op stub otherwise. Both backends share the public types
// above so call sites do not need to be feature-gated.
// ---------------------------------------------------------------------------

#[cfg(feature = "upnp")]
mod backend {
    use super::*;
    use igd_next::PortMappingProtocol;
    use igd_next::SearchOptions;
    use igd_next::aio::Gateway as GenericGateway;
    use igd_next::aio::tokio::{Tokio, search_gateway};

    pub(super) type GatewayHandle = Arc<GenericGateway<Tokio>>;

    /// Description sent to the gateway. Most consumer routers expose this
    /// in the admin UI's port-forwarding table.
    const MAPPING_DESCRIPTION: &str = concat!("saorsa-transport/", env!("CARGO_PKG_VERSION"));

    pub(super) fn spawn_background_task(
        local_port: u16,
        config: UpnpConfig,
        tx: watch::Sender<UpnpState>,
        inner: Arc<ServiceInner>,
    ) -> Option<JoinHandle<()>> {
        let handle = tokio::spawn(async move {
            run_service(local_port, config, tx, inner).await;
        });
        Some(handle)
    }

    async fn run_service(
        local_port: u16,
        config: UpnpConfig,
        tx: watch::Sender<UpnpState>,
        inner: Arc<ServiceInner>,
    ) {
        let gateway = match discover_gateway(config.discovery_timeout).await {
            Some(gw) => Arc::new(gw),
            None => {
                let _ = tx.send(UpnpState::Unavailable);
                return;
            }
        };

        // Validate the gateway's claimed external IP before trusting any
        // mapping it offers. A router that returns its LAN address here is
        // misconfigured and unsafe to use — surfacing such an "external"
        // address as a NAT traversal candidate would actively break peers.
        let external_ip = match gateway.get_external_ip().await {
            Ok(ip) => ip,
            Err(err) => {
                debug!(error = %err, "upnp: get_external_ip failed");
                let _ = tx.send(UpnpState::Unavailable);
                return;
            }
        };
        if !is_plausibly_public(external_ip) {
            warn!(
                external_ip = %external_ip,
                "upnp: gateway returned a non-public external IP, refusing to use"
            );
            let _ = tx.send(UpnpState::Unavailable);
            return;
        }

        let local_addr = local_socket_for_mapping(local_port);
        let mapped_port =
            match request_mapping(&gateway, local_addr, local_port, config.lease_duration).await {
                Some(port) => port,
                None => {
                    let _ = tx.send(UpnpState::Unavailable);
                    return;
                }
            };

        let external = SocketAddr::new(external_ip, mapped_port);
        let mut lease_expires_at = Instant::now() + config.lease_duration;
        info!(
            external = %external,
            lease_secs = config.lease_duration.as_secs(),
            "upnp: gateway mapping active"
        );

        // Record the active mapping so the shutdown path can clean it up.
        *inner.last_mapping.lock() = Some(ActiveMapping {
            external_port: mapped_port,
            gateway: Arc::clone(&gateway),
        });

        let _ = tx.send(UpnpState::Mapped {
            external,
            lease_expires_at,
        });

        // Refresh loop: re-request the mapping at half the lease interval.
        // Failure here is not fatal — we transition to Unavailable, leave
        // the existing mapping to expire on its own, and exit the task.
        loop {
            let refresh_in = (config.lease_duration / 2).max(Duration::from_secs(30));
            tokio::select! {
                () = inner.shutdown.notified() => {
                    return;
                }
                () = tokio::time::sleep(refresh_in) => {}
            }

            match request_mapping(&gateway, local_addr, mapped_port, config.lease_duration).await {
                Some(port) if port == mapped_port => {
                    lease_expires_at = Instant::now() + config.lease_duration;
                    let _ = tx.send(UpnpState::Mapped {
                        external,
                        lease_expires_at,
                    });
                }
                _ => {
                    debug!("upnp: lease refresh failed, marking unavailable");
                    *inner.last_mapping.lock() = None;
                    let _ = tx.send(UpnpState::Unavailable);
                    return;
                }
            }
        }
    }

    async fn discover_gateway(timeout: Duration) -> Option<GenericGateway<Tokio>> {
        let opts = SearchOptions {
            timeout: Some(timeout),
            ..Default::default()
        };
        match tokio::time::timeout(timeout, search_gateway(opts)).await {
            Ok(Ok(gateway)) => Some(gateway),
            Ok(Err(err)) => {
                debug!(error = %err, "upnp: gateway discovery failed");
                None
            }
            Err(_) => {
                debug!("upnp: gateway discovery timed out");
                None
            }
        }
    }

    /// Request a UDP mapping for `local_addr`, preferring port preservation.
    ///
    /// Tries `add_port(preferred_external)` first because matching the
    /// internal port keeps the mapped candidate aligned with what peers
    /// will see via OBSERVED_ADDRESS. Falls back to `add_any_port` so the
    /// gateway can pick a free port if the preferred one is taken.
    async fn request_mapping(
        gateway: &GenericGateway<Tokio>,
        local_addr: SocketAddr,
        preferred_external: u16,
        lease: Duration,
    ) -> Option<u16> {
        let lease_secs = u32::try_from(lease.as_secs()).unwrap_or(u32::MAX);

        match gateway
            .add_port(
                PortMappingProtocol::UDP,
                preferred_external,
                local_addr,
                lease_secs,
                MAPPING_DESCRIPTION,
            )
            .await
        {
            Ok(()) => return Some(preferred_external),
            Err(err) => {
                debug!(
                    preferred_external,
                    error = %err,
                    "upnp: add_port for preferred external failed, falling back to add_any_port"
                );
            }
        }

        match gateway
            .add_any_port(
                PortMappingProtocol::UDP,
                local_addr,
                lease_secs,
                MAPPING_DESCRIPTION,
            )
            .await
        {
            Ok(port) => Some(port),
            Err(err) => {
                debug!(error = %err, "upnp: add_any_port failed");
                None
            }
        }
    }

    /// Build a `SocketAddr` for the gateway to forward traffic to.
    ///
    /// `igd-next` requires an explicit local IP rather than `0.0.0.0`,
    /// because the gateway needs to know which LAN host owns the mapping.
    /// We pick the first IPv4 address that matches the egress route to the
    /// gateway by relying on the OS-default outbound socket trick: connect
    /// a UDP socket to a public address and read its local IP. The remote
    /// address is never actually contacted.
    ///
    /// This uses `std::net::UdpSocket` rather than `tokio::net::UdpSocket`
    /// because both `bind` and `connect` on UDP are pure kernel route
    /// lookups — there is no wire I/O, so the executor thread is not
    /// actually blocked. Called once per session at the top of the
    /// background task, before the real SSDP discovery begins.
    fn local_socket_for_mapping(local_port: u16) -> SocketAddr {
        // 192.0.2.1 (TEST-NET-1) is RFC 5737 documentation space — packets
        // are not routed but the kernel will still pick the correct
        // outbound interface for the route lookup.
        let probe = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|sock| {
                sock.connect("192.0.2.1:9")?;
                sock.local_addr()
            })
            .map(|addr| addr.ip());

        let local_ip = match probe {
            Ok(IpAddr::V4(v4)) if !v4.is_unspecified() => IpAddr::V4(v4),
            // UPnP IGD v1 only deals in IPv4 mappings; if the egress route
            // resolved to IPv6 (or failed entirely) we fall back to the
            // unspecified address and let `add_port` reject it. The error
            // is logged at `debug` and surfaces as `Unavailable`.
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        SocketAddr::new(local_ip, local_port)
    }

    pub(super) async fn best_effort_unmap(active: ActiveMapping) {
        let unmap = active
            .gateway
            .remove_port(PortMappingProtocol::UDP, active.external_port);
        match tokio::time::timeout(SHUTDOWN_UNMAP_BUDGET, unmap).await {
            Ok(Ok(())) => debug!("upnp: deleted port mapping on shutdown"),
            Ok(Err(err)) => debug!(error = %err, "upnp: delete_port_mapping failed on shutdown"),
            Err(_) => debug!("upnp: delete_port_mapping timed out on shutdown"),
        }
    }
}

#[cfg(not(feature = "upnp"))]
mod backend {
    use super::*;

    /// Stub gateway handle used when the `upnp` feature is disabled.
    /// Carries no state and is never instantiated at runtime.
    pub(super) type GatewayHandle = ();

    pub(super) fn spawn_background_task(
        _local_port: u16,
        _config: UpnpConfig,
        tx: watch::Sender<UpnpState>,
        _inner: Arc<ServiceInner>,
    ) -> Option<JoinHandle<()>> {
        // Without the feature we cannot probe a gateway, so transition
        // straight to Unavailable and skip spawning a task entirely.
        let _ = tx.send(UpnpState::Unavailable);
        None
    }

    pub(super) async fn best_effort_unmap(_active: ActiveMapping) {
        // No backend → nothing to release.
    }
}

use backend::{GatewayHandle, best_effort_unmap, spawn_background_task};

// ---------------------------------------------------------------------------
// Serde helpers — keep human-readable units in serialized config files
// without inflicting them on the public API.
// ---------------------------------------------------------------------------

mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(value: &Duration, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u64(value.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(de)?;
        Ok(Duration::from_secs(secs))
    }
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(value: &Duration, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u64(value.as_millis() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let ms = u64::deserialize(de)?;
        Ok(Duration::from_millis(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn disabled_service_reports_unavailable_immediately() {
        let service = UpnpMappingService::start(0, UpnpConfig::disabled());
        assert_eq!(service.current(), UpnpState::Unavailable);
    }

    #[test]
    fn default_config_is_enabled_with_one_hour_lease() {
        let cfg = UpnpConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.lease_duration, DEFAULT_LEASE);
        assert_eq!(cfg.discovery_timeout, DEFAULT_DISCOVERY_TIMEOUT);
    }

    #[test]
    fn rejects_rfc1918_addresses_as_external_ip() {
        for blocked in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 5, 9),
            Ipv4Addr::new(192, 168, 1, 254),
        ] {
            assert!(
                !is_plausibly_public(IpAddr::V4(blocked)),
                "{blocked} should be rejected as non-public"
            );
        }
    }

    #[test]
    fn rejects_loopback_link_local_and_cgnat() {
        assert!(!is_plausibly_public(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_plausibly_public(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_plausibly_public(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(!is_plausibly_public(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(!is_plausibly_public(IpAddr::V4(Ipv4Addr::new(
            100, 64, 0, 1
        ))));
        assert!(!is_plausibly_public(IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 254
        ))));
    }

    #[test]
    fn accepts_public_ipv4_outside_special_ranges() {
        assert!(is_plausibly_public(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_plausibly_public(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn rejects_documentation_ranges() {
        // RFC 5737 documentation prefixes — must never be advertised as
        // a real external IP, regardless of what a misbehaving gateway
        // might claim.
        assert!(!is_plausibly_public(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 1
        ))));
        assert!(!is_plausibly_public(IpAddr::V4(Ipv4Addr::new(
            198, 51, 100, 1
        ))));
        assert!(!is_plausibly_public(IpAddr::V4(Ipv4Addr::new(
            203, 0, 113, 1
        ))));
    }

    #[test]
    fn accepts_global_unicast_ipv6_and_rejects_link_local() {
        // 2606:4700:4700::1111 is Cloudflare DNS, a real global unicast
        // address. Explicitly chosen over 2001:db8::/32 so this test
        // exercises the happy path rather than accidentally landing in
        // documentation space.
        let global = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_plausibly_public(IpAddr::V6(global)));
        assert!(!is_plausibly_public(IpAddr::V6(link_local)));
        assert!(!is_plausibly_public(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn rejects_ipv6_documentation_range() {
        // RFC 3849 `2001:db8::/32` is the IPv6 counterpart of the RFC
        // 5737 documentation prefixes. A misbehaving router returning an
        // address from this range must never be accepted as an external
        // IP, matching the IPv4 `is_documentation()` rejection.
        assert!(!is_plausibly_public(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_plausibly_public(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0xdead, 0xbeef, 0, 0, 0, 0x42
        ))));
        // A neighbouring /32 (2001:0db9::) is not documentation space
        // and must still be accepted.
        assert!(is_plausibly_public(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db9, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn rejects_ipv6_multicast_and_unspecified() {
        assert!(!is_plausibly_public(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        // ff00::/8 — multicast.
        assert!(!is_plausibly_public(IpAddr::V6(Ipv6Addr::new(
            0xff02, 0, 0, 0, 0, 0, 0, 1
        ))));
    }
}

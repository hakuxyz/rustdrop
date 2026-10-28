//! Local network discovery via mDNS/Zeroconf.
//!
//! `rustdrop receive` announces itself as `_rustdrop._tcp.local.` with a few
//! non-sensitive TXT records; `rustdrop send` browses the same service type.
//! No central server, no internet, no account – just multicast DNS on the LAN.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo, TxtProperty};

use crate::error::{Result, RustDropError};

/// Service type announced and browsed by RustDrop.
pub const SERVICE_TYPE: &str = "_rustdrop._tcp.local.";

/// Grace period after the first hit so a couple of receivers can still show up.
const DISCOVERY_GRACE: Duration = Duration::from_millis(600);

/// A receiver found on the local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredReceiver {
    /// mDNS instance name (stable per machine, e.g. `nixbox`).
    pub instance: String,
    /// Human friendly name from the TXT record.
    pub device_name: String,
    /// Candidate endpoints, IPv4 first.
    pub addresses: Vec<SocketAddr>,
    /// Protocol version advertised by the peer.
    pub version: String,
}

impl std::fmt::Display for DiscoveredReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addrs: Vec<String> = self.addresses.iter().map(|a| a.to_string()).collect();
        write!(
            f,
            "{} ({}) [{}]",
            self.device_name,
            self.instance,
            addrs.join(", ")
        )
    }
}

/// Keeps a service announcement alive for as long as the receiver runs.
pub struct Announcement {
    daemon: ServiceDaemon,
    instance: String,
    port: u16,
}

impl Announcement {
    /// Publish `_rustdrop._tcp.local.<instance>` on this host.
    pub fn start(instance: &str, port: u16, device_name: &str) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| RustDropError::Discovery(e.to_string()))?;

        let instance = sanitize_instance(instance);
        let hostname = format!("{}.local.", sanitize_instance(&host_name()));
        let ip: IpAddr = local_ipv4().into();
        let version = crate::crypto::PROTOCOL_VERSION.to_string();

        let properties = vec![
            TxtProperty::from(("app", "rustdrop")),
            TxtProperty::from(("ver", version.as_str())),
            TxtProperty::from(("name", device_name)),
        ];

        let info = ServiceInfo::new(SERVICE_TYPE, &instance, &hostname, ip, port, properties)
            .map_err(|e| RustDropError::Discovery(e.to_string()))?;

        daemon
            .register(info)
            .map_err(|e| RustDropError::Discovery(e.to_string()))?;

        Ok(Self {
            daemon,
            instance,
            port,
        })
    }

    pub fn instance(&self) -> &str {
        &self.instance
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Announcement {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}

/// Browse for receivers.
///
/// Returns as soon as `window` elapses, or shortly after the first hit
/// (`DISCOVERY_GRACE`) so the happy path stays snappy.
pub async fn discover(filter: Option<&str>, window: Duration) -> Result<Vec<DiscoveredReceiver>> {
    let daemon = ServiceDaemon::new().map_err(|e| RustDropError::Discovery(e.to_string()))?;
    let events = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| RustDropError::Discovery(e.to_string()))?;

    let mut found: HashMap<String, DiscoveredReceiver> = HashMap::new();
    let deadline = tokio::time::Instant::now() + window;
    let mut grace_until: Option<tokio::time::Instant> = None;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        if let Some(until) = grace_until {
            if now >= until {
                break;
            }
        }

        let remaining = deadline.saturating_duration_since(now);
        match tokio::time::timeout(remaining, events.recv_async()).await {
            Ok(Ok(event)) => match event {
                ServiceEvent::ServiceResolved(resolved) => {
                    let entry = from_resolved(&resolved);
                    if filter.is_some_and(|f| !matches_filter(&entry, f)) {
                        continue;
                    }
                    let fresh = !found.contains_key(&entry.instance);
                    found.insert(entry.instance.clone(), entry);
                    if fresh && grace_until.is_none() {
                        grace_until = Some(tokio::time::Instant::now() + DISCOVERY_GRACE);
                    }
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    if let Some(instance) = fullname.split('.').next() {
                        found.remove(instance);
                    }
                }
                _ => {}
            },
            // Channel closed or timed out: stop browsing.
            _ => break,
        }
    }

    let _ = daemon.shutdown();

    let mut list: Vec<DiscoveredReceiver> = found.into_values().collect();
    list.sort_by(|a, b| a.device_name.cmp(&b.device_name));
    Ok(list)
}

fn from_resolved(resolved: &mdns_sd::ResolvedService) -> DiscoveredReceiver {
    let instance = resolved
        .fullname
        .split('.')
        .next()
        .unwrap_or(&resolved.fullname)
        .to_string();

    let device_name = resolved
        .txt_properties
        .get("name")
        .map(|p| p.val_str().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| instance.clone());

    let version = resolved
        .txt_properties
        .get("ver")
        .map(|p| p.val_str().to_string())
        .unwrap_or_else(|| "unknown".into());

    let mut addresses: Vec<SocketAddr> = resolved
        .addresses
        .iter()
        .map(|a| SocketAddr::new(a.to_ip_addr(), resolved.port))
        .collect();
    // Prefer IPv4: link-local IPv6 scopes are not routable from a plain socket.
    addresses.sort_by_key(|a| !a.is_ipv4());
    addresses.dedup();

    DiscoveredReceiver {
        instance,
        device_name,
        addresses,
        version,
    }
}

fn matches_filter(receiver: &DiscoveredReceiver, filter: &str) -> bool {
    let needle = filter.to_lowercase();
    receiver.instance.to_lowercase().contains(&needle)
        || receiver.device_name.to_lowercase().contains(&needle)
}

/// Best-effort LAN IPv4 of this host.
///
/// `UdpSocket::connect` on a public-ish address performs a route lookup
/// *without sending a single packet*, which is all we need to learn the source
/// address the rest of the LAN will see us from.
pub fn local_ipv4() -> Ipv4Addr {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("192.0.2.1:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                if let IpAddr::V4(ip) = addr.ip() {
                    if !ip.is_unspecified() {
                        return ip;
                    }
                }
            }
        }
    }
    Ipv4Addr::LOCALHOST
}

/// mDNS instance names: keep them boring and DNS-safe.
fn sanitize_instance(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();

    while out.starts_with('-') {
        out.remove(0);
    }
    out.truncate(63);
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "rustdrop".to_string()
    } else {
        out
    }
}

fn host_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "rustdrop-host".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_sanitization_is_dns_safe() {
        assert_eq!(sanitize_instance("My Laptop!"), "my-laptop");
        assert_eq!(sanitize_instance("--x--"), "x");
        assert_eq!(sanitize_instance("überraschung"), "berraschung");
        assert_eq!(sanitize_instance(""), "rustdrop");
        assert!(sanitize_instance(&"a".repeat(200)).len() <= 63);
    }

    #[test]
    fn filter_is_case_insensitive() {
        let rx = DiscoveredReceiver {
            instance: "nixbox".into(),
            device_name: "NixBox".into(),
            addresses: vec![],
            version: "1".into(),
        };
        assert!(matches_filter(&rx, "nix"));
        assert!(matches_filter(&rx, "NIXBOX"));
        assert!(!matches_filter(&rx, "gaming"));
    }

    #[test]
    fn local_ip_is_usable() {
        let ip = local_ipv4();
        assert!(!ip.is_unspecified());
    }

    #[tokio::test]
    async fn discover_returns_cleanly_on_timeout() {
        // No receiver announced (or none reachable): must not hang forever.
        let list = discover(None, Duration::from_millis(300)).await.unwrap();
        assert!(list.is_empty() || list.iter().all(|r| !r.addresses.is_empty()));
    }
}

//! Private, read-only loopback health responder.

use crate::logging::warn;
use crate::storage::AntProtocol;
use saorsa_core::P2PNode;
use serde::Serialize;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER_BYTES: usize = 2048;

#[derive(Serialize)]
struct Snapshot {
    peer_id: String,
    version: &'static str,
    uptime_secs: u64,
    bootstrapped: bool,
    peer_count: usize,
    routing_table_size: usize,
    storage_enabled: bool,
    chunks_current: u64,
    chunks_written_total: u64,
    bytes_written_total: u64,
    chunks_served_total: u64,
    bytes_served_total: u64,
}

impl Snapshot {
    async fn read(p2p: &P2PNode, protocol: Option<&AntProtocol>) -> Self {
        let stats = protocol.map(AntProtocol::storage_stats).unwrap_or_default();
        Self {
            peer_id: p2p.peer_id().to_hex(),
            version: env!("CARGO_PKG_VERSION"),
            uptime_secs: p2p.uptime().as_secs(),
            bootstrapped: p2p.is_bootstrapped(),
            peer_count: p2p.peer_count().await,
            routing_table_size: p2p.dht_manager().get_routing_table_size().await,
            storage_enabled: protocol.is_some(),
            chunks_current: stats.current_chunks,
            chunks_written_total: stats.chunks_stored,
            bytes_written_total: stats.bytes_stored,
            chunks_served_total: stats.chunks_retrieved,
            bytes_served_total: stats.bytes_retrieved,
        }
    }

    fn metrics(&self) -> String {
        // Both labels have controlled values: a hex peer ID and the package version.
        let labels = format!("peer_id=\"{}\",version=\"{}\"", self.peer_id, self.version);
        let mut text = String::new();
        for (name, kind, value) in [
            ("ant_uptime_seconds", "gauge", self.uptime_secs),
            ("p2p_health_status", "gauge", u64::from(self.bootstrapped)),
            ("p2p_network_peer_count", "gauge", self.peer_count as u64),
            (
                "p2p_dht_routing_table_size",
                "gauge",
                self.routing_table_size as u64,
            ),
            (
                "ant_storage_enabled",
                "gauge",
                u64::from(self.storage_enabled),
            ),
            ("ant_chunks_current", "gauge", self.chunks_current),
            (
                "ant_chunks_written_total",
                "counter",
                self.chunks_written_total,
            ),
            (
                "ant_bytes_written_total",
                "counter",
                self.bytes_written_total,
            ),
            (
                "ant_chunks_served_total",
                "counter",
                self.chunks_served_total,
            ),
            ("ant_bytes_served_total", "counter", self.bytes_served_total),
        ] {
            use std::fmt::Write;
            let _ = writeln!(text, "# TYPE {name} {kind}\n{name}{{{labels}}} {value}");
        }
        text
    }
}

/// Remove discovery left by this run or an earlier interrupted run.
pub async fn clear_port_file(root: &Path) {
    match tokio::time::timeout(
        REQUEST_TIMEOUT,
        tokio::fs::remove_file(root.join("metrics.port")),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(Err(error)) => warn!("Failed to clear health endpoint port file: {error}"),
        Err(_) => warn!("Timed out clearing health endpoint port file"),
    }
}

/// Bind and publish best-effort; the caller owns cancellation and joining.
pub async fn spawn(
    port: u16,
    root: &Path,
    p2p: Arc<P2PNode>,
    protocol: Option<Arc<AntProtocol>>,
    shutdown: CancellationToken,
) -> Option<JoinHandle<()>> {
    clear_port_file(root).await;
    if port == 0 {
        return None;
    }
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
        Ok(listener) => listener,
        Err(error) => {
            warn!("Failed to bind health endpoint: {error}");
            return None;
        }
    };
    let address = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => {
            warn!("Failed to read health endpoint bound port: {error}");
            return None;
        }
    };
    match tokio::time::timeout(
        REQUEST_TIMEOUT,
        tokio::fs::write(root.join("metrics.port"), format!("{}\n", address.port())),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!("Failed to publish health endpoint port: {error}"),
        Err(_) => warn!("Timed out publishing health endpoint port"),
    }
    Some(tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (mut stream, _) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!("Health endpoint accept failed: {error}");
                    break;
                }
            };
            // No child tasks: cancellation drops even a fragmented read or blocked write.
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                _ = tokio::time::timeout(REQUEST_TIMEOUT, answer(&mut stream, &p2p, protocol.as_deref())) => {}
            }
        }
    }))
}

async fn answer(
    stream: &mut TcpStream,
    p2p: &P2PNode,
    protocol: Option<&AntProtocol>,
) -> io::Result<()> {
    let mut header = [0; MAX_HEADER_BYTES];
    let mut length = 0;
    loop {
        let n = stream.read(&mut header[length..]).await?;
        if n == 0 {
            return Ok(());
        }
        length += n;
        if header[..length]
            .windows(4)
            .any(|bytes| bytes == b"\r\n\r\n")
        {
            break;
        }
        if length == header.len() {
            return Ok(());
        }
    }
    let request = String::from_utf8_lossy(&header[..length]);
    let mut tokens = request.lines().next().unwrap_or("").split_whitespace();
    let method = tokens.next().unwrap_or("");
    let path = tokens.next().unwrap_or("");
    let (status, content_type, body) = if method != "GET" {
        (
            "405 Method Not Allowed",
            "application/json",
            "{\"error\":\"method not allowed\"}".to_string(),
        )
    } else if path == "/health" || path == "/metrics" {
        let snapshot = Snapshot::read(p2p, protocol).await;
        if path == "/health" {
            (
                "200 OK",
                "application/json",
                serde_json::to_string(&snapshot).map_err(io::Error::other)?,
            )
        } else {
            ("200 OK", "text/plain; version=0.0.4", snapshot.metrics())
        }
    } else {
        (
            "404 Not Found",
            "application/json",
            "{\"error\":\"not found\"}".to_string(),
        )
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn health_json_and_metrics_golden() {
        let snapshot = Snapshot {
            peer_id: "abcd".into(),
            version: "1.2.3",
            uptime_secs: 12,
            bootstrapped: true,
            peer_count: 3,
            routing_table_size: 4,
            storage_enabled: true,
            chunks_current: 5,
            chunks_written_total: 6,
            bytes_written_total: 7,
            chunks_served_total: 8,
            bytes_served_total: 9,
        };
        assert_eq!(serde_json::to_string(&snapshot).unwrap(),
            "{\"peer_id\":\"abcd\",\"version\":\"1.2.3\",\"uptime_secs\":12,\"bootstrapped\":true,\"peer_count\":3,\"routing_table_size\":4,\"storage_enabled\":true,\"chunks_current\":5,\"chunks_written_total\":6,\"bytes_written_total\":7,\"chunks_served_total\":8,\"bytes_served_total\":9}");
        assert_eq!(snapshot.metrics(), concat!(
            "# TYPE ant_uptime_seconds gauge\nant_uptime_seconds{peer_id=\"abcd\",version=\"1.2.3\"} 12\n",
            "# TYPE p2p_health_status gauge\np2p_health_status{peer_id=\"abcd\",version=\"1.2.3\"} 1\n",
            "# TYPE p2p_network_peer_count gauge\np2p_network_peer_count{peer_id=\"abcd\",version=\"1.2.3\"} 3\n",
            "# TYPE p2p_dht_routing_table_size gauge\np2p_dht_routing_table_size{peer_id=\"abcd\",version=\"1.2.3\"} 4\n",
            "# TYPE ant_storage_enabled gauge\nant_storage_enabled{peer_id=\"abcd\",version=\"1.2.3\"} 1\n",
            "# TYPE ant_chunks_current gauge\nant_chunks_current{peer_id=\"abcd\",version=\"1.2.3\"} 5\n",
            "# TYPE ant_chunks_written_total counter\nant_chunks_written_total{peer_id=\"abcd\",version=\"1.2.3\"} 6\n",
            "# TYPE ant_bytes_written_total counter\nant_bytes_written_total{peer_id=\"abcd\",version=\"1.2.3\"} 7\n",
            "# TYPE ant_chunks_served_total counter\nant_chunks_served_total{peer_id=\"abcd\",version=\"1.2.3\"} 8\n",
            "# TYPE ant_bytes_served_total counter\nant_bytes_served_total{peer_id=\"abcd\",version=\"1.2.3\"} 9\n",
        ));
    }
}

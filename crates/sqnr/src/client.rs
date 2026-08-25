//! A minimal HTTP/3-over-sQUIC client for talking to a sqex-style admin server.

use std::net::SocketAddr;

use bytes::Buf;
use squic::Config as SquicConfig;

/// One HTTP/3 connection to the admin server, reused across requests.
///
/// The underlying QUIC connection is kept alongside the HTTP/3 layer so a caller
/// can also send and receive **datagrams** on it (RFC 9221) — unreliable,
/// unordered, one packet per send. Requests and datagrams share the connection,
/// which is what lets a relayed session negotiate over HTTP/3 and then carry
/// real-time media over datagrams without opening anything new.
pub struct Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    conn: quinn::Connection,
    _drive: tokio::task::JoinHandle<()>,
}

impl Client {
    /// Dial `addr`, pinning the server's Ed25519 key. The transport key is
    /// ephemeral: admin authority is the command signature, not the connection.
    pub async fn connect(addr: SocketAddr, server_pub: &[u8; 32]) -> Result<Client, String> {
        Self::dial(
            addr,
            server_pub,
            SquicConfig {
                alpn_protocols: vec![b"h3".to_vec()],
                // Keep the connection alive across idle periods. The server's
                // idle timeout is 60s; pinging well inside that stops an idle
                // admin session from dying between actions.
                keep_alive: Some(std::time::Duration::from_secs(15)),
                // Fail fast when the server is down, wrong, or unreachable
                // (default is Quinn's 10s); an admin CLI should not hang.
                handshake_timeout: Some(std::time::Duration::from_secs(5)),
                ..Default::default()
            },
        )
        .await
    }

    /// Shared dial + HTTP/3 setup for both connection styles.
    async fn dial(
        addr: SocketAddr,
        server_pub: &[u8; 32],
        config: SquicConfig,
    ) -> Result<Client, String> {
        let conn = squic::dial(addr, server_pub, config)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        // Keep a handle on the QUIC connection before handing it to h3: it is
        // cheap to clone (an Arc inside) and is the only route to datagrams.
        let raw = conn.clone();
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| format!("h3 setup: {e}"))?;
        let drive = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Ok(Client {
            send,
            conn: raw,
            _drive: drive,
        })
    }

    /// Send one datagram. Unreliable and unordered by design: it is not
    /// retransmitted and may be dropped, which is the right trade for media
    /// where a late packet is worth less than a lost one.
    ///
    /// Fails if the payload exceeds what the path will carry — see
    /// [`max_datagram_size`](Self::max_datagram_size).
    pub fn send_datagram(&self, payload: Vec<u8>) -> Result<(), String> {
        self.conn
            .send_datagram(bytes::Bytes::from(payload))
            .map_err(|e| format!("send datagram: {e}"))
    }

    /// Await the next datagram from the server.
    pub async fn read_datagram(&self) -> Result<Vec<u8>, String> {
        self.conn
            .read_datagram()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| format!("read datagram: {e}"))
    }

    /// The largest datagram this path will currently carry, if datagrams are
    /// enabled on both ends. `None` means the peer does not support them.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// Dial `addr` *as* the identity behind `seed`, advertising it so the server
    /// can name this caller at accept without having registered it (SIP-3).
    ///
    /// Unlike [`connect`](Self::connect), which is anonymous, this pins the
    /// transport key to the identity's own key and puts the Ed25519 name in the
    /// Initial envelope. Use it where the connection *is* the assertion — a
    /// SIP-4 beacon — rather than where authority is a signature. `seed` is the
    /// identity's secret; only a software identity has one to give.
    pub async fn connect_as(
        addr: SocketAddr,
        server_pub: &[u8; 32],
        seed: &[u8; 32],
    ) -> Result<Client, String> {
        Self::dial(
            addr,
            server_pub,
            SquicConfig {
                alpn_protocols: vec![b"h3".to_vec()],
                keep_alive: Some(std::time::Duration::from_secs(15)),
                handshake_timeout: Some(std::time::Duration::from_secs(5)),
                client_key: Some(hex::encode(seed)),
                advertise_identity: true,
                // Sessions may carry real-time media over datagrams once
                // negotiated; enabling here costs nothing if unused.
                enable_datagrams: true,
                ..Default::default()
            },
        )
        .await
    }

    pub async fn get(&mut self, path: &str) -> Result<(u16, Vec<u8>), String> {
        self.request("GET", path, None).await
    }

    pub async fn post(&mut self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), String> {
        self.request("POST", path, Some(body)).await
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), String> {
        let req = http::Request::builder()
            .method(method)
            .uri(format!("https://sqex{path}"))
            .body(())
            .map_err(|e| e.to_string())?;
        let mut stream = self
            .send
            .send_request(req)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(b) = body {
            stream
                .send_data(bytes::Bytes::from(b))
                .await
                .map_err(|e| e.to_string())?;
        }
        stream.finish().await.map_err(|e| e.to_string())?;
        let resp = stream.recv_response().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let mut out = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
            while chunk.remaining() > 0 {
                let n = chunk.chunk().len();
                out.extend_from_slice(chunk.chunk());
                chunk.advance(n);
            }
        }
        Ok((status, out))
    }
}

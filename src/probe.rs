//! One measurement from this machine: DNS CHAOS (+ NSID), optional HTTP header
//! identification and optional raw-socket traceroute. Shared by the local
//! vantage and `catchment agent`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{HttpTarget, TraceMode};
use crate::model::Observation;
use crate::{dns, http_id, traceroute};

/// What to measure. Also the JSON body of the agent API (`POST /v1/probe`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    pub target: IpAddr,
    pub qname: String,
    #[serde(default)]
    pub nsid: bool,
    #[serde(default)]
    pub http: Option<HttpTarget>,
    #[serde(default)]
    pub traceroute: TraceMode,
    #[serde(default = "default_hops")]
    pub max_hops: u8,
    #[serde(default)]
    pub trace_port: Option<u16>,
}

fn default_hops() -> u8 {
    30
}

#[derive(Debug, Clone, Copy)]
pub struct ProbeLimits {
    pub timeout: Duration,
    pub attempts: u32,
}

/// Runs every requested measurement; failures are recorded in the observation,
/// never returned, so one broken method does not hide the others.
pub async fn run(req: &ProbeRequest, limits: ProbeLimits) -> Observation {
    let mut obs = Observation {
        target: Some(req.target),
        ..Observation::default()
    };
    let dns = dns::query_opts(
        SocketAddr::new(req.target, 53),
        &req.qname,
        dns::TYPE_TXT,
        dns::CLASS_CH,
        req.nsid,
        limits.timeout,
        limits.attempts,
    );
    let http = async {
        match &req.http {
            Some(h) => Some(http_id::identify(h, req.target, limits.timeout * 2).await),
            None => None,
        }
    };
    let trace = traceroute::run(
        req.target,
        traceroute::TraceOptions {
            mode: req.traceroute,
            max_hops: req.max_hops,
            port: req.trace_port,
            hop_timeout: limits.timeout.min(Duration::from_secs(3)),
        },
    );
    let (dns, http, trace) = tokio::join!(dns, http, trace);
    match dns {
        Ok((msg, rtt)) => {
            obs.rtt_ms = Some(rtt.as_secs_f64() * 1000.0);
            obs.chaos = msg.first_txt().map(str::to_string);
            obs.nsid = msg.nsid;
            if obs.chaos.is_none() && obs.nsid.is_none() {
                obs.error = Some("no TXT answer".into());
            }
        }
        Err(e) => obs.error = Some(dns::sanitize(e.to_string().as_bytes())),
    }
    match http {
        Some(Ok(v)) => obs.http_id = v,
        Some(Err(e)) => {
            let msg = dns::sanitize(format!("http: {e:#}").as_bytes());
            obs.error = Some(match obs.error.take() {
                Some(prev) => dns::sanitize(format!("{prev}; {msg}").as_bytes()),
                None => msg,
            });
        }
        None => {}
    }
    match trace {
        Ok(t) => {
            obs.last_hop = t.last_hop(req.target);
            if obs.rtt_ms.is_none() {
                obs.rtt_ms = t.dst_rtt_ms;
            }
            if t.hops.iter().all(|h| h.addr.is_none()) {
                obs.trace_error = Some(
                    "no ICMP replies (is inbound ICMP Time Exceeded blocked by a firewall?)".into(),
                );
            }
        }
        Err(traceroute::TraceError::Disabled) => {}
        Err(e) => {
            tracing::debug!(error = %e, "local traceroute skipped");
            obs.trace_error = Some(dns::sanitize(e.to_string().as_bytes()));
        }
    }
    // A vantage is only failed when nothing identified the PoP.
    if obs.http_id.is_some() {
        obs.error = obs.error.filter(|e| !e.starts_with("no TXT answer"));
    }
    obs
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn chaos_and_nsid_from_local_server() {
        // A fake DNS server on 127.0.0.1:53 is not possible without privileges,
        // so drive the DNS part through dns::query_opts on a high port instead
        // and check the observation mapping on a closed port.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, peer) = server.recv_from(&mut buf).await.unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            assert_eq!(buf[11], 1, "NSID request must carry an OPT record");
            let reply = dns::tests::txt_nsid_response(id, "id.server", b"fra1", b"fra1-a");
            server.send_to(&reply, peer).await.unwrap();
        });
        let (msg, _) = dns::query_opts(
            addr,
            "id.server",
            dns::TYPE_TXT,
            dns::CLASS_CH,
            true,
            Duration::from_secs(2),
            1,
        )
        .await
        .unwrap();
        assert_eq!(msg.nsid.as_deref(), Some("fra1-a"));

        let req = ProbeRequest {
            target: "127.0.0.1".parse().unwrap(),
            qname: "id.server".into(),
            nsid: true,
            http: None,
            traceroute: TraceMode::Off,
            max_hops: 30,
            trace_port: None,
        };
        let obs = run(
            &req,
            ProbeLimits {
                timeout: Duration::from_millis(200),
                attempts: 1,
            },
        )
        .await;
        assert_eq!(obs.target, req.target.into());
        // Usually nothing answers on 127.0.0.1:53; a local resolver may.
        assert!(obs.error.is_some() || obs.chaos.is_some() || obs.nsid.is_some());
        assert!(obs.trace_error.is_none());
    }
}

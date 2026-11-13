//! Local traceroute over raw sockets: ICMP echo, UDP or TCP SYN probes with an
//! increasing TTL / hop limit, ICMP Time Exceeded / Unreachable replies read
//! from a raw ICMP(v6) socket.
//!
//! Privileges: Linux needs CAP_NET_RAW (or root), macOS root, Windows an
//! elevated (Administrator) process and an inbound firewall rule for ICMP
//! Time Exceeded. Without them [`TraceError::Privilege`] is returned and the
//! caller keeps the CHAOS/NSID/HTTP result (graceful fallback).
//!
//! Replies are untrusted: every field is bounds checked and only replies that
//! quote one of our own probes (address, ports, ICMP id/sequence) count.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use thiserror::Error;

use crate::config::TraceMode;

pub const DEFAULT_UDP_PORT: u16 = 33434;
pub const DEFAULT_TCP_PORT: u16 = 443;
/// Consecutive silent hops after which the trace stops.
const GAP_LIMIT: u8 = 5;
const POLL: Duration = Duration::from_millis(50);
const PAYLOAD: &[u8; 16] = b"catchment-probe\0";

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("traceroute needs raw sockets: {0}")]
    Privilege(&'static str),
    #[error("traceroute disabled")]
    Disabled,
    #[error("traceroute I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    pub hops: Vec<Hop>,
    pub reached: bool,
    pub dst_rtt_ms: Option<f64>,
}

impl Trace {
    /// Last responding hop that is not the target itself (the PoP's edge).
    pub fn last_hop(&self, target: IpAddr) -> Option<IpAddr> {
        self.hops
            .iter()
            .filter_map(|h| h.addr)
            .rfind(|a| *a != target)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TraceOptions {
    pub mode: TraceMode,
    pub max_hops: u8,
    pub port: Option<u16>,
    pub hop_timeout: Duration,
}

fn privilege_message() -> &'static str {
    if cfg!(target_os = "linux") {
        "grant CAP_NET_RAW (setcap cap_net_raw+ep, or AmbientCapabilities=CAP_NET_RAW) or run as root"
    } else if cfg!(target_os = "macos") {
        "run as root on macOS"
    } else if cfg!(windows) {
        "run from an elevated (Administrator) process and allow inbound ICMP Time Exceeded in Windows Firewall"
    } else {
        "run with raw-socket privileges"
    }
}

/// Runs the trace on a blocking thread.
pub async fn run(target: IpAddr, opts: TraceOptions) -> Result<Trace, TraceError> {
    if opts.mode == TraceMode::Off {
        return Err(TraceError::Disabled);
    }
    tokio::task::spawn_blocking(move || trace_blocking(target, opts))
        .await
        .map_err(|e| TraceError::Io(io::Error::other(e.to_string())))?
}

/// Local address the OS would use to reach `target` (no packet is sent).
fn source_for(target: IpAddr) -> io::Result<IpAddr> {
    let unspecified: IpAddr = if target.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    };
    let s = UdpSocket::bind((unspecified, 0))?;
    s.connect((target, 53))?;
    Ok(s.local_addr()?.ip())
}

fn set_hop_limit(sock: SockRef<'_>, v6: bool, ttl: u8) -> io::Result<()> {
    if v6 {
        sock.set_unicast_hops_v6(u32::from(ttl))
    } else {
        sock.set_ttl_v4(u32::from(ttl))
    }
}

/// What identifies one of our probes inside a quoted packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Icmp { id: u16, seq: u16 },
    Udp { src: u16, dst: u16 },
    Tcp { src: u16, dst: u16 },
}

/// First 8 bytes of the transport header of the packet an ICMP error quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quote {
    pub proto: u8,
    pub dst: IpAddr,
    /// Ports (UDP/TCP) or id/sequence (ICMP echo).
    pub a: u16,
    pub b: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    TimeExceeded(Quote),
    Unreachable(Quote),
    Echo { id: u16, seq: u16 },
}

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn quote_v4(inner: &[u8]) -> Option<Quote> {
    if inner.first()? >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(inner[0] & 0x0f) * 4;
    let dst: [u8; 4] = inner.get(16..20)?.try_into().ok()?;
    let t = inner.get(ihl..ihl + 8)?;
    let proto = *inner.get(9)?;
    let (a, b) = if proto == PROTO_ICMP {
        (be16(t, 4)?, be16(t, 6)?)
    } else {
        (be16(t, 0)?, be16(t, 2)?)
    };
    Some(Quote {
        proto,
        dst: IpAddr::from(dst),
        a,
        b,
    })
}

fn quote_v6(inner: &[u8]) -> Option<Quote> {
    if inner.first()? >> 4 != 6 {
        return None;
    }
    let dst: [u8; 16] = inner.get(24..40)?.try_into().ok()?;
    let t = inner.get(40..48)?;
    let proto = *inner.get(6)?;
    let (a, b) = if proto == PROTO_ICMPV6 {
        (be16(t, 4)?, be16(t, 6)?)
    } else {
        (be16(t, 0)?, be16(t, 2)?)
    };
    Some(Quote {
        proto,
        dst: IpAddr::from(dst),
        a,
        b,
    })
}

/// Parse what a raw ICMP socket returned. IPv4 raw sockets include the IP
/// header; ICMPv6 raw sockets return the ICMPv6 message only.
pub fn parse_icmp(buf: &[u8], v6: bool) -> Option<Reply> {
    let icmp = if v6 {
        buf
    } else {
        if buf.first()? >> 4 != 4 || *buf.get(9)? != PROTO_ICMP {
            return None;
        }
        buf.get(usize::from(buf[0] & 0x0f) * 4..)?
    };
    let (kind, inner) = (*icmp.first()?, icmp.get(8..).unwrap_or_default());
    let quote = |inner| if v6 { quote_v6(inner) } else { quote_v4(inner) };
    match (v6, kind) {
        (false, 11) | (true, 3) => Some(Reply::TimeExceeded(quote(inner)?)),
        (false, 3) | (true, 1) => Some(Reply::Unreachable(quote(inner)?)),
        (false, 0) | (true, 129) => Some(Reply::Echo {
            id: be16(icmp, 4)?,
            seq: be16(icmp, 6)?,
        }),
        _ => None,
    }
}

fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for chunk in chunks {
        for &byte in *chunk {
            match odd.take() {
                Some(hi) => sum += u32::from(u16::from_be_bytes([hi, byte])),
                None => odd = Some(byte),
            }
        }
    }
    if let Some(hi) = odd {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// ICMP / ICMPv6 echo request. ICMPv6 checksums include a pseudo header;
/// kernels that compute it themselves simply overwrite ours.
pub fn echo_request(src: IpAddr, dst: IpAddr, id: u16, seq: u16) -> Vec<u8> {
    let v6 = dst.is_ipv6();
    let mut pkt = vec![if v6 { 128 } else { 8 }, 0, 0, 0];
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(PAYLOAD);
    let sum = match (src, dst) {
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let len = (pkt.len() as u32).to_be_bytes();
            checksum(&[
                &s.octets(),
                &d.octets(),
                &len,
                &[0, 0, 0, PROTO_ICMPV6],
                &pkt,
            ])
        }
        _ => checksum(&[&pkt]),
    };
    pkt[2..4].copy_from_slice(&sum.to_be_bytes());
    pkt
}

fn matches(reply: &Reply, key: Key, target: IpAddr, from: IpAddr) -> bool {
    let quoted = |q: &Quote| {
        q.dst == target
            && match key {
                Key::Icmp { id, seq } => {
                    (q.proto == PROTO_ICMP || q.proto == PROTO_ICMPV6) && (q.a, q.b) == (id, seq)
                }
                Key::Udp { src, dst } => q.proto == PROTO_UDP && (q.a, q.b) == (src, dst),
                Key::Tcp { src, dst } => q.proto == PROTO_TCP && (q.a, q.b) == (src, dst),
            }
    };
    match reply {
        Reply::TimeExceeded(q) | Reply::Unreachable(q) => quoted(q),
        Reply::Echo { id, seq } => {
            from == target && matches!(key, Key::Icmp { id: i, seq: s } if (i, s) == (*id, *seq))
        }
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn trace_blocking(target: IpAddr, opts: TraceOptions) -> Result<Trace, TraceError> {
    let v6 = target.is_ipv6();
    let (domain, icmp_proto) = if v6 {
        (Domain::IPV6, Protocol::ICMPV6)
    } else {
        (Domain::IPV4, Protocol::ICMPV4)
    };
    let local = source_for(target)?;
    let raw = Socket::new(domain, Type::RAW, Some(icmp_proto)).map_err(|e| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            TraceError::Privilege(privilege_message())
        } else {
            TraceError::Io(e)
        }
    })?;
    // Windows requires a bound raw socket before it delivers anything.
    raw.bind(&SocketAddr::new(local, 0).into())?;
    // A std UdpSocket is a thin wrapper over the descriptor: it gives safe
    // recv_from/send_to on the raw socket without MaybeUninit buffers.
    let raw: UdpSocket = raw.into();
    let udp = match opts.mode {
        TraceMode::Udp => Some(UdpSocket::bind((local, 0))?),
        _ => None,
    };
    let ident = rand_u16();
    let mut trace = Trace::default();
    let mut silent = 0u8;
    let mut buf = [0u8; 2048];
    for ttl in 1..=opts.max_hops.clamp(1, 64) {
        let started = Instant::now();
        let mut tcp: Option<Socket> = None;
        let key = match opts.mode {
            TraceMode::Off => return Err(TraceError::Disabled),
            TraceMode::Icmp => {
                set_hop_limit(SockRef::from(&raw), v6, ttl)?;
                let seq = u16::from(ttl);
                raw.send_to(&echo_request(local, target, ident, seq), (target, 0))?;
                Key::Icmp { id: ident, seq }
            }
            TraceMode::Udp => {
                let sock = udp.as_ref().ok_or(TraceError::Disabled)?;
                set_hop_limit(SockRef::from(sock), v6, ttl)?;
                let dst = opts
                    .port
                    .unwrap_or(DEFAULT_UDP_PORT)
                    .wrapping_add(u16::from(ttl) - 1);
                sock.send_to(PAYLOAD, (target, dst))?;
                Key::Udp {
                    src: sock.local_addr()?.port(),
                    dst,
                }
            }
            TraceMode::Tcp => {
                let dst = opts.port.unwrap_or(DEFAULT_TCP_PORT);
                let s = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
                set_hop_limit(SockRef::from(&s), v6, ttl)?;
                s.bind(&SocketAddr::new(local, 0).into())?;
                s.set_nonblocking(true)?;
                match s.connect(&SocketAddr::new(target, dst).into()) {
                    Ok(()) => {}
                    Err(e) if is_in_progress(&e) => {}
                    Err(e) => return Err(e.into()),
                }
                let src = s
                    .local_addr()?
                    .as_socket()
                    .map(|a| a.port())
                    .unwrap_or_default();
                tcp = Some(s);
                Key::Tcp { src, dst }
            }
        };
        let deadline = started + opts.hop_timeout;
        let mut hop = Hop {
            ttl,
            addr: None,
            rtt_ms: None,
        };
        let mut done = false;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if let Some(s) = &tcp {
                // SYN-ACK (connected) or RST (refused) both mean the target answered.
                let refused = matches!(s.take_error(), Ok(Some(e)) if e.kind() == io::ErrorKind::ConnectionRefused);
                if refused || s.peer_addr().is_ok() {
                    hop.addr = Some(target);
                    hop.rtt_ms = Some(ms(started.elapsed()));
                    done = true;
                    break;
                }
            }
            let wait = (deadline - now).min(if tcp.is_some() { POLL } else { deadline - now });
            raw.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
            match raw.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let Some(reply) = parse_icmp(&buf[..n], v6) else {
                        continue;
                    };
                    if !matches(&reply, key, target, from.ip()) {
                        continue;
                    }
                    hop.addr = Some(from.ip());
                    hop.rtt_ms = Some(ms(started.elapsed()));
                    // Echo reply, or an unreachable from anyone (port unreachable
                    // from the target, or a filter on the way): stop here.
                    done = !matches!(reply, Reply::TimeExceeded(_));
                    break;
                }
                Err(e) if is_timeout(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        drop(tcp);
        silent = if hop.addr.is_some() { 0 } else { silent + 1 };
        if hop.addr == Some(target) {
            trace.reached = true;
            trace.dst_rtt_ms = hop.rtt_ms;
        }
        trace.hops.push(hop);
        if done || silent >= GAP_LIMIT {
            break;
        }
    }
    Ok(trace)
}

fn is_in_progress(e: &io::Error) -> bool {
    // EINPROGRESS (Unix) / WSAEWOULDBLOCK (Windows).
    e.kind() == io::ErrorKind::WouldBlock
        || e.raw_os_error()
            == Some(if cfg!(windows) {
                10035
            } else {
                libc_einprogress()
            })
}

const fn libc_einprogress() -> i32 {
    if cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    )) {
        36
    } else {
        115
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn rand_u16() -> u16 {
    let mut b = [0u8; 2];
    if getrandom::fill(&mut b).is_err() {
        return std::process::id() as u16;
    }
    u16::from_be_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_header(proto: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        h
    }

    fn time_exceeded_v4(router: [u8; 4], quoted_proto: u8, transport: [u8; 8]) -> Vec<u8> {
        let mut p = v4_header(PROTO_ICMP, router, [192, 0, 2, 10]);
        p.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);
        p.extend(v4_header(quoted_proto, [192, 0, 2, 10], [198, 51, 100, 53]));
        p.extend_from_slice(&transport);
        p
    }

    #[test]
    fn parses_v4_time_exceeded_for_udp() {
        let pkt = time_exceeded_v4(
            [203, 0, 113, 1],
            PROTO_UDP,
            [0x9c, 0x40, 0x82, 0x9a, 0, 24, 0, 0],
        );
        let reply = parse_icmp(&pkt, false).unwrap();
        let target: IpAddr = "198.51.100.53".parse().unwrap();
        assert_eq!(
            reply,
            Reply::TimeExceeded(Quote {
                proto: PROTO_UDP,
                dst: target,
                a: 40000,
                b: 33434
            })
        );
        let router: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(matches(
            &reply,
            Key::Udp {
                src: 40000,
                dst: 33434
            },
            target,
            router
        ));
        assert!(!matches(
            &reply,
            Key::Udp {
                src: 40000,
                dst: 33435
            },
            target,
            router
        ));
        assert!(!matches(
            &reply,
            Key::Tcp {
                src: 40000,
                dst: 33434
            },
            target,
            router
        ));
        // Same probe, other destination: not ours.
        let other: IpAddr = "198.51.100.54".parse().unwrap();
        assert!(!matches(
            &reply,
            Key::Udp {
                src: 40000,
                dst: 33434
            },
            other,
            router
        ));
    }

    #[test]
    fn parses_v4_echo_quote_and_reply() {
        let pkt = time_exceeded_v4([203, 0, 113, 1], PROTO_ICMP, [8, 0, 0, 0, 0x12, 0x34, 0, 3]);
        let target: IpAddr = "198.51.100.53".parse().unwrap();
        let reply = parse_icmp(&pkt, false).unwrap();
        assert!(matches(
            &reply,
            Key::Icmp { id: 0x1234, seq: 3 },
            target,
            "203.0.113.1".parse().unwrap()
        ));

        let mut echo = v4_header(PROTO_ICMP, [198, 51, 100, 53], [192, 0, 2, 10]);
        echo.extend_from_slice(&[0, 0, 0, 0, 0x12, 0x34, 0, 7]);
        let reply = parse_icmp(&echo, false).unwrap();
        assert_eq!(reply, Reply::Echo { id: 0x1234, seq: 7 });
        assert!(matches(
            &reply,
            Key::Icmp { id: 0x1234, seq: 7 },
            target,
            target
        ));
        // An echo reply from someone else is not the target answering.
        assert!(!matches(
            &reply,
            Key::Icmp { id: 0x1234, seq: 7 },
            target,
            "203.0.113.9".parse().unwrap()
        ));
    }

    #[test]
    fn parses_v6_unreachable_for_tcp() {
        let target: Ipv6Addr = "2001:db8::53".parse().unwrap();
        let mut p = vec![1, 4, 0, 0, 0, 0, 0, 0];
        let mut inner = vec![0x60, 0, 0, 0, 0, 20, PROTO_TCP, 1];
        inner.extend_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
        inner.extend_from_slice(&target.octets());
        inner.extend_from_slice(&[0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 1]);
        p.extend(inner);
        let reply = parse_icmp(&p, true).unwrap();
        assert_eq!(
            reply,
            Reply::Unreachable(Quote {
                proto: PROTO_TCP,
                dst: IpAddr::V6(target),
                a: 50000,
                b: 443
            })
        );
    }

    #[test]
    fn rejects_garbage_and_truncation() {
        let pkt = time_exceeded_v4(
            [203, 0, 113, 1],
            PROTO_UDP,
            [0x9c, 0x40, 0x82, 0x9a, 0, 24, 0, 0],
        );
        for n in 0..pkt.len() {
            // Never panics; truncated quotes are dropped.
            let r = parse_icmp(&pkt[..n], false);
            assert!(r.is_none(), "accepted truncated packet of {n} bytes");
        }
        assert_eq!(parse_icmp(&[0x60; 3], false), None);
        assert_eq!(parse_icmp(&[200, 0, 0, 0], true), None);
    }

    #[test]
    fn checksums() {
        let src: IpAddr = "192.0.2.10".parse().unwrap();
        let pkt = echo_request(src, "198.51.100.53".parse().unwrap(), 0x1234, 1);
        assert_eq!(checksum(&[&pkt]), 0, "v4 echo checksum must verify");
        let s6: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let d6: Ipv6Addr = "2001:db8::53".parse().unwrap();
        let pkt = echo_request(s6.into(), d6.into(), 1, 2);
        let len = (pkt.len() as u32).to_be_bytes();
        assert_eq!(
            checksum(&[&s6.octets(), &d6.octets(), &len, &[0, 0, 0, 58], &pkt]),
            0
        );
    }

    #[test]
    fn last_hop_skips_target() {
        let target: IpAddr = "198.51.100.53".parse().unwrap();
        let hop = |ttl, a: Option<&str>| Hop {
            ttl,
            addr: a.map(|a| a.parse().unwrap()),
            rtt_ms: None,
        };
        let t = Trace {
            hops: vec![
                hop(1, Some("192.0.2.1")),
                hop(2, Some("203.0.113.7")),
                hop(3, None),
                hop(4, Some("198.51.100.53")),
            ],
            reached: true,
            dst_rtt_ms: None,
        };
        assert_eq!(t.last_hop(target), Some("203.0.113.7".parse().unwrap()));
    }

    #[tokio::test]
    async fn degrades_without_privileges_or_runs() {
        // Either works (privileged CI) or fails with a clear error; never panics.
        let opts = TraceOptions {
            mode: TraceMode::Icmp,
            max_hops: 2,
            port: None,
            hop_timeout: Duration::from_millis(200),
        };
        match run("127.0.0.1".parse().unwrap(), opts).await {
            Ok(t) => assert!(t.hops.len() <= 2),
            Err(e) => assert!(!e.to_string().is_empty()),
        }
        assert!(matches!(
            run(
                "127.0.0.1".parse().unwrap(),
                TraceOptions {
                    mode: TraceMode::Off,
                    ..opts
                }
            )
            .await,
            Err(TraceError::Disabled)
        ));
    }
}

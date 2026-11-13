//! Minimal DNS wire codec (queries, TXT/PTR answers) and a UDP client.
//!
//! Responses are untrusted: every read is bounds checked, compression pointers
//! are limited, and decoded text is sanitized before it leaves this module.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::net::UdpSocket;

pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const CLASS_IN: u16 = 1;
pub const CLASS_CH: u16 = 3;
pub const TYPE_OPT: u16 = 41;
/// EDNS option code for NSID (RFC 5001).
pub const OPT_NSID: u16 = 3;
/// UDP payload size advertised in the OPT record.
const EDNS_PAYLOAD: u16 = 1232;
const MAX_NSID: usize = 128;

const MAX_NAME: usize = 255;
const MAX_POINTERS: usize = 16;
const MAX_TEXT: usize = 255;
const MAX_RECORDS: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("truncated DNS message")]
    Truncated,
    #[error("malformed DNS name")]
    BadName,
    #[error("not a DNS response")]
    NotResponse,
    #[error("DNS response id mismatch")]
    IdMismatch,
    #[error("DNS rcode {0}")]
    Rcode(u8),
    #[error("DNS response truncated (TC bit)")]
    TcBit,
    #[error("invalid query name")]
    BadQuery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    Txt(String),
    Ptr(String),
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub answers: Vec<RData>,
    /// NSID option from the OPT record, if the server sent one.
    pub nsid: Option<String>,
}

impl Message {
    pub fn first_txt(&self) -> Option<&str> {
        self.answers.iter().find_map(|a| match a {
            RData::Txt(t) => Some(t.as_str()),
            _ => None,
        })
    }

    pub fn first_ptr(&self) -> Option<&str> {
        self.answers.iter().find_map(|a| match a {
            RData::Ptr(t) => Some(t.as_str()),
            _ => None,
        })
    }
}

/// Replace control and non-printable characters and cap the length, so
/// attacker-controlled answers cannot inject terminal escapes or huge strings.
pub fn sanitize(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(MAX_TEXT)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// NSID payload as text when printable, otherwise lowercase hex (RFC 5001
/// leaves the encoding to the operator).
pub fn decode_nsid(bytes: &[u8]) -> String {
    let bytes = &bytes[..bytes.len().min(MAX_NSID)];
    if !bytes.is_empty() && bytes.iter().all(|b| (0x20..0x7f).contains(b)) {
        sanitize(bytes)
    } else {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Query with an EDNS0 OPT record asking for NSID when `nsid` is set.
pub fn encode_query_opts(
    id: u16,
    qname: &str,
    qtype: u16,
    qclass: u16,
    nsid: bool,
) -> Result<Vec<u8>, DnsError> {
    let mut out = encode_query(id, qname, qtype, qclass)?;
    if nsid {
        out[11] = 1; // ARCOUNT = 1
        out.push(0); // root name
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&EDNS_PAYLOAD.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]); // extended rcode, version 0, flags
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&OPT_NSID.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // empty NSID = request
    }
    Ok(out)
}

pub fn encode_query(id: u16, qname: &str, qtype: u16, qclass: u16) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(48 + qname.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // flags: standard query, RD off
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1 AN=0 NS=0 AR=0
    let name = qname.strip_suffix('.').unwrap_or(qname);
    if name.is_empty() || name.len() > 253 {
        return Err(DnsError::BadQuery);
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::BadQuery);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    Ok(out)
}

fn read_u16(buf: &[u8], pos: usize) -> Result<u16, DnsError> {
    let b = buf.get(pos..pos + 2).ok_or(DnsError::Truncated)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

/// Decode a possibly-compressed name starting at `pos`.
/// Returns the dotted name and the offset just past it in the original stream.
fn read_name(buf: &[u8], mut pos: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<u8> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos).ok_or(DnsError::Truncated)? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    let next = end.unwrap_or(pos + 1);
                    return Ok((sanitize(&labels), next));
                }
                let label = buf.get(pos + 1..pos + 1 + len).ok_or(DnsError::Truncated)?;
                if !labels.is_empty() {
                    labels.push(b'.');
                }
                labels.extend_from_slice(label);
                if labels.len() > MAX_NAME {
                    return Err(DnsError::BadName);
                }
                pos += 1 + len;
            }
            0xC0 => {
                jumps += 1;
                if jumps > MAX_POINTERS {
                    return Err(DnsError::BadName);
                }
                let ptr = (read_u16(buf, pos)? & 0x3FFF) as usize;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                pos = ptr;
            }
            _ => return Err(DnsError::BadName),
        }
    }
}

fn decode_txt(rdata: &[u8]) -> Result<String, DnsError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        let chunk = rdata.get(i + 1..i + 1 + len).ok_or(DnsError::Truncated)?;
        out.extend_from_slice(chunk);
        i += 1 + len;
    }
    Ok(sanitize(&out))
}

/// Parse a DNS response. `expected_id` is checked when given (live queries);
/// RIPE Atlas `abuf` payloads are parsed without it.
pub fn parse_response(buf: &[u8], expected_id: Option<u16>) -> Result<Message, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let id = read_u16(buf, 0)?;
    if expected_id.is_some_and(|e| e != id) {
        return Err(DnsError::IdMismatch);
    }
    let flags = read_u16(buf, 2)?;
    if flags & 0x8000 == 0 {
        return Err(DnsError::NotResponse);
    }
    if flags & 0x0200 != 0 {
        return Err(DnsError::TcBit);
    }
    let rcode = (flags & 0x000F) as u8;
    if rcode != 0 {
        return Err(DnsError::Rcode(rcode));
    }
    let qdcount = read_u16(buf, 4)? as usize;
    let ancount = read_u16(buf, 6)? as usize;
    let nscount = read_u16(buf, 8)? as usize;
    let arcount = read_u16(buf, 10)? as usize;
    let mut pos = 12;
    for _ in 0..qdcount.min(MAX_RECORDS) {
        let (_, next) = read_name(buf, pos)?;
        pos = next + 4;
        if pos > buf.len() {
            return Err(DnsError::Truncated);
        }
    }
    let mut answers = Vec::new();
    for _ in 0..ancount.min(MAX_RECORDS) {
        let (_, next) = read_name(buf, pos)?;
        let rtype = read_u16(buf, next)?;
        let rdlen = read_u16(buf, next + 8)? as usize;
        let start = next + 10;
        let rdata = buf.get(start..start + rdlen).ok_or(DnsError::Truncated)?;
        answers.push(match rtype {
            TYPE_TXT => RData::Txt(decode_txt(rdata)?),
            TYPE_PTR => RData::Ptr(read_name(buf, start)?.0),
            other => RData::Other(other),
        });
        pos = start + rdlen;
    }
    // Authority records are skipped; additional records are scanned for OPT.
    // A missing or malformed additional section never invalidates the answers.
    let mut nsid = None;
    for i in 0..(nscount + arcount).min(MAX_RECORDS) {
        let Ok((_, next)) = read_name(buf, pos) else {
            break;
        };
        let (Ok(rtype), Ok(rdlen)) = (read_u16(buf, next), read_u16(buf, next + 8)) else {
            break;
        };
        let start = next + 10;
        let Some(rdata) = buf.get(start..start + rdlen as usize) else {
            break;
        };
        if i >= nscount && rtype == TYPE_OPT {
            nsid = nsid.or_else(|| find_nsid(rdata));
        }
        pos = start + rdlen as usize;
    }
    Ok(Message { id, answers, nsid })
}

/// Walk EDNS options (code, length, data) looking for NSID.
fn find_nsid(mut rdata: &[u8]) -> Option<String> {
    while rdata.len() >= 4 {
        let code = u16::from_be_bytes([rdata[0], rdata[1]]);
        let len = u16::from_be_bytes([rdata[2], rdata[3]]) as usize;
        let data = rdata.get(4..4 + len)?;
        if code == OPT_NSID && !data.is_empty() {
            return Some(decode_nsid(data));
        }
        rdata = &rdata[4 + len..];
    }
    None
}

/// Reverse-lookup name for an address (in-addr.arpa / ip6.arpa).
pub fn ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", byte & 0x0F, byte >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    // Fall back to the clock only if the OS RNG is unavailable.
    if getrandom::fill(&mut b).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        return nanos as u16;
    }
    u16::from_be_bytes(b)
}

/// Send one query over UDP with retries. Returns the parsed response and RTT.
pub async fn query(
    server: SocketAddr,
    qname: &str,
    qtype: u16,
    qclass: u16,
    timeout: Duration,
    attempts: u32,
) -> anyhow::Result<(Message, Duration)> {
    query_opts(server, qname, qtype, qclass, false, timeout, attempts).await
}

/// [`query`] with optional EDNS NSID request.
pub async fn query_opts(
    server: SocketAddr,
    qname: &str,
    qtype: u16,
    qclass: u16,
    nsid: bool,
    timeout: Duration,
    attempts: u32,
) -> anyhow::Result<(Message, Duration)> {
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(bind).await?;
    // connect() makes the kernel drop datagrams from any other source.
    sock.connect(server).await?;
    let mut buf = [0u8; 4096];
    let mut last_err = anyhow::anyhow!("no attempts made");
    for _ in 0..attempts.max(1) {
        let id = random_id();
        let packet = encode_query_opts(id, qname, qtype, qclass, nsid)?;
        let started = Instant::now();
        sock.send(&packet).await?;
        let deadline = started + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, sock.recv(&mut buf)).await {
                Err(_) => {
                    last_err = anyhow::anyhow!("timeout after {timeout:?}");
                    break;
                }
                Ok(Err(e)) => {
                    last_err = e.into();
                    break;
                }
                Ok(Ok(n)) => match parse_response(&buf[..n], Some(id)) {
                    Ok(msg) => return Ok((msg, started.elapsed())),
                    // A stray or spoofed packet with the wrong id: keep waiting.
                    Err(DnsError::IdMismatch) => continue,
                    Err(e) => {
                        last_err = e.into();
                        break;
                    }
                },
            }
        }
    }
    Err(last_err)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a response to `encode_query(id, qname, TXT, CH)` with one TXT answer
    /// using a compression pointer back to the question name.
    pub(crate) fn txt_response(id: u16, qname: &str, txt: &[u8]) -> Vec<u8> {
        let mut m = encode_query(id, qname, TYPE_TXT, CLASS_CH).unwrap();
        m[2] = 0x84; // QR + AA
        m[7] = 1; // ANCOUNT = 1
        m.extend_from_slice(&[0xC0, 12]);
        m.extend_from_slice(&TYPE_TXT.to_be_bytes());
        m.extend_from_slice(&CLASS_CH.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(&((txt.len() + 1) as u16).to_be_bytes());
        m.push(txt.len() as u8);
        m.extend_from_slice(txt);
        m
    }

    #[test]
    fn encodes_chaos_query() {
        let q = encode_query(0x1234, "hostname.bind", TYPE_TXT, CLASS_CH).unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..], b"\x08hostname\x04bind\x00\x00\x10\x00\x03");
        assert!(encode_query(1, "a..b", TYPE_TXT, CLASS_CH).is_err());
        assert!(encode_query(1, &"x".repeat(64), TYPE_TXT, CLASS_CH).is_err());
    }

    #[test]
    fn parses_txt_answer() {
        let r = txt_response(7, "hostname.bind", b"fra1.example");
        let m = parse_response(&r, Some(7)).unwrap();
        assert_eq!(m.first_txt(), Some("fra1.example"));
        assert_eq!(parse_response(&r, Some(8)), Err(DnsError::IdMismatch));
    }

    #[test]
    fn sanitizes_control_characters() {
        let r = txt_response(7, "id.server", b"ist1\x1b[31m\n");
        let m = parse_response(&r, None).unwrap();
        assert_eq!(m.first_txt(), Some("ist1?[31m?"));
    }

    #[test]
    fn rejects_every_truncation() {
        let r = txt_response(7, "hostname.bind", b"fra1");
        for n in 0..r.len() {
            assert!(parse_response(&r[..n], None).is_err(), "len {n} accepted");
        }
    }

    #[test]
    fn rejects_pointer_loop_and_bad_flags() {
        let mut r = txt_response(7, "hostname.bind", b"fra1");
        let ans = 12 + 15 + 4; // header + qname + qtype/qclass
        r[ans] = 0xC0;
        r[ans + 1] = ans as u8; // points at itself
        assert_eq!(parse_response(&r, None), Err(DnsError::BadName));

        let mut q = txt_response(7, "hostname.bind", b"fra1");
        q[2] = 0; // QR cleared
        assert_eq!(parse_response(&q, None), Err(DnsError::NotResponse));

        let mut e = txt_response(7, "hostname.bind", b"fra1");
        e[3] = 0x03; // NXDOMAIN
        assert_eq!(parse_response(&e, None), Err(DnsError::Rcode(3)));
    }

    /// `txt_response` plus an OPT record carrying `nsid`.
    pub(crate) fn txt_nsid_response(id: u16, qname: &str, txt: &[u8], nsid: &[u8]) -> Vec<u8> {
        let mut m = txt_response(id, qname, txt);
        m[11] = 1;
        m.push(0);
        m.extend_from_slice(&TYPE_OPT.to_be_bytes());
        m.extend_from_slice(&1232u16.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(&((nsid.len() + 4) as u16).to_be_bytes());
        m.extend_from_slice(&OPT_NSID.to_be_bytes());
        m.extend_from_slice(&(nsid.len() as u16).to_be_bytes());
        m.extend_from_slice(nsid);
        m
    }

    #[test]
    fn encodes_nsid_request() {
        let q = encode_query_opts(1, "id.server", TYPE_TXT, CLASS_CH, true).unwrap();
        assert_eq!(q[11], 1);
        assert!(q.ends_with(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0]));
        let plain = encode_query_opts(1, "id.server", TYPE_TXT, CLASS_CH, false).unwrap();
        assert_eq!(
            plain,
            encode_query(1, "id.server", TYPE_TXT, CLASS_CH).unwrap()
        );
    }

    #[test]
    fn parses_nsid_option() {
        let r = txt_nsid_response(7, "hostname.bind", b"fra1", b"fra1-ns2");
        let m = parse_response(&r, Some(7)).unwrap();
        assert_eq!(m.first_txt(), Some("fra1"));
        assert_eq!(m.nsid.as_deref(), Some("fra1-ns2"));
        let bin = txt_nsid_response(7, "hostname.bind", b"fra1", &[0x00, 0xff, 0x10]);
        assert_eq!(
            parse_response(&bin, None).unwrap().nsid.as_deref(),
            Some("00ff10")
        );
        // A truncated OPT record keeps the answer and drops the NSID.
        let cut = &r[..r.len() - 3];
        let m = parse_response(cut, None).unwrap();
        assert_eq!((m.first_txt(), m.nsid.as_deref()), (Some("fra1"), None));
    }

    #[test]
    fn parses_ptr_answer() {
        let qname = ptr_name("192.0.2.7".parse().unwrap());
        assert_eq!(qname, "7.2.0.192.in-addr.arpa");
        let mut m = encode_query(9, &qname, TYPE_PTR, CLASS_IN).unwrap();
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 1;
        m.extend_from_slice(&[0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 60]);
        let target = b"\x02ae\x04nyc1\x07example\x03net\x00";
        m.extend_from_slice(&(target.len() as u16).to_be_bytes());
        m.extend_from_slice(target);
        let msg = parse_response(&m, Some(9)).unwrap();
        assert_eq!(msg.first_ptr(), Some("ae.nyc1.example.net"));
    }

    #[test]
    fn ipv6_ptr_name() {
        let n = ptr_name("2001:db8::1".parse().unwrap());
        assert!(n.starts_with("1.0.0.0."));
        assert!(n.ends_with(".8.b.d.0.1.0.0.2.ip6.arpa"));
    }

    #[tokio::test]
    async fn udp_query_roundtrip() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            // A wrong-id reply first must be ignored by the client.
            let decoy = txt_response(id.wrapping_add(1), "hostname.bind", b"evil");
            server.send_to(&decoy, peer).await.unwrap();
            assert!(n > 12);
            let reply = txt_response(id, "hostname.bind", b"ams1.example");
            server.send_to(&reply, peer).await.unwrap();
        });
        let (msg, _) = query(
            addr,
            "hostname.bind",
            TYPE_TXT,
            CLASS_CH,
            Duration::from_secs(2),
            1,
        )
        .await
        .unwrap();
        assert_eq!(msg.first_txt(), Some("ams1.example"));
    }
}

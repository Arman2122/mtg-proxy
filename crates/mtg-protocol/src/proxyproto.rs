//! Incremental HAProxy PROXY protocol v1 & v2 parser and stack-allocated v2 encoder.
//!
//! Designed to execute asynchronously inside `ConnPhase::ProxyProto` under the
//! per-connection handshake timeout — never blocking the listener accept loop.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use thiserror::Error;

/// PROXY protocol v1 ASCII prefix.
pub const V1_PREFIX: &[u8; 6] = b"PROXY ";

/// Maximum legal PROXY protocol v1 header length including `\r\n`.
pub const V1_MAX_LEN: usize = 107;

/// PROXY protocol v2 12-byte binary signature.
pub const V2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

/// Fixed PROXY protocol v2 header size (before address payload + TLVs).
pub const V2_HEADER_LEN: usize = 16;

/// Maximum TLV + address length accepted in a PROXY v2 header to bound pre-auth buffering.
pub const V2_MAX_PAYLOAD_LEN: usize = 4096;

/// Policy controlling whether incoming connections must carry a PROXY header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtoMode {
    /// Reject connections lacking a valid PROXY v1/v2 header.
    Required,
    /// Accept PROXY v1/v2 if present; otherwise leave all bytes untouched.
    Optional,
}

/// Decoded PROXY protocol header metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyHeader {
    pub version: u8,
    /// `None` for v1 `UNKNOWN` or v2 `LOCAL` / `UNSPEC` (peer addresses remain unchanged).
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
}

/// Incremental parsing outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyParseStatus {
    /// Need more bytes from the socket.
    Incomplete,
    /// No PROXY header present (only returned in [`ProxyProtoMode::Optional`]);
    /// caller must replay all buffered bytes to the inner protocol parser.
    NotPresent,
    /// Valid PROXY header decoded; `consumed` bytes should be discarded from the buffer.
    Complete {
        header: ProxyHeader,
        consumed: usize,
    },
}

/// Errors returned on malformed or disallowed PROXY protocol headers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProxyProtoError {
    #[error("missing required PROXY protocol header")]
    MissingRequired,
    #[error("PROXY v1 header exceeds maximum 107 bytes")]
    V1TooLong,
    #[error("malformed PROXY v1 header")]
    V1Malformed,
    #[error("unsupported PROXY v2 version/command byte {0:#x}")]
    V2InvalidVersionCommand(u8),
    #[error("unsupported PROXY v2 family/protocol byte {0:#x}")]
    V2InvalidFamilyProtocol(u8),
    #[error("PROXY v2 payload length {0} exceeds maximum {V2_MAX_PAYLOAD_LEN}")]
    V2PayloadTooLarge(usize),
    #[error("PROXY v2 address payload truncated")]
    V2TruncatedAddress,
}

/// Incrementally parse a PROXY protocol v1 or v2 header from `buf`.
pub fn parse_proxy_header(
    buf: &[u8],
    mode: ProxyProtoMode,
) -> Result<ProxyParseStatus, ProxyProtoError> {
    if buf.is_empty() {
        return Ok(ProxyParseStatus::Incomplete);
    }

    // Check if `buf` matches prefix of V2_SIGNATURE or V1_PREFIX.
    let v2_prefix_match = buf.iter().zip(V2_SIGNATURE.iter()).all(|(a, b)| a == b);
    let v1_prefix_match = buf.iter().zip(V1_PREFIX.iter()).all(|(a, b)| a == b);

    if !v2_prefix_match && !v1_prefix_match {
        return match mode {
            ProxyProtoMode::Optional => Ok(ProxyParseStatus::NotPresent),
            ProxyProtoMode::Required => Err(ProxyProtoError::MissingRequired),
        };
    }

    if v2_prefix_match {
        if buf.len() < V2_HEADER_LEN {
            return Ok(ProxyParseStatus::Incomplete);
        }
        return parse_v2(buf);
    }

    // v1_prefix_match is true
    if buf.len() < V1_PREFIX.len() {
        return Ok(ProxyParseStatus::Incomplete);
    }
    parse_v1(buf)
}

fn parse_v1(buf: &[u8]) -> Result<ProxyParseStatus, ProxyProtoError> {
    let search_len = buf.len().min(V1_MAX_LEN);
    let crlf = buf[..search_len].windows(2).position(|w| w == b"\r\n");

    let Some(end) = crlf else {
        if buf.len() >= V1_MAX_LEN {
            return Err(ProxyProtoError::V1TooLong);
        }
        return Ok(ProxyParseStatus::Incomplete);
    };

    let line = std::str::from_utf8(&buf[..end]).map_err(|_| ProxyProtoError::V1Malformed)?;
    let consumed = end + 2;

    // Must start with "PROXY "
    let rest = line
        .strip_prefix("PROXY ")
        .ok_or(ProxyProtoError::V1Malformed)?;
    let mut parts = rest.split(' ');
    let proto = parts.next().ok_or(ProxyProtoError::V1Malformed)?;

    if proto == "UNKNOWN" {
        return Ok(ProxyParseStatus::Complete {
            header: ProxyHeader {
                version: 1,
                source: None,
                destination: None,
            },
            consumed,
        });
    }

    let (Some(src_ip_s), Some(dst_ip_s), Some(src_port_s), Some(dst_port_s), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(ProxyProtoError::V1Malformed);
    };

    let src_port: u16 = src_port_s
        .parse()
        .map_err(|_| ProxyProtoError::V1Malformed)?;
    let dst_port: u16 = dst_port_s
        .parse()
        .map_err(|_| ProxyProtoError::V1Malformed)?;

    let (source, destination) = match proto {
        "TCP4" => {
            let sip: Ipv4Addr = src_ip_s.parse().map_err(|_| ProxyProtoError::V1Malformed)?;
            let dip: Ipv4Addr = dst_ip_s.parse().map_err(|_| ProxyProtoError::V1Malformed)?;
            (
                SocketAddr::V4(SocketAddrV4::new(sip, src_port)),
                SocketAddr::V4(SocketAddrV4::new(dip, dst_port)),
            )
        }
        "TCP6" => {
            let sip: Ipv6Addr = src_ip_s.parse().map_err(|_| ProxyProtoError::V1Malformed)?;
            let dip: Ipv6Addr = dst_ip_s.parse().map_err(|_| ProxyProtoError::V1Malformed)?;
            (
                SocketAddr::V6(SocketAddrV6::new(sip, src_port, 0, 0)),
                SocketAddr::V6(SocketAddrV6::new(dip, dst_port, 0, 0)),
            )
        }
        _ => return Err(ProxyProtoError::V1Malformed),
    };

    Ok(ProxyParseStatus::Complete {
        header: ProxyHeader {
            version: 1,
            source: Some(source),
            destination: Some(destination),
        },
        consumed,
    })
}

fn parse_v2(buf: &[u8]) -> Result<ProxyParseStatus, ProxyProtoError> {
    let ver_cmd = buf[12];
    if (ver_cmd >> 4) != 0x02 {
        return Err(ProxyProtoError::V2InvalidVersionCommand(ver_cmd));
    }
    let cmd = ver_cmd & 0x0f;
    if cmd > 0x01 {
        return Err(ProxyProtoError::V2InvalidVersionCommand(ver_cmd));
    }

    let fam_proto = buf[13];
    let payload_len = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
    if payload_len > V2_MAX_PAYLOAD_LEN {
        return Err(ProxyProtoError::V2PayloadTooLarge(payload_len));
    }

    let total_len = V2_HEADER_LEN + payload_len;
    if buf.len() < total_len {
        return Ok(ProxyParseStatus::Incomplete);
    }

    // LOCAL (0x00) ignores address block and keeps actual peer socket addresses.
    if cmd == 0x00 {
        return Ok(ProxyParseStatus::Complete {
            header: ProxyHeader {
                version: 2,
                source: None,
                destination: None,
            },
            consumed: total_len,
        });
    }

    let payload = &buf[V2_HEADER_LEN..total_len];
    let (source, destination) = match fam_proto {
        0x00 => (None, None), // UNSPEC
        0x11 | 0x12 => {
            // AF_INET STREAM / DGRAM (12 bytes: 4 src + 4 dst + 2 sport + 2 dport)
            if payload.len() < 12 {
                return Err(ProxyProtoError::V2TruncatedAddress);
            }
            let sip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let dip = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            let sport = u16::from_be_bytes([payload[8], payload[9]]);
            let dport = u16::from_be_bytes([payload[10], payload[11]]);
            (
                Some(SocketAddr::V4(SocketAddrV4::new(sip, sport))),
                Some(SocketAddr::V4(SocketAddrV4::new(dip, dport))),
            )
        }
        0x21 | 0x22 => {
            // AF_INET6 STREAM / DGRAM (36 bytes: 16 src + 16 dst + 2 sport + 2 dport)
            if payload.len() < 36 {
                return Err(ProxyProtoError::V2TruncatedAddress);
            }
            let sip_bytes: [u8; 16] = payload[0..16].try_into().expect("16 bytes");
            let dip_bytes: [u8; 16] = payload[16..32].try_into().expect("16 bytes");
            let sport = u16::from_be_bytes([payload[32], payload[33]]);
            let dport = u16::from_be_bytes([payload[34], payload[35]]);
            (
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sip_bytes),
                    sport,
                    0,
                    0,
                ))),
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(dip_bytes),
                    dport,
                    0,
                    0,
                ))),
            )
        }
        0x31 | 0x32 => {
            // AF_UNIX (216 bytes) -> no IP address to override
            if payload.len() < 216 {
                return Err(ProxyProtoError::V2TruncatedAddress);
            }
            (None, None)
        }
        _ => return Err(ProxyProtoError::V2InvalidFamilyProtocol(fam_proto)),
    };

    Ok(ProxyParseStatus::Complete {
        header: ProxyHeader {
            version: 2,
            source,
            destination,
        },
        consumed: total_len,
    })
}

/// Stack-allocated PROXY v2 TCP header (28 bytes for IPv4, 52 bytes for IPv6).
///
/// Zero heap allocations — ideal for coalescing with the first `DATA` write
/// via `writev` in WebRelay and domain-fronting.
#[derive(Debug, Clone, Copy)]
pub struct EncodedProxyV2 {
    buf: [u8; 52],
    len: usize,
}

impl EncodedProxyV2 {
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Encode a PROXY protocol v2 TCP header onto the stack (`28` or `52` bytes).
///
/// Automatically unmaps IPv4-mapped IPv6 addresses when both endpoints are IPv4
/// (emitting compact 28-byte TCPv4), and promotes IPv4 to IPv4-mapped IPv6
/// (`::ffff:a.b.c.d`) when mixing IPv4 and IPv6 endpoints (e.g., IPv6 client
/// fronted to `127.0.0.1` backend).
pub fn encode_v2_tcp(src: SocketAddr, dst: SocketAddr) -> EncodedProxyV2 {
    let normalize = |a: SocketAddr| -> SocketAddr {
        match a {
            SocketAddr::V4(v4) => SocketAddr::V4(v4),
            SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
                Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
                None => SocketAddr::V6(v6),
            },
        }
    };

    let src = normalize(src);
    let dst = normalize(dst);

    let mut out = [0u8; 52];
    out[..12].copy_from_slice(&V2_SIGNATURE);
    out[12] = 0x21; // version 2, PROXY command

    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            out[13] = 0x11; // AF_INET | STREAM
            out[14..16].copy_from_slice(&12u16.to_be_bytes());
            out[16..20].copy_from_slice(&s.ip().octets());
            out[20..24].copy_from_slice(&d.ip().octets());
            out[24..26].copy_from_slice(&s.port().to_be_bytes());
            out[26..28].copy_from_slice(&d.port().to_be_bytes());
            EncodedProxyV2 { buf: out, len: 28 }
        }
        (s, d) => {
            let to_v6 = |ip: IpAddr| -> Ipv6Addr {
                match ip {
                    IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                    IpAddr::V6(v6) => v6,
                }
            };
            out[13] = 0x21; // AF_INET6 | STREAM
            out[14..16].copy_from_slice(&36u16.to_be_bytes());
            out[16..32].copy_from_slice(&to_v6(s.ip()).octets());
            out[32..48].copy_from_slice(&to_v6(d.ip()).octets());
            out[48..50].copy_from_slice(&s.port().to_be_bytes());
            out[50..52].copy_from_slice(&d.port().to_be_bytes());
            EncodedProxyV2 { buf: out, len: 52 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_parse_tcp4_tcp6_unknown_and_optional() {
        let h = b"PROXY TCP4 198.51.100.7 203.0.113.9 50123 443\r\nEXTRA";
        let ProxyParseStatus::Complete { header, consumed } =
            parse_proxy_header(h, ProxyProtoMode::Required).unwrap()
        else {
            panic!("expected Complete");
        };
        assert_eq!(consumed, h.len() - 5);
        assert_eq!(header.version, 1);
        assert_eq!(header.source, Some("198.51.100.7:50123".parse().unwrap()));
        assert_eq!(header.destination, Some("203.0.113.9:443".parse().unwrap()));

        let unk = b"PROXY UNKNOWN ignored stuff\r\n";
        let ProxyParseStatus::Complete { header, consumed } =
            parse_proxy_header(unk, ProxyProtoMode::Required).unwrap()
        else {
            panic!("expected Complete");
        };
        assert_eq!(consumed, unk.len());
        assert_eq!(header.source, None);

        // Non-PROXY TLS ClientHello in Optional mode -> NotPresent
        let tls = [0x16, 0x03, 0x01, 0x00, 0x50];
        assert_eq!(
            parse_proxy_header(&tls, ProxyProtoMode::Optional).unwrap(),
            ProxyParseStatus::NotPresent
        );
        assert_eq!(
            parse_proxy_header(&tls, ProxyProtoMode::Required).unwrap_err(),
            ProxyProtoError::MissingRequired
        );
    }

    #[test]
    fn v2_encode_and_parse_v4_v6_and_mixed_family() {
        let s4: SocketAddr = "198.51.100.1:12345".parse().unwrap();
        let d4: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let enc4 = encode_v2_tcp(s4, d4);
        assert_eq!(enc4.as_slice().len(), 28);

        // Byte-by-byte incremental parse!
        for i in 0..enc4.as_slice().len() {
            assert_eq!(
                parse_proxy_header(&enc4.as_slice()[..i], ProxyProtoMode::Required).unwrap(),
                ProxyParseStatus::Incomplete
            );
        }
        let ProxyParseStatus::Complete { header, consumed } =
            parse_proxy_header(enc4.as_slice(), ProxyProtoMode::Required).unwrap()
        else {
            panic!("expected Complete");
        };
        assert_eq!(consumed, 28);
        assert_eq!(header.source, Some(s4));
        assert_eq!(header.destination, Some(d4));

        // Mixed IPv6 client + IPv4 local backend -> 52-byte IPv6 header
        let s6: SocketAddr = "[2001:db8::42]:54321".parse().unwrap();
        let enc_mixed = encode_v2_tcp(s6, d4);
        assert_eq!(enc_mixed.as_slice().len(), 52);
        let ProxyParseStatus::Complete { header, consumed } =
            parse_proxy_header(enc_mixed.as_slice(), ProxyProtoMode::Required).unwrap()
        else {
            panic!("expected Complete");
        };
        assert_eq!(consumed, 52);
        assert_eq!(header.source, Some(s6));
        assert_eq!(
            header.destination,
            Some("[::ffff:127.0.0.1]:443".parse().unwrap())
        );
    }
}

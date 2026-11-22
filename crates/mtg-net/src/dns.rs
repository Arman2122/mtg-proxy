//! Asynchronous DNS resolver backed by `hickory-resolver`:
//! supports system `/etc/resolv.conf`, custom UDP+TCP (`ip[:port]`),
//! DNS-over-TLS (`tls://...`), and DNS-over-HTTPS (`https://...` or legacy `doh-ip`),
//! with bounded caching and `PreferIp` address ordering.

use std::io;
use std::net::{IpAddr, SocketAddr};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use mtg_config::PreferIp;

/// Configured asynchronous DNS resolver for domain fronting, DC updates, and
/// upstream proxy hostname resolution.
#[derive(Debug, Clone)]
pub struct DnsResolver {
    inner: TokioResolver,
    prefer_ip: PreferIp,
}

impl DnsResolver {
    /// Build a [`DnsResolver`] from `network.dns`, legacy `network.doh_ip`,
    /// and `prefer-ip`.
    ///
    /// Accepted `dns_spec` forms:
    /// - `None` / `Some("")` / `Some("system")`: OS `/etc/resolv.conf` (unless `doh_ip` is set)
    /// - `Some("tls://<ip>[:port][#<sni>]")` or `Some("tls://<host>")`: DNS-over-TLS
    /// - `Some("https://<ip>[:port][#<sni>]")` or `Some("https://<host>")`: DNS-over-HTTPS
    /// - `Some("<ip>[:port]")`: plain UDP+TCP resolver
    pub fn build(
        dns_spec: Option<&str>,
        doh_ip: Option<IpAddr>,
        prefer_ip: PreferIp,
    ) -> io::Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 4096;
        opts.ip_strategy = match prefer_ip {
            PreferIp::OnlyIpv4 => LookupIpStrategy::Ipv4Only,
            PreferIp::OnlyIpv6 => LookupIpStrategy::Ipv6Only,
            PreferIp::PreferIpv4 => LookupIpStrategy::Ipv4thenIpv6,
            PreferIp::PreferIpv6 => LookupIpStrategy::Ipv6thenIpv4,
        };

        let spec = dns_spec.map_or("", str::trim);
        let resolver = if spec.is_empty() || spec.eq_ignore_ascii_case("system") {
            if let Some(ip) = doh_ip {
                let sni = default_doh_sni(ip);
                let group = NameServerConfigGroup::from_ips_https(&[ip], 443, sni, true);
                let cfg = ResolverConfig::from_parts(None, vec![], group);
                TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default())
                    .with_options(opts)
                    .build()
            } else if let Ok(mut b) = TokioResolver::builder_tokio() {
                *b.options_mut() = opts;
                b.build()
            } else {
                let cfg = ResolverConfig::cloudflare();
                TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default())
                    .with_options(opts)
                    .build()
            }
        } else if let Some(rest) = spec.strip_prefix("tls://") {
            let (ip, port, sni) = parse_encrypted_dns_spec(rest, 853)?;
            let group = NameServerConfigGroup::from_ips_tls(&[ip], port, sni, true);
            let cfg = ResolverConfig::from_parts(None, vec![], group);
            TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default())
                .with_options(opts)
                .build()
        } else if let Some(rest) = spec.strip_prefix("https://") {
            let (ip, port, sni) = parse_encrypted_dns_spec(rest, 443)?;
            let group = NameServerConfigGroup::from_ips_https(&[ip], port, sni, true);
            let cfg = ResolverConfig::from_parts(None, vec![], group);
            TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default())
                .with_options(opts)
                .build()
        } else {
            let (ip, port) = parse_clear_dns_spec(spec, 53)?;
            let group = NameServerConfigGroup::from_ips_clear(&[ip], port, true);
            let cfg = ResolverConfig::from_parts(None, vec![], group);
            TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default())
                .with_options(opts)
                .build()
        };

        Ok(Self {
            inner: resolver,
            prefer_ip,
        })
    }

    /// Resolve `host` into ordered IP addresses honoring [`PreferIp`].
    ///
    /// Literal IP strings short-circuit with zero network I/O.
    /// Resolve `host` and attach `port` to every returned IP address.
    pub async fn resolve_host(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<Vec<std::net::SocketAddr>> {
        let ips = self.resolve_ips(host).await?;
        Ok(ips
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, port))
            .collect())
    }

    pub async fn resolve_ips(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let lookup = self
            .inner
            .lookup_ip(host)
            .await
            .map_err(|e| io::Error::other(format!("DNS lookup for {host:?} failed: {e}")))?;

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for ip in lookup.iter() {
            match ip {
                IpAddr::V4(_) => v4.push(ip),
                IpAddr::V6(_) => v6.push(ip),
            }
        }
        let out = match self.prefer_ip {
            PreferIp::OnlyIpv4 => v4,
            PreferIp::OnlyIpv6 => v6,
            PreferIp::PreferIpv4 => {
                v4.extend(v6);
                v4
            }
            PreferIp::PreferIpv6 => {
                v6.extend(v4);
                v6
            }
        };
        if out.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("DNS returned no matching records for {host:?}"),
            ));
        }
        Ok(out)
    }

    /// Resolve `host:port` to ordered [`SocketAddr`]s.
    pub async fn resolve_socket_addrs(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let ips = self.resolve_ips(host).await?;
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

fn default_doh_sni(ip: IpAddr) -> String {
    match ip.to_string().as_str() {
        "1.1.1.1" | "1.0.0.1" | "2606:4700:4700::1111" | "2606:4700:4700::1001" => {
            "cloudflare-dns.com".to_owned()
        }
        "8.8.8.8" | "8.8.4.4" | "2001:4860:4860::8888" | "2001:4860:4860::8844" => {
            "dns.google".to_owned()
        }
        "9.9.9.9" | "149.112.112.112" | "2620:fe::fe" => "dns.quad9.net".to_owned(),
        other => other.to_owned(),
    }
}

fn parse_clear_dns_spec(spec: &str, default_port: u16) -> io::Result<(IpAddr, u16)> {
    if let Ok(sa) = spec.parse::<SocketAddr>() {
        return Ok((sa.ip(), sa.port()));
    }
    let ip: IpAddr = spec
        .trim_matches(|c| c == '[' || c == ']')
        .parse()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DNS server {spec:?}"),
            )
        })?;
    Ok((ip, default_port))
}

fn parse_encrypted_dns_spec(rest: &str, default_port: u16) -> io::Result<(IpAddr, u16, String)> {
    let authority = rest.split('/').next().unwrap_or(rest);
    let (addr_part, explicit_sni) = match authority.split_once('#') {
        Some((a, s)) => (a, Some(s.to_owned())),
        None => (authority, None),
    };
    let (ip, port) = parse_clear_dns_spec(addr_part, default_port)?;
    let sni = explicit_sni.unwrap_or_else(|| default_doh_sni(ip));
    Ok((ip, port, sni))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dns_resolver_builds_for_system_udp_dot_and_doh_and_resolves_literals() {
        for (spec, doh) in [
            (None, None),
            (Some("1.1.1.1:53"), None),
            (Some("tls://1.1.1.1:853#cloudflare-dns.com"), None),
            (Some("https://9.9.9.9/dns-query"), None),
            (None, Some("1.1.1.1".parse().unwrap())),
        ] {
            let r = DnsResolver::build(spec, doh, PreferIp::PreferIpv4).unwrap();
            let ips = r.resolve_ips("127.0.0.1").await.unwrap();
            assert_eq!(ips, vec![IpAddr::from([127, 0, 0, 1])]);
        }
    }
}

//! `mtg-proxy access` subcommand — exact JSON parity with Go `internal/cli/access.go`
//! (`ipv4`, `ipv6`, `secret`, `secrets`, `listeners`, `web`, and `api.qrserver.com` QR URLs).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use mtg_config::{Config, ConfigListener, HostPort};
use mtg_core::{Secret, SecretMode};
use mtg_net::SocketConfig;
use serde::Serialize;

use crate::cmd_run::read_and_validate_config;

#[derive(Debug, Serialize)]
struct AccessSecret {
    hex: String,
    base64: String,
}

#[derive(Debug, Serialize)]
struct AccessUrls {
    ip: IpAddr,
    port: u16,
    tg_url: String,
    tg_qrcode: String,
    tme_url: String,
    tme_qrcode: String,
}

#[derive(Debug, Serialize)]
struct AccessModeUrls {
    secret: String,
    tg_url: String,
    tg_qrcode: String,
    tme_url: String,
    tme_qrcode: String,
}

#[derive(Debug, Serialize)]
struct AccessListenerUrls {
    ip: String,
    port: u16,
    secrets: BTreeMap<String, BTreeMap<String, AccessModeUrls>>,
}

#[derive(Debug, Serialize)]
struct AccessListener {
    bind_to: String,
    accept: Vec<String>,
    public: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    unreachable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4: Option<AccessListenerUrls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6: Option<AccessListenerUrls>,
}

#[derive(Debug, Serialize)]
struct AccessWebSecret {
    secret: String,
    tg_url: String,
    tg_qrcode: String,
}

#[derive(Debug, Serialize)]
struct AccessWeb {
    host: String,
    secret: AccessWebSecret,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    secrets: BTreeMap<String, AccessWebSecret>,
}

#[derive(Debug, Serialize)]
struct AccessResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4: Option<AccessUrls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6: Option<AccessUrls>,
    secret: AccessSecret,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    secrets: BTreeMap<String, AccessSecret>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    listeners: Vec<AccessListener>,
    #[serde(skip_serializing_if = "Option::is_none")]
    web: Option<AccessWeb>,
}

pub async fn execute_access(
    config_path: &Path,
    cli_ipv4: Option<IpAddr>,
    cli_ipv6: Option<IpAddr>,
    cli_port: Option<u16>,
    hex: bool,
) -> Result<()> {
    let conf = read_and_validate_config(config_path)?;
    let secrets = conf.get_secrets();

    let Some(first_secret) = secrets.values().next().cloned() else {
        anyhow::bail!("configuration has no secrets");
    };
    let secret = AccessSecret {
        hex: first_secret.encode_hex(),
        base64: first_secret.encode_base64(),
    };

    let mut multi = BTreeMap::new();
    if secrets.len() > 1 {
        for (name, s) in &secrets {
            multi.insert(
                name.clone(),
                AccessSecret {
                    hex: s.encode_hex(),
                    base64: s.encode_base64(),
                },
            );
        }
    }

    let sock_cfg = SocketConfig::default();

    let v4_fut = async {
        if let Some(ip) = cli_ipv4.or(conf.public_ipv4).filter(IpAddr::is_ipv4) {
            return Some(ip);
        }
        detect_public_ip(&sock_cfg, "https://ipv4.myip.wtf/text", true).await
    };
    let v6_fut = async {
        if let Some(ip) = cli_ipv6.or(conf.public_ipv6).filter(IpAddr::is_ipv6) {
            return Some(ip);
        }
        detect_public_ip(&sock_cfg, "https://ipv6.myip.wtf/text", false).await
    };

    let (ip4, ip6) = tokio::join!(v4_fut, v6_fut);

    let port = cli_port.unwrap_or_else(|| conf.bind_to.first().map_or(443, |hp| hp.port));
    let first_str = if hex {
        first_secret.encode_hex()
    } else {
        first_secret.encode_base64()
    };

    let ipv4 = ip4.map(|ip| make_urls(ip, port, &first_str));
    let ipv6 = ip6.map(|ip| make_urls(ip, port, &first_str));

    let listeners = make_listeners(&conf, &secrets, ip4, ip6);
    let web = make_web(&conf, &secrets);

    let resp = AccessResponse {
        ipv4,
        ipv6,
        secret,
        secrets: multi,
        listeners,
        web,
    };

    let json = serde_json::to_string_pretty(&resp)?;
    println!("{json}");
    Ok(())
}

fn make_qr_code_url(data: &str) -> String {
    let mut u = url::Url::parse("https://api.qrserver.com/v1/create-qr-code").expect("valid url");
    u.query_pairs_mut()
        .append_pair("data", data)
        .append_pair("format", "svg")
        .append_pair("qzone", "4");
    u.to_string()
}

fn make_urls(ip: IpAddr, port: u16, secret: &str) -> AccessUrls {
    let mut tg = url::Url::parse("tg://proxy").expect("valid url");
    tg.query_pairs_mut()
        .append_pair("port", &port.to_string())
        .append_pair("secret", secret)
        .append_pair("server", &ip.to_string());
    let tg_url = tg.to_string();

    let mut tme = url::Url::parse("https://t.me/proxy").expect("valid url");
    tme.query_pairs_mut()
        .append_pair("port", &port.to_string())
        .append_pair("secret", secret)
        .append_pair("server", &ip.to_string());
    let tme_url = tme.to_string();

    AccessUrls {
        ip,
        port,
        tg_qrcode: make_qr_code_url(&tg_url),
        tme_qrcode: make_qr_code_url(&tme_url),
        tg_url,
        tme_url,
    }
}

fn make_mode_urls(ip: IpAddr, port: u16, secret: &str) -> AccessModeUrls {
    let u = make_urls(ip, port, secret);
    AccessModeUrls {
        secret: secret.to_owned(),
        tg_url: u.tg_url,
        tg_qrcode: u.tg_qrcode,
        tme_url: u.tme_url,
        tme_qrcode: u.tme_qrcode,
    }
}

fn make_listeners(
    conf: &Config,
    secrets: &BTreeMap<String, Secret>,
    ip4: Option<IpAddr>,
    ip6: Option<IpAddr>,
) -> Vec<AccessListener> {
    let mut out = Vec::with_capacity(conf.listeners.len());
    for listener in &conf.listeners {
        let bind_str = listener
            .bind_to
            .as_ref()
            .map_or("", HostPort::as_str)
            .to_owned();
        let accept: Vec<String> = listener
            .accept
            .iter()
            .map(|m| m.as_str().to_owned())
            .collect();
        let public = listener.public.unwrap_or(false);

        let (port, is_loopback) = parse_listener_port(&bind_str);
        let (unreachable, l_v4, l_v6) = if port == 0 {
            (
                "this listener has no port to advertise".to_owned(),
                None,
                None,
            )
        } else if is_loopback {
            (
                "bound to loopback, so it is reachable only from this host (a WEB relay backend is meant to look like this)"
                    .to_owned(),
                None,
                None,
            )
        } else {
            (
                String::new(),
                ip4.map(|ip| make_listener_urls(listener, secrets, ip, port)),
                ip6.map(|ip| make_listener_urls(listener, secrets, ip, port)),
            )
        };

        out.push(AccessListener {
            bind_to: bind_str,
            accept,
            public,
            unreachable,
            ipv4: l_v4,
            ipv6: l_v6,
        });
    }
    out
}

fn parse_listener_port(bind_to: &str) -> (u16, bool) {
    let Ok(hp) = HostPort::parse(bind_to) else {
        return (0, false);
    };
    let loopback = hp.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    (hp.port, loopback)
}

fn make_listener_urls(
    listener: &ConfigListener,
    secrets: &BTreeMap<String, Secret>,
    ip: IpAddr,
    port: u16,
) -> AccessListenerUrls {
    let mut map = BTreeMap::new();
    for (name, secret) in secrets {
        let mut forms = BTreeMap::new();
        for &mode in &listener.accept {
            let text = match mode {
                SecretMode::Dd => secret.encode_dd_hex(),
                SecretMode::Plain => secret.encode_plain_hex(),
                SecretMode::FakeTls => continue,
            };
            forms.insert(mode.as_str().to_owned(), make_mode_urls(ip, port, &text));
        }
        if !forms.is_empty() {
            map.insert(name.clone(), forms);
        }
    }
    AccessListenerUrls {
        ip: ip.to_string(),
        port,
        secrets: map,
    }
}

fn make_web(conf: &Config, secrets: &BTreeMap<String, Secret>) -> Option<AccessWeb> {
    if !conf.web.enabled.unwrap_or(false) {
        return None;
    }
    let host = conf.web.host.as_deref().filter(|h| !h.is_empty())?;
    mtg_config::canonical_web_host(host).ok()?;

    let first = secrets.values().next()?;
    let first_web = make_web_secret(host, first);
    let mut multi = BTreeMap::new();
    if secrets.len() > 1 {
        for (name, s) in secrets {
            multi.insert(name.clone(), make_web_secret(host, s));
        }
    }

    Some(AccessWeb {
        host: host.to_owned(),
        secret: first_web,
        secrets: multi,
    })
}

fn make_web_secret(host: &str, secret: &Secret) -> AccessWebSecret {
    let dd = secret.encode_dd_hex();
    let mut tg = url::Url::parse("tg://webproxy").expect("valid url");
    tg.query_pairs_mut()
        .append_pair("secret", &dd)
        .append_pair("server", host);
    let tg_url = tg.to_string();
    AccessWebSecret {
        secret: dd,
        tg_qrcode: make_qr_code_url(&tg_url),
        tg_url,
    }
}

async fn detect_public_ip(sock_cfg: &SocketConfig, url: &str, want_v4: bool) -> Option<IpAddr> {
    let bytes = mtg_net::dc::fetch_url_bytes(url, None, *sock_cfg, Duration::from_secs(5))
        .await
        .ok()?;
    let body = std::str::from_utf8(&bytes).ok()?;
    let ip: IpAddr = body.trim().parse().ok()?;
    if (want_v4 && ip.is_ipv4()) || (!want_v4 && ip.is_ipv6()) {
        Some(ip)
    } else {
        None
    }
}

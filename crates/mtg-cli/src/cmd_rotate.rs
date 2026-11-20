//! `mtg-proxy rotate-secret` subcommand:
//! - Value-free stderr diagnostics; new secret ONLY on stdout after commit!
//! - Penhoon panel path guard (`mtg-[0-9]+.toml` + `/etc/p-ui/` / `/var/lib/penhoon/`).
//! - Atomic `.rotate.lock` + `fchown`/`chmod`/`fsync`/SHA-256 race check/`rename` via `mtg-config`.
//! - Optional `--reload`: preflights running Management API (`GET /stats` verifying
//!   `secret-rotation` feature unless `--force`), runs `POST /reload`, and verifies
//!   the rotated secret via `GET /secrets/{name}` read-back!

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use chrono::Utc;
use clap::Args;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use mtg_config::{
    Config, RotationRequest, is_panel_managed_path, parse_duration, rotate_file_atomic,
};
use mtg_core::{MAX_RETIRING_OVERLAP, Secret, SecretMode};
use serde_json::Value;
use tokio::net::TcpStream;

#[derive(Debug, Args)]
pub struct RotateArgs {
    /// Path to the configuration file.
    pub config_path: PathBuf,
    /// The secret to rotate (or whose overlap ends): a name from [secrets], or "default".
    pub name: Option<String>,
    /// How long the previous key stays accepted (0 to 720h; 0 retires immediately).
    #[arg(long = "overlap")]
    pub overlap: Option<String>,
    /// ee only: the fronting hostname of the new key. Without it the current one is kept.
    #[arg(long = "host")]
    pub host: Option<String>,
    /// Remove every [[retiring-secret]] block of the name.
    #[arg(long = "end-overlap")]
    pub end_overlap: bool,
    /// Remove every expired [[retiring-secret]] block, of any name.
    #[arg(long = "prune")]
    pub prune: bool,
    /// Print on stderr what the run would do, and write nothing.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
    /// Reload the running proxy through its management API (api-bind-to) and read back.
    #[arg(long = "reload")]
    pub reload: bool,
    /// Proceed even if the file looks panel-managed or running proxy lacks secret-rotation.
    #[arg(long = "force")]
    pub force: bool,
}

pub async fn execute_rotate(args: RotateArgs) -> Result<()> {
    let name = args.name.clone().unwrap_or_default();
    let rotate = !name.is_empty() && !args.end_overlap;

    if !rotate && !args.end_overlap && !args.prune {
        bail!(
            "nothing to do: specify a secret name to rotate, --end-overlap, or --prune; nothing was written"
        );
    }
    if args.end_overlap && name.is_empty() {
        bail!("--end-overlap requires a secret name; nothing was written");
    }
    if args.end_overlap && args.overlap.is_some() {
        bail!("--overlap cannot be combined with --end-overlap; nothing was written");
    }
    if args.host.is_some() && !rotate {
        bail!("--host is only valid when rotating a secret; nothing was written");
    }

    let now = Utc::now();
    let until = if rotate {
        let Some(ov_str) = &args.overlap else {
            bail!(
                "say how long the previous key stays accepted: --overlap 24h, or --overlap 0 to retire it at once; nothing was written"
            );
        };
        let dur = parse_duration(ov_str).map_err(|e| {
            anyhow::anyhow!("invalid --overlap {ov_str:?}: {e}; nothing was written")
        })?;
        if dur > MAX_RETIRING_OVERLAP {
            bail!("--overlap exceeds maximum 720h; nothing was written");
        }
        if dur.is_zero() {
            None
        } else {
            Some(now + chrono::Duration::from_std(dur)?)
        }
    } else {
        None
    };

    // Panel path heuristic on both raw path and canonical symlink target
    if !args.force && looks_like_panel_path(&args.config_path) {
        bail!(
            "this looks like a config the Penhoon panel generates (…/mtproto/mtg-N.toml); pass --force to proceed anyway; nothing was written"
        );
    }
    let target = fs::canonicalize(&args.config_path).with_context(|| {
        format!(
            "cannot resolve {}; nothing was written",
            args.config_path.display()
        )
    })?;
    if !args.force && (looks_like_panel_path(&target) || is_panel_managed_path(&target)) {
        bail!(
            "this looks like a config the Penhoon panel generates; pass --force to proceed anyway; nothing was written"
        );
    }

    // Parse current config to validate --host override & optional --reload preflight
    let raw_before = fs::read(&target)?;
    let conf_before =
        Config::parse(&raw_before).context("cannot parse config; nothing was written")?;

    let reload_target = if args.reload {
        let rt = ReloadClient::from_config(&conf_before)?;
        rt.preflight(args.force).await?;
        Some(rt)
    } else {
        None
    };

    let explicit_new_primary = if rotate {
        if let Some(new_host) = &args.host {
            let secrets = conf_before.get_secrets();
            let cur = secrets
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("secret {name:?} not found; nothing was written"))?;
            if cur.mode() != SecretMode::FakeTls {
                bail!("--host is only valid for ee secrets; nothing was written");
            }
            Some(Secret::generate_mode(SecretMode::FakeTls, new_host)?)
        } else {
            None
        }
    } else {
        None
    };

    let req = RotationRequest {
        name: name.clone(),
        rotate,
        until,
        end_overlap: args.end_overlap,
        prune: args.prune,
        now,
    };

    let res = rotate_file_atomic(
        &target,
        &req,
        explicit_new_primary,
        args.force,
        args.dry_run,
    )
    .map_err(|e| anyhow::anyhow!("{e}; nothing was written"))?;

    // Value-free summary on stderr
    for w in &res.warnings {
        eprintln!("warning: {w}");
    }
    if res.summary.no_op {
        eprintln!("no changes needed");
        return Ok(());
    }
    let shown = if res.summary.name.is_empty() {
        "the secret asked for (name hidden)"
    } else {
        &res.summary.name
    };
    if args.dry_run {
        eprintln!(
            "dry-run: would update {shown} (removed {} retiring block(s)); nothing was written",
            res.summary.removed.len()
        );
        return Ok(());
    }

    if let Some(until_dt) = res.summary.until {
        eprintln!(
            "rotated {shown}; previous key accepted until {} (removed {} retiring block(s))",
            until_dt.format("%Y-%m-%dT%H:%M:%SZ"),
            res.summary.removed.len()
        );
    } else if rotate {
        eprintln!(
            "rotated {shown}; previous key retired immediately (removed {} retiring block(s))",
            res.summary.removed.len()
        );
    } else {
        eprintln!("removed {} retiring block(s)", res.summary.removed.len());
    }

    // Print ONLY the new secret on stdout after atomic write succeeds!
    if let Some(val) = &res.new_value_text {
        println!("{val}");
    }

    // Optional --reload: trigger POST /reload & read back GET /secrets/{name}!
    if let Some(rt) = reload_target {
        rt.reload_and_verify(&target, &name, res.new_primary.as_ref())
            .await?;
        eprintln!(
            "reloaded running proxy at {} and verified active state",
            rt.addr
        );
    }

    Ok(())
}

fn looks_like_panel_path(path: &Path) -> bool {
    if is_panel_managed_path(path) {
        return true;
    }
    let Some(file) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let Some(rest) = file
        .strip_prefix("mtg-")
        .and_then(|s| s.strip_suffix(".toml"))
    else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

struct ReloadClient {
    addr: String,
    token: String,
}

impl ReloadClient {
    fn from_config(conf: &Config) -> Result<Self> {
        let Some(hp) = &conf.api_bind_to else {
            bail!(
                "--reload needs the proxy's management API, and the config sets no api-bind-to; nothing was written"
            );
        };
        let mut host = hp.host.clone();
        if let Ok(ip) = host.parse::<IpAddr>()
            && ip.is_unspecified()
        {
            host = if ip.is_ipv4() {
                "127.0.0.1".to_owned()
            } else {
                "::1".to_owned()
            };
        }
        let addr = if host.contains(':') {
            format!("[{host}]:{}", hp.port)
        } else {
            format!("{host}:{}", hp.port)
        };
        Ok(Self {
            addr,
            token: (*conf.api_token).clone(),
        })
    }

    async fn call(&self, method: Method, path: &str) -> Result<(StatusCode, Vec<u8>)> {
        let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&self.addr))
            .await
            .context("management API connect timeout")?
            .with_context(|| format!("cannot reach management API at {}", self.addr))?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .context("management API HTTP handshake failed")?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, &self.addr);
        if !self.token.is_empty() {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", self.token));
        }
        let req = builder.body(Empty::<Bytes>::new())?;
        let resp = tokio::time::timeout(Duration::from_secs(60), sender.send_request(req))
            .await
            .context("management API request timeout")?
            .context("management API request failed")?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes().to_vec();
        Ok((status, bytes))
    }

    async fn preflight(&self, force: bool) -> Result<()> {
        let (status, body) = self.call(Method::GET, "/stats").await?;
        if status != StatusCode::OK {
            bail!(
                "management API GET /stats returned {}; nothing was written",
                status.as_u16()
            );
        }
        let val: Value = serde_json::from_slice(&body)
            .context("the answer is not the JSON the management API sends; nothing was written")?;
        let has_rot = val["features"]
            .as_array()
            .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("secret-rotation")));
        if !has_rot && !force {
            bail!(
                "running proxy at {} does not advertise secret-rotation; pass --force to proceed anyway; nothing was written",
                self.addr
            );
        }
        Ok(())
    }

    async fn reload_and_verify(
        &self,
        written_path: &Path,
        name: &str,
        expected_primary: Option<&Secret>,
    ) -> Result<()> {
        let (status, _) = self.call(Method::POST, "/reload").await?;
        if status != StatusCode::OK {
            bail!(
                "the file is rotated but the proxy does not serve it: POST /reload returned {}",
                status.as_u16()
            );
        }

        if name.is_empty() {
            return Ok(());
        }

        let path = format!("/secrets/{name}");
        let (status, body) = self.call(Method::GET, &path).await?;
        if status != StatusCode::OK {
            bail!(
                "the file is rotated but the proxy does not serve it: GET /secrets read-back returned {}",
                status.as_u16()
            );
        }
        let got: Value = serde_json::from_slice(&body)
            .context("the file is rotated but the proxy read-back was not JSON")?;

        if let Some(exp) = expected_primary {
            let got_secret_str = got["secret"].as_str().unwrap_or("");
            let got_parsed = Secret::parse(got_secret_str).ok();
            if got_parsed.as_ref().map(Secret::key) != Some(exp.key()) {
                bail!("the file is rotated but the proxy serves another primary key");
            }
        }

        // Verify retiring_keys count matches written file
        let written_bytes = fs::read(written_path)?;
        let written_conf = Config::parse(&written_bytes)?;
        let expected_retiring = written_conf
            .get_retiring_secrets(Utc::now())
            .usable
            .iter()
            .filter(|r| r.name == name)
            .count();
        let got_retiring = got["retiring_keys"].as_u64().unwrap_or(0) as usize;
        if got_retiring != expected_retiring {
            bail!(
                "the file is rotated but the proxy reports {got_retiring} retiring keys (expected {expected_retiring})"
            );
        }

        Ok(())
    }
}

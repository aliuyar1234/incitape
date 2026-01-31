use crate::auth::BearerToken;
use crate::grpc::{serve_grpc, tls_config_from_pem, GrpcState};
use crate::http::{serve_http, HttpState};
use crate::ingest::RecorderIngest;
use crate::tls::load_rustls_config;
use incitape_core::config::RecorderConfig;
use incitape_core::{AppError, AppResult};
use incitape_redaction::{RedactionEngine, RedactionRuleset};
use incitape_tape::bounds::Bounds;
use incitape_tape::finalize::finalize_tape_dir;
use incitape_tape::manifest::{Capture, Redaction};
use incitape_tape::writer::TapeWriter;
use serde::Serialize;
use serde_yaml::Value;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};

pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 15;

pub struct RecorderSettings {
    pub grpc_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub auth: Option<BearerToken>,
    pub tls: Option<TlsPaths>,
    pub bounds: Bounds,
    pub request_timeout: Duration,
}

#[derive(Clone)]
pub struct TlsPaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl RecorderSettings {
    pub async fn from_config(
        config: &RecorderConfig,
        bounds: Bounds,
        request_timeout: Duration,
    ) -> AppResult<Self> {
        let grpc_addr = parse_bind("recorder.grpc_bind", &config.grpc_bind)?;
        let http_addr = parse_bind("recorder.http_bind", &config.http_bind)?;

        let auth = if config.auth.enabled {
            let token_path = config
                .auth
                .token_path
                .as_ref()
                .ok_or_else(|| AppError::usage("auth.enabled=true requires token_path"))?;
            Some(BearerToken::load(token_path).await?)
        } else {
            None
        };

        let tls = if config.tls.enabled {
            let cert_path = config
                .tls
                .cert_path
                .as_ref()
                .ok_or_else(|| AppError::usage("tls.enabled=true requires cert_path"))?;
            let key_path = config
                .tls
                .key_path
                .as_ref()
                .ok_or_else(|| AppError::usage("tls.enabled=true requires key_path"))?;
            Some(TlsPaths {
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
            })
        } else {
            None
        };

        let non_loopback = !grpc_addr.ip().is_loopback() || !http_addr.ip().is_loopback();
        if non_loopback {
            if auth.is_none() {
                return Err(AppError::security(
                    "non-loopback bind requires auth.enabled=true with token_path",
                ));
            }
            if tls.is_none() {
                return Err(AppError::security(
                    "non-loopback bind requires tls.enabled=true with cert_path and key_path",
                ));
            }
        }

        Ok(Self {
            grpc_addr,
            http_addr,
            auth,
            tls,
            bounds,
            request_timeout,
        })
    }
}

pub async fn record(
    settings: RecorderSettings,
    out_dir: PathBuf,
    duration: Option<Duration>,
) -> AppResult<()> {
    let partial_dir = partial_dir(&out_dir)?;
    ensure_fresh_paths(&out_dir, &partial_dir)?;

    tokio::fs::create_dir_all(&partial_dir)
        .await
        .map_err(|e| AppError::internal(format!("failed to create partial dir: {e}")))?;

    let tape_path = partial_dir.join("tape.tape.zst");
    let writer = TapeWriter::create(&tape_path, settings.bounds)?;

    let ruleset = RedactionRuleset::safe_default()?;
    let engine = RedactionEngine::new(ruleset.clone());

    let started_at = now_rfc3339()?;
    write_partial_manifest(&partial_dir, &started_at, &ruleset)?;

    let (fatal_tx, mut fatal_rx) = mpsc::channel(4);
    let ingest = Arc::new(RecorderIngest::new(
        engine,
        settings.bounds,
        writer,
        fatal_tx,
    ));

    let http_state = HttpState::new(
        ingest.clone(),
        settings.auth.clone(),
        settings.bounds.max_record_bytes as usize,
        settings.request_timeout,
    );
    let grpc_state = GrpcState::new(
        ingest.clone(),
        settings.auth.clone(),
        settings.bounds.max_record_bytes as usize,
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_err_tx, mut server_err_rx) = mpsc::channel(2);

    let http_tls = if let Some(tls) = &settings.tls {
        Some(load_rustls_config(&tls.cert_path, &tls.key_path).await?)
    } else {
        None
    };

    let grpc_tls = if let Some(tls) = &settings.tls {
        let cert = tokio::fs::read(&tls.cert_path)
            .await
            .map_err(|e| AppError::internal(format!("failed to read tls cert: {e}")))?;
        let key = tokio::fs::read(&tls.key_path)
            .await
            .map_err(|e| AppError::internal(format!("failed to read tls key: {e}")))?;
        Some(tls_config_from_pem(&cert, &key)?)
    } else {
        None
    };

    let grpc_shutdown = shutdown_future(shutdown_rx.clone());

    let http_err_tx = server_err_tx.clone();
    let http_handle = tokio::spawn(async move {
        let result = serve_http(
            settings.http_addr,
            http_state,
            settings.request_timeout,
            http_tls,
            shutdown_rx.clone(),
        )
        .await;
        if let Err(err) = &result {
            let _ = http_err_tx.send(err.clone()).await;
        }
        result
    });
    let grpc_err_tx = server_err_tx.clone();
    let grpc_handle = tokio::spawn(async move {
        let result = serve_grpc(
            settings.grpc_addr,
            grpc_state,
            settings.request_timeout,
            grpc_tls,
            grpc_shutdown,
        )
        .await;
        if let Err(err) = &result {
            let _ = grpc_err_tx.send(err.clone()).await;
        }
        result
    });

    let stop_reason = if let Some(duration) = duration {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => StopReason::Signal,
            _ = tokio::time::sleep(duration) => StopReason::Duration,
            err = fatal_rx.recv() => StopReason::Fatal(err),
            err = server_err_rx.recv() => StopReason::Fatal(err),
        }
    } else {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => StopReason::Signal,
            err = fatal_rx.recv() => StopReason::Fatal(err),
            err = server_err_rx.recv() => StopReason::Fatal(err),
        }
    };

    let _ = shutdown_tx.send(true);

    http_handle
        .await
        .map_err(|e| AppError::internal(format!("http server join error: {e}")))??;
    grpc_handle
        .await
        .map_err(|e| AppError::internal(format!("grpc server join error: {e}")))??;

    if let StopReason::Fatal(Some(err)) = stop_reason {
        return Err(err);
    }

    ingest.finish().await?;

    let ended_at = now_rfc3339()?;
    update_manifest_end(&partial_dir.join("manifest.yaml"), &ended_at)?;

    finalize_tape_dir(&partial_dir, &out_dir)?;

    Ok(())
}

enum StopReason {
    Signal,
    Duration,
    Fatal(Option<AppError>),
}

fn parse_bind(field: &str, value: &str) -> AppResult<SocketAddr> {
    SocketAddr::from_str(value)
        .map_err(|_| AppError::usage(format!("invalid {field} '{value}'; expected ip:port")))
}

fn partial_dir(final_dir: &Path) -> AppResult<PathBuf> {
    let file_name = final_dir
        .file_name()
        .ok_or_else(|| AppError::usage("record --out requires a directory name"))?;
    let name = file_name.to_string_lossy();
    let partial_name = format!("{name}.partial");
    Ok(final_dir
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(partial_name))
}

fn ensure_fresh_paths(final_dir: &Path, partial_dir: &Path) -> AppResult<()> {
    if final_dir.exists() {
        return Err(AppError::validation("output tape_dir already exists"));
    }
    if partial_dir.exists() {
        return Err(AppError::validation(
            "partial tape_dir already exists; remove it before recording",
        ));
    }
    Ok(())
}

async fn shutdown_future(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}

fn now_rfc3339() -> AppResult<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| AppError::internal(format!("failed to format time: {e}")))
}

#[derive(Serialize)]
struct PartialManifest {
    tape_version: u16,
    capture: Capture,
    redaction: Redaction,
    ground_truth: Option<incitape_tape::manifest::GroundTruth>,
}

fn write_partial_manifest(
    partial_dir: &Path,
    started_at: &str,
    ruleset: &RedactionRuleset,
) -> AppResult<()> {
    let manifest = PartialManifest {
        tape_version: 1,
        capture: Capture {
            started_at_rfc3339: started_at.to_string(),
            ended_at_rfc3339: started_at.to_string(),
            source: "otlp_receiver".to_string(),
        },
        redaction: Redaction {
            profile: ruleset.name.clone(),
            ruleset_sha256: ruleset.ruleset_sha256(),
            applied: true,
        },
        ground_truth: None,
    };
    let content = serde_yaml::to_string(&manifest)
        .map_err(|e| AppError::internal(format!("manifest encode error: {e}")))?;
    std::fs::write(partial_dir.join("manifest.yaml"), content)
        .map_err(|e| AppError::internal(format!("manifest write error: {e}")))
}

fn update_manifest_end(path: &Path, ended_at: &str) -> AppResult<()> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| AppError::internal(format!("failed to read manifest: {e}")))?;
    let mut value: Value = serde_yaml::from_str(&raw)
        .map_err(|e| AppError::internal(format!("manifest parse error: {e}")))?;
    let map = value
        .as_mapping_mut()
        .ok_or_else(|| AppError::internal("manifest must be a mapping"))?;
    let capture = map
        .get_mut(Value::String("capture".to_string()))
        .and_then(|v| v.as_mapping_mut())
        .ok_or_else(|| AppError::internal("manifest capture section missing"))?;
    capture.insert(
        Value::String("ended_at_rfc3339".to_string()),
        Value::String(ended_at.to_string()),
    );
    let content = serde_yaml::to_string(&value)
        .map_err(|e| AppError::internal(format!("manifest encode error: {e}")))?;
    std::fs::write(path, content)
        .map_err(|e| AppError::internal(format!("manifest write error: {e}")))
}

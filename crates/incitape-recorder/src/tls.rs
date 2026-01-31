use incitape_core::{AppError, AppResult};
use rustls::ServerConfig;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::path::Path;

pub type RustlsServerConfig = ServerConfig;

pub async fn load_rustls_config(
    cert_path: &Path,
    key_path: &Path,
) -> AppResult<RustlsServerConfig> {
    let cert_bytes = tokio::fs::read(cert_path)
        .await
        .map_err(|e| AppError::internal(format!("failed to read tls cert: {e}")))?;
    let key_bytes = tokio::fs::read(key_path)
        .await
        .map_err(|e| AppError::internal(format!("failed to read tls key: {e}")))?;
    build_rustls_config(&cert_bytes, &key_bytes)
}

pub fn build_rustls_config(cert_pem: &[u8], key_pem: &[u8]) -> AppResult<RustlsServerConfig> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AppError::internal(format!("failed to parse tls certs: {e}")))?;
    if certs.is_empty() {
        return Err(AppError::internal("tls certs are empty"));
    }

    let key = load_private_key(key_pem)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AppError::internal(format!("tls config error: {e}")))?;
    Ok(config)
}

fn load_private_key(key_pem: &[u8]) -> AppResult<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| {
        if matches!(e, rustls_pki_types::pem::Error::NoItemsFound) {
            AppError::internal("tls key is empty")
        } else {
            AppError::internal(format!("failed to parse tls key: {e}"))
        }
    })
}

use incitape_core::{AppError, AppResult};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn compute_tape_id(path: &Path) -> AppResult<String> {
    let mut file = File::open(path)
        .map_err(|e| AppError::validation(format!("failed to open tape for hash: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| AppError::validation(format!("failed to read tape: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

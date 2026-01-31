use incitape_core::{AppError, AppResult};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::Path;

const CHECKSUMS_FILE: &str = "checksums.sha256";
const REQUIRED_FILES: [&str; 2] = ["manifest.yaml", "tape.tape.zst"];

pub fn write_checksums(tape_dir: &Path, files: &[&str]) -> AppResult<()> {
    let mut entries = BTreeMap::new();

    for name in files {
        validate_name(name)?;
        let path = tape_dir.join(name);
        let hash = hash_file(&path)?;
        entries.insert(name.to_string(), hash);
    }

    let mut lines = Vec::new();
    for (name, hash) in entries {
        lines.push(format!("{hash}  {name}"));
    }

    let output = tape_dir.join(CHECKSUMS_FILE);
    fs::write(&output, lines.join("\n") + "\n")
        .map_err(|e| AppError::internal(format!("write checksums failed: {e}")))
}

pub fn verify_checksums(tape_dir: &Path) -> AppResult<()> {
    let path = tape_dir.join(CHECKSUMS_FILE);
    let content = fs::read_to_string(&path)
        .map_err(|e| AppError::validation(format!("missing checksums.sha256: {e}")))?;

    let mut entries = BTreeMap::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, "  ").collect();
        if parts.len() != 2 {
            return Err(AppError::validation("invalid checksums line"));
        }
        let hash = parts[0].trim();
        let name = parts[1].trim();
        validate_name(name)?;
        if entries.contains_key(name) {
            return Err(AppError::validation("duplicate checksums entry"));
        }
        entries.insert(name.to_string(), hash.to_string());
    }

    let present: BTreeSet<_> = entries.keys().cloned().collect();
    for required in REQUIRED_FILES {
        if !present.contains(required) {
            return Err(AppError::validation(format!(
                "checksums missing required entry {required}"
            )));
        }
    }

    for (name, expected) in entries {
        let actual = hash_file(&tape_dir.join(&name))?;
        if actual != expected {
            return Err(AppError::validation(format!(
                "checksum mismatch for {name}"
            )));
        }
    }

    Ok(())
}

fn hash_file(path: &Path) -> AppResult<String> {
    let mut file = fs::File::open(path)
        .map_err(|e| AppError::validation(format!("missing file {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| AppError::validation(format!("read error {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_name(name: &str) -> AppResult<()> {
    if name.contains('/') || name.contains('\\') {
        return Err(AppError::validation("invalid checksums filename"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn checksums_round_trip() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("manifest.yaml"), "a").unwrap();
        fs::write(dir.path().join("tape.tape.zst"), "b").unwrap();

        write_checksums(dir.path(), &["manifest.yaml", "tape.tape.zst"]).unwrap();
        verify_checksums(dir.path()).unwrap();
    }
}

use crate::checksums::write_checksums;
use crate::manifest::Manifest;
use crate::tape_id::compute_tape_id;
use incitape_core::{AppError, AppResult};
use serde_yaml::Value;
use std::fs;
use std::path::Path;

pub fn finalize_tape_dir(partial_dir: &Path, final_dir: &Path) -> AppResult<()> {
    if !partial_dir.exists() {
        return Err(AppError::validation("partial tape_dir does not exist"));
    }
    if final_dir.exists() {
        return Err(AppError::validation("final tape_dir already exists"));
    }

    let tape_path = partial_dir.join("tape.tape.zst");
    let tape_id = compute_tape_id(&tape_path)?;

    let manifest_path = partial_dir.join("manifest.yaml");
    let raw = fs::read_to_string(&manifest_path)
        .map_err(|e| AppError::validation(format!("failed to read manifest: {e}")))?;
    let mut value: Value = serde_yaml::from_str(&raw)
        .map_err(|e| AppError::validation(format!("manifest parse error: {e}")))?;
    let map = value
        .as_mapping_mut()
        .ok_or_else(|| AppError::validation("manifest must be a mapping to finalize tape"))?;
    map.insert(
        Value::String("tape_id".to_string()),
        Value::String(tape_id.clone()),
    );

    let manifest: Manifest = serde_yaml::from_value(value)
        .map_err(|e| AppError::validation(format!("manifest schema error: {e}")))?;
    manifest.validate(&tape_id)?;
    manifest.write(&manifest_path)?;

    write_checksums(partial_dir, &["manifest.yaml", "tape.tape.zst"])?;

    sync_path(&manifest_path)?;
    sync_path(&tape_path)?;
    sync_path(&partial_dir.join("checksums.sha256"))?;

    fs::rename(partial_dir, final_dir)
        .map_err(|e| AppError::internal(format!("failed to finalize tape_dir: {e}")))?;

    try_sync_dir(final_dir);

    Ok(())
}

fn sync_path(path: &Path) -> AppResult<()> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
            ) {
                return Ok(());
            }
            return Err(AppError::internal(format!(
                "fsync open failed {}: {err}",
                path.display()
            )));
        }
    };
    match file.sync_all() {
        Ok(()) => Ok(()),
        Err(err) => {
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
            ) {
                Ok(())
            } else {
                Err(AppError::internal(format!(
                    "fsync failed {}: {err}",
                    path.display()
                )))
            }
        }
    }
}

fn try_sync_dir(path: &Path) {
    if let Ok(dir) = fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::Bounds;
    use crate::writer::TapeWriter;
    use tempfile::tempdir;

    #[test]
    fn finalize_updates_manifest_and_moves_dir() {
        let temp = tempdir().unwrap();
        let partial_dir = temp.path().join("tape.partial");
        let final_dir = temp.path().join("tape");
        fs::create_dir_all(&partial_dir).unwrap();

        let tape_path = partial_dir.join("tape.tape.zst");
        let mut writer = TapeWriter::create(&tape_path, Bounds::default()).unwrap();
        writer
            .write_record(crate::record::RecordType::Traces, 1, b"payload")
            .unwrap();
        writer.finish().unwrap();

        let manifest = Manifest {
            tape_version: 1,
            tape_id: "0".repeat(64),
            capture: crate::manifest::Capture {
                started_at_rfc3339: "2025-01-01T00:00:00Z".to_string(),
                ended_at_rfc3339: "2025-01-01T00:00:01Z".to_string(),
                source: "otlp_receiver".to_string(),
            },
            redaction: crate::manifest::Redaction {
                profile: "safe_default".to_string(),
                ruleset_sha256: "0".repeat(64),
                applied: true,
            },
            ground_truth: None,
            derived_from: None,
        };
        manifest.write(&partial_dir.join("manifest.yaml")).unwrap();

        finalize_tape_dir(&partial_dir, &final_dir).unwrap();
        assert!(final_dir.exists());
        assert!(!partial_dir.exists());

        let updated = Manifest::load(&final_dir.join("manifest.yaml")).unwrap();
        let expected = compute_tape_id(&final_dir.join("tape.tape.zst")).unwrap();
        assert_eq!(updated.tape_id, expected);
    }
}

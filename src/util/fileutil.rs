//! File helpers shared by the persistence layers.

use anyhow::Result;
use std::io::Write;

fn write_and_sync(path: &str, data: &[u8], permissions: Option<std::fs::Permissions>) -> Result<()> {
    let mut file = std::fs::File::create(path)?;
    if let Some(permissions) = permissions {
        file.set_permissions(permissions)?;
    }
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

/// Replace the contents of `path` in one step: the data is written to a temporary file in the
/// same directory and flushed to disk before being renamed over the target. A crash during the
/// write leaves the previous file intact rather than a truncated one. The permissions of an
/// existing target are carried over to the replacement.
pub(crate) fn write_atomically(path: &str, data: &[u8]) -> Result<()> {
    let tmp_path = format!("{}.tmp{}", path, std::process::id());
    let permissions = std::fs::metadata(path).ok().map(|m| m.permissions());
    let result = write_and_sync(&tmp_path, data, permissions)
        .and_then(|()| std::fs::rename(&tmp_path, path).map_err(Into::into));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_file() {
        let dir = std::env::temp_dir().join(format!("matc-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let path = path.to_str().unwrap();

        write_atomically(path, b"first").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"first");
        write_atomically(path, b"second").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"second");

        // no temporary file is left behind
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left: {:?}", leftovers);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn keeps_permissions_of_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("matc-atomic-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let path = path.to_str().unwrap();

        write_atomically(path, b"first").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_atomically(path, b"second").unwrap();
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failed_write_keeps_previous_content() {
        let dir = std::env::temp_dir().join(format!("matc-atomic-fail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let path = path.to_str().unwrap();
        write_atomically(path, b"original").unwrap();

        // a directory in place of the temporary file makes the write fail
        let tmp_path = format!("{}.tmp{}", path, std::process::id());
        std::fs::create_dir(&tmp_path).unwrap();
        assert!(write_atomically(path, b"replacement").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"original");

        std::fs::remove_dir_all(&tmp_path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

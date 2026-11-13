// Files a user names by path, read with a size cap so `/dev/zero` cannot fill memory. The apps also
// refuse anything but a regular file, since a FIFO would block the thread the idle lock runs on.
// The CLI does not: `--key-file <(…)` is a pipe, and blocking on it is what the user asked for.

use std::io::Read;
use std::path::Path;

use zeroize::Zeroize;

// KeePassXC accepts any file as a key file, a photo as readily as a generated one.
pub const KEY_FILE_MAX: u64 = 64 << 20;
pub const ATTACHMENT_MAX: u64 = 64 << 20;
pub const CSV_MAX: u64 = 64 << 20;

/// For the apps: a regular file only.
pub fn read_capped_file(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    read_capped(path, max)
}

/// For the CLI: a pipe or device too, but never more than `max` bytes.
pub fn read_capped(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if meta.is_dir() {
        return Err(std::io::Error::other("a folder, not a file"));
    }
    let too_big = || std::io::Error::other(format!("over {}", size(max)));
    if meta.is_file() && meta.len() > max {
        return Err(too_big());
    }
    let mut bytes = Vec::with_capacity(meta.len().min(max) as usize);
    std::fs::File::open(path)?
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    // It grew between the stat and the read. What was read may be key material.
    if bytes.len() as u64 > max {
        bytes.zeroize();
        return Err(too_big());
    }
    Ok(bytes)
}

pub fn read_capped_text(path: &Path, max: u64) -> std::io::Result<String> {
    String::from_utf8(read_capped(path, max)?).map_err(|e| {
        e.into_bytes().zeroize();
        std::io::Error::new(std::io::ErrorKind::InvalidData, "not UTF-8 text")
    })
}

fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{} MiB", b >> 20),
        b => format!("{} KiB", b >> 10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sennel-capped-{tag}-{}", std::process::id()))
    }

    #[test]
    fn a_file_at_the_limit_reads_and_one_byte_over_does_not() {
        let path = temp("size");
        std::fs::write(&path, vec![b'x'; 1024]).unwrap();
        assert_eq!(read_capped(&path, 1024).unwrap().len(), 1024);
        let err = read_capped(&path, 1023).unwrap_err();
        assert!(err.to_string().starts_with("over"), "{err}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_apps_refuse_a_folder_or_a_fifo_without_blocking() {
        assert!(read_capped_file(&std::env::temp_dir(), 1024).is_err());
        assert!(read_capped(&std::env::temp_dir(), 1024).is_err());
        let fifo = temp("fifo");
        let _ = std::fs::remove_file(&fifo);
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo only creates the node.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let err = read_capped_file(&fifo, 1024).unwrap_err();
        assert_eq!(err.to_string(), "not a regular file");
        std::fs::remove_file(&fifo).unwrap();
    }

    #[test]
    fn the_cli_reads_a_device_only_up_to_the_cap() {
        let err = read_capped(Path::new("/dev/zero"), 4096).unwrap_err();
        assert!(err.to_string().starts_with("over"), "{err}");
    }

    #[test]
    fn text_that_is_not_utf8_is_refused() {
        let path = temp("utf8");
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(read_capped_text(&path, 1024).is_err());
        std::fs::remove_file(&path).unwrap();
    }
}

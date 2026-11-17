// The local socket between the proxy a browser starts and the desktop app, and the framing both
// sides of it use. Native messaging frames each message with a 32-bit length in native byte order;
// the socket uses the same frames, so the proxy relays bytes without reading them.

use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// The host name Sennel's own extension uses.
pub const APP_HOST: &str = "app.sennel.browser";
/// KeePassXC-Browser only ever looks for this one.
pub const KEEPASSXC_HOST: &str = "org.keepassxc.keepassxc_browser";

// A browser sends a page URL and a few keys; anything this size is not a real request.
pub const MAX_FRAME: usize = 1 << 20;

pub fn read_frame(from: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match from.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; len];
    from.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn write_frame(to: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    to.write_all(&(body.len() as u32).to_ne_bytes())?;
    to.write_all(body)?;
    to.flush()
}

/// The first frame a proxy sends: which host name the browser started it under.
pub fn hello(host: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "sennel-proxy": 1, "host": host })).unwrap_or_default()
}

pub fn read_hello(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    (value.get("sennel-proxy")?.as_u64()? == 1).then_some(())?;
    Some(value.get("host")?.as_str()?.to_string())
}

/// Where the socket lives: the per-user runtime folder on Linux, else Sennel's state folder. Never
/// a shared temporary folder.
pub fn socket_path() -> Option<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && cfg!(target_os = "linux"));
    let base = match runtime {
        Some(dir) => dir.join("sennel"),
        None => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())?;
            let state = std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(".local/state"));
            state.join("sennel").join("run")
        }
    };
    Some(base.join("browser.sock"))
}

// The socket's folder is made 0700 in one step, and an existing one is used only if it is a real
// folder this user owns that nobody else can enter, so another account cannot plant or watch it.
fn private_folder(dir: &Path) -> io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(dir)?;
    // SAFETY: getuid has no failure mode and touches no memory.
    let me = unsafe { libc::getuid() };
    if !meta.is_dir() || meta.uid() != me || meta.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a private folder of this user", dir.display()),
        ));
    }
    Ok(())
}

/// Listens on `path`. Refuses when another Sennel already answers there, and replaces only a stale
/// socket of this user's.
pub fn listen(path: &Path) -> io::Result<UnixListener> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no folder"))?;
    private_folder(dir)?;
    if UnixStream::connect(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "another Sennel window is already serving browsers",
        ));
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    UnixListener::bind(path)
}

/// Whether the process on the other end is this user's copy of `expected`, the program the
/// browser registration starts. A folder only this user can enter still admits every program the
/// user runs, so the peer's executable is checked too.
pub fn peer_is(stream: &UnixStream, expected: &Path) -> bool {
    let Ok(expected) = expected.canonicalize() else {
        return false;
    };
    peer_exe(stream)
        .and_then(|exe| exe.canonicalize().ok())
        .is_some_and(|exe| exe == expected)
}

#[cfg(target_os = "macos")]
fn peer_exe(stream: &UnixStream) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: the out-pointers are valid locals and fd is an open socket.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 || uid != unsafe { libc::getuid() }
    {
        return None;
    }
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: pid and len are valid for the size passed.
    let got = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    if got != 0 || pid <= 0 {
        return None;
    }
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is as long as the size passed.
    let n = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if n <= 0 {
        return None;
    }
    buffer.truncate(n as usize);
    Some(PathBuf::from(
        <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(buffer),
    ))
}

#[cfg(target_os = "linux")]
fn peer_exe(stream: &UnixStream) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for the size passed.
    let got = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    // SAFETY: getuid has no failure mode.
    if got != 0 || cred.pid <= 0 || cred.uid != unsafe { libc::getuid() } {
        return None;
    }
    std::fs::read_link(format!("/proc/{}/exe", cred.pid)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sennel-transport-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn frames_round_trip_and_an_oversized_one_is_refused() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"{\"a\":1}").unwrap();
        write_frame(&mut wire, b"").unwrap();
        let mut reader = &wire[..];
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), b"{\"a\":1}");
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), b"");
        assert!(read_frame(&mut reader).unwrap().is_none());
        let huge = ((MAX_FRAME + 1) as u32).to_ne_bytes();
        assert!(read_frame(&mut &huge[..]).is_err());
    }

    #[test]
    fn hello_names_the_host() {
        assert_eq!(
            read_hello(&hello(KEEPASSXC_HOST)).as_deref(),
            Some(KEEPASSXC_HOST)
        );
        assert_eq!(read_hello(br#"{"action":"get-logins"}"#), None);
    }

    #[test]
    fn the_folder_is_private_and_a_shared_one_is_refused() {
        let dir = temp("folder");
        let path = dir.join("run").join("browser.sock");
        let listener = listen(&path).unwrap();
        let mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        // A second window finds the first one answering.
        assert_eq!(listen(&path).unwrap_err().kind(), io::ErrorKind::AddrInUse);
        drop(listener);
        // A stale socket is replaced.
        assert!(listen(&path).is_ok());

        let open = dir.join("open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(listen(&open.join("browser.sock")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_the_expected_program_counts_as_the_peer() {
        let dir = temp("peer");
        let path = dir.join("run").join("browser.sock");
        let listener = listen(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        // The peer is this test binary itself.
        let me = std::env::current_exe().unwrap();
        assert!(peer_is(&server, &me));
        assert!(!peer_is(&server, Path::new("/bin/sh")));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

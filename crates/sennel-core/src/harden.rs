// Keeps the decrypted vault out of anything a crash or another process could read. A core dump
// holds every secret at once, and on Linux a dumpable process can be attached to by anything
// running as the same user. Best effort: a platform that refuses either call is no worse off.
pub fn harden() {
    unsafe {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Whether core dumps are actually off, read back rather than assumed.
pub fn core_dumps_off() -> bool {
    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    let read = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
    read == 0 && limit.rlim_cur == 0
}

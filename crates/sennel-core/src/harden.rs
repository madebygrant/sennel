#[cfg(all(target_os = "macos", not(debug_assertions)))]
static ATTACH_DENIED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// A core dump holds every secret at once, and a process another of the same user can attach to
// gives them up too. Returns the calls the system refused, for the caller to name.
#[must_use]
pub fn harden() -> Vec<&'static str> {
    let mut refused = Vec::new();
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        refused.push("the core dump limit");
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        refused.push("turning off ptrace attach");
    }
    // Release builds only: it kills a process that is already being debugged, which a debug build
    // run under lldb is.
    #[cfg(all(target_os = "macos", not(debug_assertions)))]
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } == 0 {
        ATTACH_DENIED.store(true, std::sync::atomic::Ordering::SeqCst);
    } else {
        refused.push("turning off ptrace attach");
    }
    refused
}

/// Whether another process of the same user can attach to this one. Read back from the kernel on
/// Linux. macOS cannot be asked, so it is whether the deny call worked. `None` where neither applies.
pub fn attachable() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        Some(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0)
    }
    #[cfg(all(target_os = "macos", not(debug_assertions)))]
    {
        Some(!ATTACH_DENIED.load(std::sync::atomic::Ordering::SeqCst))
    }
    #[cfg(not(any(target_os = "linux", all(target_os = "macos", not(debug_assertions)))))]
    {
        None
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

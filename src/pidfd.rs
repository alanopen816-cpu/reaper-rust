//! Minimal Linux pidfd syscall wrappers, intentionally limited to AArch64.
#[cfg(not(target_arch = "aarch64"))]
compile_error!("Reaper pidfd syscall wrappers require AArch64 Linux (Termux ARM64)");

use std::io;
use std::os::raw::{c_int, c_long};

// Linux AArch64 asm-generic UAPI: pidfd_send_signal=424, pidfd_open=434,
// close=57. These are syscall-table numbers (not libc symbols); fail closed
// on unsupported architectures above rather than guessing another ABI.
const NR_PIDFD_SEND_SIGNAL: c_long = 424;
const NR_PIDFD_OPEN: c_long = 434;
const NR_CLOSE: c_long = 57;

fn syscall4(nr: c_long, a: c_long, b: c_long, c: c_long, d: c_long) -> io::Result<c_long> {
    let ret: c_long;
    // SAFETY: Linux AArch64 syscall ABI; arguments are scalar syscall values.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            lateout("x4") _,
            lateout("x5") _,
            lateout("x6") _,
            lateout("x7") _,
            options(nostack)
        );
    }
    if ret < 0 {
        Err(io::Error::from_raw_os_error((-ret) as i32))
    } else {
        Ok(ret)
    }
}

fn syscall3(nr: c_long, a: c_long, b: c_long, c: c_long) -> io::Result<c_long> {
    let ret: c_long;
    // SAFETY: Linux AArch64 syscall ABI; arguments are scalar syscall values.
    unsafe {
        core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a => ret,
        in("x1") b, in("x2") c, lateout("x3") _, lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, options(nostack));
    }
    if ret < 0 {
        Err(io::Error::from_raw_os_error((-ret) as i32))
    } else {
        Ok(ret)
    }
}

/// Open a pidfd for this process; caller must close it with [`close`].
pub fn open(pid: u32) -> io::Result<i32> {
    syscall3(NR_PIDFD_OPEN, pid as c_long, 0, 0).map(|fd| fd as i32)
}

pub fn open_self() -> io::Result<i32> {
    open(std::process::id())
}

/// Send a signal through an already-open pidfd.
pub fn send_empty(pidfd: i32, sig: c_int) -> io::Result<()> {
    syscall4(NR_PIDFD_SEND_SIGNAL, pidfd as c_long, sig as c_long, 0, 0).map(|_| ())
}

/// Existence-only probe of this process (signal zero delivers nothing).
pub fn probe_self_empty() -> io::Result<()> {
    let fd = open_self()?;
    let result = send_empty(fd, 0);
    let close_result = close(fd);
    result.and(close_result)
}

/// Close a raw pidfd.
pub fn close(fd: i32) -> io::Result<()> {
    syscall3(NR_CLOSE, fd as c_long, 0, 0).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_pidfd_open_probe_close_roundtrip() {
        match open_self() {
            Ok(fd) => {
                assert!(send_empty(fd, 0).is_ok());
                assert!(close(fd).is_ok());
            }
            // ENOSYS (or another kernel denial) means caller must use its
            // immediate double-revalidation fallback; it is not permission to act.
            Err(e) => {
                assert!(e.raw_os_error().is_some());
                assert!(probe_self_empty().is_err());
            }
        }
    }
    #[test]
    fn pidfd_send_signal_against_registered_lab_child_succeeds() {
        let _guard = crate::lab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous_registry = std::env::var_os("REAPER_LAB_REGISTRY");
        let path =
            std::env::temp_dir().join(format!("reaper-pidfd-{}-test.json", std::process::id()));
        std::env::set_var("REAPER_LAB_REGISTRY", &path);
        let mut child = crate::lab::spawn(false).expect("spawn registered lab sleeper");
        let entry = child.entry.clone();
        let fd = open(entry.pid).expect("open pidfd for registered lab child");
        send_empty(fd, 0).expect("zero-signal probe on registered lab child");
        close(fd).expect("close lab pidfd");
        let fd = open(entry.pid).expect("reopen pidfd for registered lab child");
        send_empty(fd, 15).expect("TERM registered lab child");
        close(fd).expect("close signalled lab pidfd");
        child.wait().expect("reap lab sleeper terminated by TERM");
        if let Some(previous) = previous_registry {
            std::env::set_var("REAPER_LAB_REGISTRY", previous);
        } else {
            std::env::remove_var("REAPER_LAB_REGISTRY");
        }
    }
    #[test]
    fn syscall_error_is_mapped_to_io_error() {
        let err = send_empty(-1, 0).unwrap_err();
        assert!(err.raw_os_error().is_some());
    }
}

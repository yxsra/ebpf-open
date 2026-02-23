use std::path::Path;

const MAX_LOG_SIZE: libc::off_t = 2 * 1024 * 1024; // 2MB

/// 检查日志文件大小，超限则轮转（rename → .old，重新打开）
pub fn maybe_rotate_log(log_path: &Path) {
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(libc::STDOUT_FILENO, &mut st) != 0 || st.st_size < MAX_LOG_SIZE {
            return;
        }
        let mut old = log_path.as_os_str().as_encoded_bytes().to_vec();
        old.extend_from_slice(b".old\0");
        let path_cstr = match std::ffi::CString::new(
            log_path.to_str().unwrap_or_default(),
        ) {
            Ok(c) => c,
            Err(_) => return,
        };
        libc::rename(path_cstr.as_ptr(), old.as_ptr() as *const _);
        let fd = libc::open(
            path_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o644 as libc::c_uint,
        );
        if fd < 0 {
            return;
        }
        libc::dup2(fd, libc::STDOUT_FILENO);
        libc::dup2(fd, libc::STDERR_FILENO);
        libc::close(fd);
    }
}

pub fn daemonize(log_path: &Path) -> anyhow::Result<()> {
    let path_cstr = std::ffi::CString::new(
        log_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("log path: non-UTF8"))?,
    )?;

    unsafe {
        let fd = libc::open(
            path_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o644 as libc::c_uint,
        );
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "open log file: {}",
                std::io::Error::last_os_error()
            ));
        }

        if libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
            libc::close(fd);
            return Err(anyhow::anyhow!("another instance is already running"));
        }

        let pid = libc::fork();
        if pid < 0 {
            libc::close(fd);
            return Err(anyhow::anyhow!("fork: {}", std::io::Error::last_os_error()));
        }
        if pid > 0 {
            std::process::exit(0);
        }

        libc::setsid();
        libc::dup2(fd, libc::STDOUT_FILENO);
        libc::dup2(fd, libc::STDERR_FILENO);
        libc::close(fd);
        libc::close(libc::STDIN_FILENO);
    }

    Ok(())
}

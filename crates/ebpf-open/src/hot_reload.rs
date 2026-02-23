use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;

/// 基于 inotify 的配置文件监听器
pub struct ConfigWatcher {
    inotify_fd: RawFd,
    _wd: i32,
    filename: OsString,
}

impl ConfigWatcher {
    /// 创建监听器，监听指定配置文件的修改事件
    pub fn new(config_path: &Path) -> anyhow::Result<Self> {
        let watch_dir = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let filename = config_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("config path has no filename"))?
            .to_os_string();

        let dir_cstr = CString::new(
            watch_dir
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("config path is not valid UTF-8"))?,
        )?;

        unsafe {
            let fd = libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC);
            if fd < 0 {
                return Err(anyhow::anyhow!(
                    "inotify_init1 failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let wd = libc::inotify_add_watch(
                fd,
                dir_cstr.as_ptr(),
                libc::IN_MODIFY | libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_CREATE,
            );
            if wd < 0 {
                libc::close(fd);
                return Err(anyhow::anyhow!(
                    "inotify_add_watch failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            Ok(Self {
                inotify_fd: fd,
                _wd: wd,
                filename,
            })
        }
    }

    /// 非阻塞检查配置文件是否变更
    pub fn poll_change(&self) -> bool {
        let mut buf = [0u8; 4096];
        let n = unsafe {
            libc::read(
                self.inotify_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n <= 0 {
            return false;
        }
        let n = n as usize;
        let mut offset = 0;
        let event_hdr = std::mem::size_of::<libc::inotify_event>();
        while offset + event_hdr <= n {
            let event = unsafe { &*(buf.as_ptr().add(offset) as *const libc::inotify_event) };
            let name_len = event.len as usize;
            if name_len > 0 && offset + event_hdr + name_len <= n {
                let name_bytes = &buf[offset + event_hdr..offset + event_hdr + name_len];
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
                if name_bytes[..name_end] == *self.filename.as_bytes() {
                    return true;
                }
            }
            offset += event_hdr + name_len;
        }
        false
    }
}

impl Drop for ConfigWatcher {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.inotify_fd);
        }
    }
}

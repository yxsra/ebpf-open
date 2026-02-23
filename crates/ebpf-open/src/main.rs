mod bpf_loader;
mod cli;
mod daemon;
mod event_handler;
mod hot_reload;
mod log;

use ebpf_open_sys::*;
use intercept_config::Config;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use std::collections::HashMap;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_sigint(_: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

fn main() -> anyhow::Result<()> {
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_sigint as *const () as libc::sighandler_t,
        );
    }

    let rlim = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    unsafe {
        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) != 0 {
            eprintln!("warning: failed to set RLIMIT_MEMLOCK");
        }
    }

    let args = cli::parse_args();
    if let Some(ref path) = args.log_file {
        daemon::daemonize(path)?;
    }
    log::init(args.verbosity);

    // 加载 BPF skeleton
    let builder = FileMonitorSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = if let Some(ref path) = args.btf_path {
        let path_cstr = CString::new(
            path.to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid btf path: non-UTF8"))?,
        )?;
        let open_opts = libbpf_sys::bpf_object_open_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t,
            btf_custom_path: path_cstr.as_ptr(),
            ..Default::default()
        };
        builder.open_opts(open_opts, &mut open_object)?
    } else {
        builder.open(&mut open_object)?
    };
    // 设置 BPF 全局变量（必须在 load 之前）
    if let Some(rodata) = open_skel.maps.rodata_data.as_mut() {
        rodata.verbose_level = args.verbosity;
        if let Some(ref path) = args.config_path {
            let cfg = Config::load(path)?;
            rodata.modify_enabled = if cfg.settings.modify_enabled { 1 } else { 0 };
        }
    }
    let mut skel = open_skel.load()?;

    // 排除自身 pid
    bpf_loader::whitelist_self(&mut skel)?;

    // 加载初始配置
    let mut nr_names: HashMap<u32, String> = HashMap::new();
    let hot_reload_enabled = if let Some(ref path) = args.config_path {
        let config = Config::load(path)?;
        for s in &config.syscall {
            nr_names.insert(s.nr.arm64, s.name.clone());
            if let Some(nr32) = s.nr.arm32 {
                nr_names.insert(nr32, s.name.clone());
            }
        }
        let validated = config.validate()?;
        bpf_loader::load_syscall_args(&mut skel, &validated)?;
        bpf_loader::load_whitelist(&mut skel, &config)?;
        if config.settings.modify_enabled {
            bpf_loader::load_modify_rules(&mut skel, &validated)?;
        }
        config.settings.hot_reload
    } else {
        false
    };

    skel.attach()?;

    // 设置 ring buffer
    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, |data| event_handler::handle_print_event(data, &nr_names))?;
    rb_builder.add(&skel.maps.intercept_events, |data| {
        event_handler::handle_intercept_event(data)
    })?;
    let rb = rb_builder.build()?;

    // 设置热重载监听
    let watcher = if hot_reload_enabled {
        if let Some(ref path) = args.config_path {
            match hot_reload::ConfigWatcher::new(path) {
                Ok(w) => {
                    log::info!("Hot reload enabled, watching config file.");
                    Some(w)
                }
                Err(e) => {
                    eprintln!("warning: failed to setup config watcher: {e}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    // 主循环
    log::info!("Monitoring file syscalls... Ctrl+C to stop.");
    while RUNNING.load(Ordering::Relaxed) {
        if let Err(e) = rb.poll(Duration::from_millis(100)) {
            if RUNNING.load(Ordering::Relaxed) {
                eprintln!("ring buffer poll error: {e}");
                break;
            }
        }

        // 日志轮转检查
        if let Some(ref path) = args.log_file {
            daemon::maybe_rotate_log(path);
        }

        // 检查配置变更
        if let Some(ref w) = watcher {
            if w.poll_change() {
                if let Some(ref path) = args.config_path {
                    match Config::load(path) {
                        Ok(config) => {
                            log::info!("Config changed, reloading rules...");
                            if let Err(e) =
                                bpf_loader::reload(&mut skel, &config)
                            {
                                eprintln!("Failed to reload rules: {e}");
                            }
                        }
                        Err(e) => eprintln!("Failed to parse config: {e}"),
                    }
                }
            }
        }
    }

    log::info!("\nExiting.");
    Ok(())
}

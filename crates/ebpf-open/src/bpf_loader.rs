use common::MAX_PATH_LEN;
use ebpf_open_sys::*;
use intercept_config::{Config, ValidatedConfig};
use libbpf_rs::{MapCore, MapFlags};

#[repr(C)]
struct BpfSyscallArgInfo {
    str_reg_idx: u32,
    flags: u32,
}

#[repr(C)]
struct BpfModifyRuleEntry {
    to: [u8; MAX_PATH_LEN],
    to_len: u32,
    filter_type: u32,
    rule_index: u32,
    allowed_uid_mask: u32,
    has_exclude_uids: u32,
    no_restore: u32,
}

#[repr(C)]
struct BpfRuleFilterKey {
    rule_index: u32,
    value: u32,
}

fn as_bytes<T>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) }
}

pub fn load_syscall_args(skel: &mut FileMonitorSkel, validated: &ValidatedConfig) -> anyhow::Result<()> {
    for (nr, info) in &validated.syscall_args_64 {
        let val = BpfSyscallArgInfo { str_reg_idx: info.str_reg_idx, flags: info.flags };
        skel.maps.syscall_args_64.update(&nr.to_ne_bytes(), as_bytes(&val), MapFlags::ANY)?;
    }
    for (nr, info) in &validated.syscall_args_32 {
        let val = BpfSyscallArgInfo { str_reg_idx: info.str_reg_idx, flags: info.flags };
        skel.maps.syscall_args_32.update(&nr.to_ne_bytes(), as_bytes(&val), MapFlags::ANY)?;
    }
    crate::log::info!(
        "Loaded {} 64-bit + {} 32-bit syscall entries",
        validated.syscall_args_64.len(), validated.syscall_args_32.len()
    );
    Ok(())
}

pub fn load_modify_rules(skel: &mut FileMonitorSkel, validated: &ValidatedConfig) -> anyhow::Result<()> {
    for rule in &validated.modify_rules {
        let val = BpfModifyRuleEntry {
            to: rule.to,
            to_len: rule.to_len,
            filter_type: rule.filter_type,
            rule_index: rule.rule_index,
            allowed_uid_mask: rule.allowed_uid_mask,
            has_exclude_uids: rule.has_exclude_uids,
            no_restore: rule.no_restore,
        };
        skel.maps.modify_rules.update(&rule.from, as_bytes(&val), MapFlags::ANY)?;
    }
    let v = [1u8];
    for fe in &validated.filter_entries {
        let key = BpfRuleFilterKey { rule_index: fe.rule_index, value: fe.value };
        skel.maps.rule_filter.update(as_bytes(&key), &v, MapFlags::ANY)?;
    }
    crate::log::info!("Loaded {} modify rules", validated.modify_rules.len());
    Ok(())
}


pub fn load_whitelist(skel: &mut FileMonitorSkel, config: &Config) -> anyhow::Result<()> {
    let val = [1u8];
    for &uid in &config.whitelist.uid {
        skel.maps.uid_whitelist.update(&uid.to_ne_bytes(), &val, MapFlags::ANY)?;
    }
    for &pid in &config.whitelist.pid {
        skel.maps.pid_whitelist.update(&pid.to_ne_bytes(), &val, MapFlags::ANY)?;
    }
    crate::log::info!("Loaded whitelist: {} uids, {} pids", config.whitelist.uid.len(), config.whitelist.pid.len());
    Ok(())
}

/// 写入自身 pid 到白名单
pub fn whitelist_self(skel: &mut FileMonitorSkel) -> anyhow::Result<()> {
    let pid = std::process::id();
    skel.maps.pid_whitelist.update(&pid.to_ne_bytes(), &[1u8], MapFlags::ANY)?;
    crate::log::info!("Self pid {} added to whitelist", pid);
    Ok(())
}

fn clear_map(map: &mut libbpf_rs::MapMut) {
    let keys: Vec<_> = map.keys().collect();
    for key in &keys {
        let _ = map.delete(key);
    }
}

pub fn clear_all(skel: &mut FileMonitorSkel) -> anyhow::Result<()> {
    clear_map(&mut skel.maps.modify_rules);
    clear_map(&mut skel.maps.rule_filter);
    clear_map(&mut skel.maps.pid_whitelist);
    clear_map(&mut skel.maps.uid_whitelist);
    clear_map(&mut skel.maps.syscall_args_64);
    clear_map(&mut skel.maps.syscall_args_32);
    clear_map(&mut skel.maps.pending_prints);
    Ok(())
}

pub fn reload(skel: &mut FileMonitorSkel, config: &Config) -> anyhow::Result<()> {
    clear_all(skel)?;
    whitelist_self(skel)?;
    load_whitelist(skel, config)?;
    let validated = config.validate()?;
    load_syscall_args(skel, &validated)?;
    if config.settings.modify_enabled {
        load_modify_rules(skel, &validated)?;
    }
    Ok(())
}

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;

pub const MAX_PATH_LEN: usize = 256;
pub const TASK_COMM_LEN: usize = 16;

pub const SYSCALL_FLAG_MODIFY: u32 = 1 << 0;
pub const SYSCALL_FLAG_PRINT: u32 = 1 << 1;

pub const FILTER_NONE: u32 = 0;
pub const FILTER_PIDS: u32 = 1;
pub const FILTER_UIDS: u32 = 2;
pub const FILTER_UID_GROUPS: u32 = 3;

pub const UID_GROUP_APP: u32 = 1 << 0;
pub const UID_GROUP_ISO: u32 = 1 << 1;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("{0}")]
    Validation(String),
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub whitelist: Whitelist,
    #[serde(default)]
    pub syscall: Vec<SyscallDef>,
    #[serde(default)]
    pub syscall_groups: Vec<SyscallGroup>,
    #[serde(default)]
    pub print: Option<PrintConfig>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    #[serde(default = "default_true")]
    pub modify_enabled: bool,
    #[serde(default = "default_true")]
    pub hot_reload: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { modify_enabled: true, hot_reload: true }
    }
}

fn default_true() -> bool { true }

#[derive(Debug, Deserialize, Default)]
pub struct Whitelist {
    #[serde(default)]
    pub uid: Vec<u32>,
    #[serde(default)]
    pub pid: Vec<u32>,
}

#[derive(Debug, Deserialize)]
pub struct SyscallDef {
    pub name: String,
    pub nr: SyscallNr,
    #[serde(default)]
    pub arm64: Vec<ArgDef>,
    #[serde(default)]
    pub arm32: Vec<ArgDef>,
}

#[derive(Debug, Deserialize)]
pub struct SyscallNr {
    pub arm64: u32,
    pub arm32: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ArgDef {
    pub reg: u32,
    #[serde(rename = "type")]
    pub arg_type: ArgType,
    pub name: String,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ArgType { Str, Int }

#[derive(Debug, Deserialize)]
pub struct SyscallGroup {
    pub name: String,
    pub syscalls: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PrintConfig {
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub groups: Vec<String>,
    pub modify: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub exclude_uid: Vec<u32>,
    #[serde(default)]
    pub uid_groups: Vec<String>,
    #[serde(default)]
    pub pids: Vec<u32>,
    #[serde(default)]
    pub uids: Vec<u32>,
    #[serde(default)]
    pub no_restore: bool,
}

// ==================== 校验输出 ====================

#[derive(Debug, Clone)]
pub struct SyscallArgInfo {
    pub str_reg_idx: u32,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct ValidatedModifyRule {
    pub from: [u8; MAX_PATH_LEN],
    pub to: [u8; MAX_PATH_LEN],
    pub to_len: u32,
    pub filter_type: u32,
    pub rule_index: u32,
    pub allowed_uid_mask: u32,
    pub has_exclude_uids: u32,
    pub no_restore: u32,
}

#[derive(Debug, Clone)]
pub struct FilterEntry {
    pub rule_index: u32,
    pub value: u32,
}

#[derive(Debug)]
pub struct ValidatedConfig {
    pub syscall_args_64: Vec<(u32, SyscallArgInfo)>,
    pub syscall_args_32: Vec<(u32, SyscallArgInfo)>,
    pub modify_rules: Vec<ValidatedModifyRule>,
    pub filter_entries: Vec<FilterEntry>,
}

fn resolve_uid_group_mask(name: &str) -> Option<u32> {
    match name {
        "app" => Some(UID_GROUP_APP),
        "iso" => Some(UID_GROUP_ISO),
        _ => None,
    }
}

/// 找 str 参数的寄存器索引：优先匹配 modify_param 名，否则取第一个 str 参数
fn find_str_reg(args: &[ArgDef], modify_param: Option<&str>) -> Option<u32> {
    if let Some(name) = modify_param {
        if let Some(a) = args.iter().find(|a| a.name == name && a.arg_type == ArgType::Str) {
            return Some(a.reg);
        }
    }
    args.iter().find(|a| a.arg_type == ArgType::Str).map(|a| a.reg)
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn validate(&self) -> Result<ValidatedConfig, ConfigError> {
        let err = |msg: String| ConfigError::Validation(msg);

        // syscall name -> def
        let syscall_map: HashMap<&str, &SyscallDef> =
            self.syscall.iter().map(|s| (s.name.as_str(), s)).collect();

        // group name -> syscall names
        let group_map: HashMap<&str, &[String]> = self
            .syscall_groups.iter()
            .map(|g| (g.name.as_str(), g.syscalls.as_slice()))
            .collect();

        // 收集 active syscalls: (flags, modify_param_name)
        let mut active: HashMap<&str, (u32, Option<&str>)> = HashMap::new();

        for (i, rule) in self.rules.iter().enumerate() {
            for gname in &rule.groups {
                let syscalls = group_map.get(gname.as_str())
                    .ok_or_else(|| err(format!("rule[{i}]: unknown group '{gname}'")))?;
                for sname in *syscalls {
                    let e = active.entry(sname.as_str()).or_insert((0, None));
                    e.0 |= SYSCALL_FLAG_MODIFY;
                    if let Some(prev) = e.1 {
                        if prev != rule.modify.as_str() {
                            return Err(err(format!(
                                "syscall '{sname}': conflicting modify params"
                            )));
                        }
                    } else {
                        e.1 = Some(rule.modify.as_str());
                    }
                }
            }
        }

        if let Some(ref print) = self.print {
            for gname in &print.groups {
                let syscalls = group_map.get(gname.as_str())
                    .ok_or_else(|| err(format!("[print]: unknown group '{gname}'")))?;
                for sname in *syscalls {
                    active.entry(sname.as_str()).or_insert((0, None)).0 |= SYSCALL_FLAG_PRINT;
                }
            }
        }

        // 生成 syscall_args
        let mut args_64 = Vec::new();
        let mut args_32 = Vec::new();

        for (&sname, &(flags, modify_param)) in &active {
            let def = syscall_map.get(sname)
                .ok_or_else(|| err(format!("undefined syscall '{sname}'")))?;

            let reg64 = find_str_reg(&def.arm64, modify_param)
                .ok_or_else(|| err(format!("syscall '{sname}' arm64: no str param")))?;
            args_64.push((def.nr.arm64, SyscallArgInfo { str_reg_idx: reg64, flags }));

            if let Some(nr32) = def.nr.arm32 {
                let reg32 = find_str_reg(&def.arm32, modify_param)
                    .ok_or_else(|| err(format!("syscall '{sname}' arm32: no str param")))?;
                args_32.push((nr32, SyscallArgInfo { str_reg_idx: reg32, flags }));
            }
        }

        // 校验 rules
        let mut from_set: HashSet<&str> = HashSet::new();
        let mut modify_rules = Vec::new();
        let mut filter_entries = Vec::new();

        for (i, rule) in self.rules.iter().enumerate() {
            if !from_set.insert(&rule.from) {
                return Err(err(format!("rule[{i}]: duplicate from '{}'", rule.from)));
            }
            if rule.from.len() >= MAX_PATH_LEN {
                return Err(err(format!("rule[{i}]: from too long")));
            }
            if rule.to.len() >= MAX_PATH_LEN {
                return Err(err(format!("rule[{i}]: to too long")));
            }
            if rule.to.len() > rule.from.len() {
                return Err(err(format!(
                    "rule[{i}]: to ({} bytes) > from ({} bytes)",
                    rule.to.len(), rule.from.len()
                )));
            }

            // 过滤三选一
            let cnt = !rule.pids.is_empty() as u8
                + !rule.uids.is_empty() as u8
                + !rule.uid_groups.is_empty() as u8;
            if cnt > 1 {
                return Err(err(format!("rule[{i}]: pids/uids/uid_groups mutually exclusive")));
            }
            if !rule.exclude_uid.is_empty() && rule.uid_groups.is_empty() {
                return Err(err(format!("rule[{i}]: exclude_uid requires uid_groups")));
            }

            let rule_index = i as u32;
            let (filter_type, allowed_uid_mask) = if !rule.pids.is_empty() {
                for &pid in &rule.pids {
                    filter_entries.push(FilterEntry { rule_index, value: pid });
                }
                (FILTER_PIDS, 0)
            } else if !rule.uids.is_empty() {
                for &uid in &rule.uids {
                    filter_entries.push(FilterEntry { rule_index, value: uid });
                }
                (FILTER_UIDS, 0)
            } else if !rule.uid_groups.is_empty() {
                let mut mask = 0u32;
                for g in &rule.uid_groups {
                    mask |= resolve_uid_group_mask(g)
                        .ok_or_else(|| err(format!("rule[{i}]: unknown uid_group '{g}'")))?;
                }
                for &uid in &rule.exclude_uid {
                    filter_entries.push(FilterEntry { rule_index, value: uid });
                }
                (FILTER_UID_GROUPS, mask)
            } else {
                (FILTER_NONE, 0)
            };

            let mut from_buf = [0u8; MAX_PATH_LEN];
            from_buf[..rule.from.len()].copy_from_slice(rule.from.as_bytes());
            let mut to_buf = [0u8; MAX_PATH_LEN];
            to_buf[..rule.to.len()].copy_from_slice(rule.to.as_bytes());

            modify_rules.push(ValidatedModifyRule {
                from: from_buf,
                to: to_buf,
                to_len: rule.to.len() as u32 + 1,
                filter_type,
                rule_index,
                allowed_uid_mask,
                has_exclude_uids: if rule.exclude_uid.is_empty() { 0 } else { 1 },
                no_restore: if rule.no_restore { 1 } else { 0 },
            });
        }

        Ok(ValidatedConfig { syscall_args_64: args_64, syscall_args_32: args_32, modify_rules, filter_entries })
    }
}

# ebpf-open

基于 eBPF 的 Android 文件访问监控与拦截工具。通过 `raw_tracepoint.w` hook 系统调用，实现对指定目录/文件的访问监控、路径重定向，并支持按进程名/UID/PID 过滤。

## 特性

- **多 syscall 监控** — openat, openat2, execve, execveat, faccessat, statfs, readlinkat, newfstatat, statx
- **路径重定向** — 透明地将文件访问重定向到其他路径，sys_exit 自动恢复原始路径
- **灵活过滤** — 按 PID / UID / UID 分组（app, iso）三选一过滤，支持 exclude_uid
- **白名单** — PID / UID 维度白名单，自动排除自身进程
- **配置热重载** — inotify 监听配置文件变更，无需重启即可更新规则
- **守护进程模式** — fork 后台运行，日志自动轮转（2MB）
- **BPF CO-RE** — 支持 BTF，跨内核版本兼容（Android Kernel 5.10+）

## 环境要求

- Linux x86_64 主机（编译环境）
- Rust toolchain + `aarch64-unknown-linux-musl` / `aarch64-linux-android` target
- clang/llvm（BPF 编译）
- 目标设备：Android Kernel 5.10+，Root 权限

### 编译目标

| Target | 说明 |
|--------|------|
| `aarch64-unknown-linux-musl` | 完全静态链接，通用 aarch64 Linux |
| `aarch64-linux-android` | 动态链接 libc/libdl，Android 设备 |

## 编译

### musl 静态编译

```bash
# 1. 准备 musl 工具链和 sysroot
./setup_musl_sysroot.sh

# 2. 编译
./build_musl.sh
# 产物: dist/ebpf-open-static
```

### Android NDK 编译

```bash
# 1. 准备 NDK sysroot
./setup_ndk_sysroot.sh

# 2. 编译
./build_android.sh
# 产物: dist/ebpf-open-android
```


## 使用

```
ebpf-open [OPTIONS]

OPTIONS:
    -c <path>       配置文件路径（默认: ./config.toml）
    --btf <path>    自定义 BTF 文件路径
    -q              静默模式，仅输出错误
    -v              详细模式：显示监控事件
    -vv             调试模式：显示调试信息
    -s <path>       守护进程模式，日志输出到文件
    -h, --help      显示帮助
```

## 配置

配置文件为 TOML 格式（[config.toml](crates/res/config.toml)），支持热重载。

## License

MIT

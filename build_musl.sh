#!/bin/bash
set -euo pipefail

MUSL_CROSS=/home/root1/aarch64-linux-musl-cross
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SYSROOT_DIR=$PROJECT_DIR/sysroot-musl

# 验证依赖
for f in "$SYSROOT_DIR/lib/libelf.a" "$SYSROOT_DIR/lib/libz.a"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: missing $f"
        echo "请先编译 musl-compatible libelf.a 和 libz.a 到 sysroot-musl/lib/"
        exit 1
    fi
done

if [ ! -x "$MUSL_CROSS/bin/aarch64-linux-musl-gcc" ]; then
    echo "ERROR: musl-cross toolchain not found at $MUSL_CROSS"
    echo "请下载: wget https://musl.cc/aarch64-linux-musl-cross.tgz"
    exit 1
fi

# cc crate 环境变量（libbpf-sys vendored-libbpf 编译用）
export CC_aarch64_unknown_linux_musl="${MUSL_CROSS}/bin/aarch64-linux-musl-gcc"
export AR_aarch64_unknown_linux_musl="${MUSL_CROSS}/bin/aarch64-linux-musl-ar"
export RANLIB_aarch64_unknown_linux_musl="${MUSL_CROSS}/bin/aarch64-linux-musl-ranlib"
export CFLAGS_aarch64_unknown_linux_musl="-I${SYSROOT_DIR}/include"

# libbpf-sys vendored-libbpf 编译 libbpf 时的额外 CFLAGS
export LIBBPF_SYS_EXTRA_CFLAGS="-I${SYSROOT_DIR}/include"

# 禁用 pkg-config 避免找到 host 的库
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_PATH=""
export PKG_CONFIG_LIBDIR=""

cd "$PROJECT_DIR"
cargo build --target aarch64-unknown-linux-musl --release -p ebpf-open -vv

# 复制产物到 dist/
DIST_DIR=$PROJECT_DIR/dist
mkdir -p "$DIST_DIR"
cp target/aarch64-unknown-linux-musl/release/ebpf-open "$DIST_DIR/ebpf-open-static"
"${MUSL_CROSS}/bin/aarch64-linux-musl-strip" "$DIST_DIR/ebpf-open-static"
echo "Output: $DIST_DIR/ebpf-open-static"

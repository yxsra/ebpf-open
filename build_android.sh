#!/bin/bash
set -euo pipefail

NDK=/home/root1/ndk/android-ndk-r28c
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SYSROOT_DIR=$PROJECT_DIR/sysroot

# 验证依赖
for f in "$SYSROOT_DIR/lib/libelf.a" "$SYSROOT_DIR/lib/libz.a" \
         "$SYSROOT_DIR/include/libelf.h" "$SYSROOT_DIR/include/zlib.h"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: missing $f"
        exit 1
    fi
done

# cc crate 环境变量（libbpf-sys vendored 编译用）
export CC_aarch64_linux_android="${TOOLCHAIN}/bin/aarch64-linux-android30-clang"
export AR_aarch64_linux_android="${TOOLCHAIN}/bin/llvm-ar"
export RANLIB_aarch64_linux_android="${TOOLCHAIN}/bin/llvm-ranlib"
export CFLAGS_aarch64_linux_android="-I${SYSROOT_DIR}/include -D__poll_t=unsigned"

# libbpf-sys vendored-libbpf 编译 libbpf 时的额外 CFLAGS
export LIBBPF_SYS_EXTRA_CFLAGS="-I${SYSROOT_DIR}/include -D__poll_t=unsigned"

# 禁用 pkg-config 避免找到 host 的库
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_PATH=""
export PKG_CONFIG_LIBDIR=""

cargo build --target aarch64-linux-android --release -p ebpf-open -vv

# 复制产物到 dist/
DIST_DIR=$PROJECT_DIR/dist
mkdir -p "$DIST_DIR"
cp target/aarch64-linux-android/release/ebpf-open "$DIST_DIR/ebpf-open-android"
echo "Output: $DIST_DIR/ebpf-open-android"

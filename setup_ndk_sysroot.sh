#!/bin/bash
# 准备 Android NDK 交叉编译环境：编译 elfutils libelf、复制 zlib
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SYSROOT_DIR=$PROJECT_DIR/sysroot
NDK=/home/root/ndk/android-ndk-r28c
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
NDK_SYSROOT=$TOOLCHAIN/sysroot
WORK_DIR=/tmp/ndk-sysroot-build

mkdir -p "$WORK_DIR"

# ============================================================
# 1. 验证 NDK
# ============================================================
if [ ! -x "$TOOLCHAIN/bin/aarch64-linux-android30-clang" ]; then
    echo "ERROR: NDK not found at $NDK"
    echo "use wget https://dl.google.com/android/repository/android-ndk-r28c-linux.zip && unzip android-ndk-r28c-linux.zip to download NDK r28c and unzip it to $NDK"
    echo "请下载 NDK r28c 并解压到 $NDK"
    exit 1
fi
echo "NDK found at $NDK"

export CC="$TOOLCHAIN/bin/aarch64-linux-android30-clang"
export AR="$TOOLCHAIN/bin/llvm-ar"
export RANLIB="$TOOLCHAIN/bin/llvm-ranlib"

# ============================================================
# 2. 添加 Rust target
# ============================================================
if rustup target list --installed | grep -q aarch64-linux-android; then
    echo "Rust target aarch64-linux-android already installed."
else
    echo "Adding Rust target aarch64-linux-android..."
    rustup target add aarch64-linux-android
fi

# ============================================================
# 3. 编译 elfutils libelf.a
# ============================================================
ELFUTILS_VER=0.191
ELFUTILS_SRC=$WORK_DIR/elfutils-$ELFUTILS_VER

if [ -f "$SYSROOT_DIR/lib/libelf.a" ]; then
    echo "libelf.a already exists in $SYSROOT_DIR/lib/"
else
    echo "Building elfutils libelf for Android..."

    if [ ! -d "$ELFUTILS_SRC" ]; then
        cd "$WORK_DIR"
        wget -q --show-progress "https://sourceware.org/elfutils/ftp/$ELFUTILS_VER/elfutils-$ELFUTILS_VER.tar.bz2"
        tar xf "elfutils-$ELFUTILS_VER.tar.bz2"
    fi

    # 修补 lib/eu-config.h：NDK sysroot 没有 libintl.h
    # 将无条件 #include <libintl.h> 改为条件编译
    cd "$ELFUTILS_SRC"
    if grep -q '^#include <libintl.h>' lib/eu-config.h; then
        echo "Patching lib/eu-config.h for libintl.h..."
        sed -i 's|^#include <libintl.h>|#if ENABLE_NLS\n#include <libintl.h>|' lib/eu-config.h
        sed -i '/^#define N_(Str) Str/{
            N
            s|#define N_(Str) Str\n#define _(Str) dgettext ("elfutils", Str)|#define N_(Str) Str\n#define _(Str) dgettext ("elfutils", Str)\n#else\n#define N_(Str) Str\n#define _(Str) Str\n#endif|
        }' lib/eu-config.h
        echo "Patch applied."
    fi

    # configure：
    # - 跳过 argp/obstack 检查（glibc 特有，bionic 没有，libelf 不需要）
    # - program_invocation_short_name: bionic 用 __progname 代替
    CFLAGS="-O2 -D_GNU_SOURCE -Dprogram_invocation_short_name=__progname -Dprogram_invocation_name=__progname" \
    ./configure \
        --host=aarch64-linux-android \
        --prefix=/tmp/elfutils-android \
        --disable-debuginfod --disable-libdebuginfod \
        --disable-demangler --disable-nls \
        ac_cv_null_dereference=no \
        ac_cv_c11_thread_local=no \
        ac_cv_search_argp_parse="none required" \
        ac_cv_search__obstack_free="none required"

    cd libelf && make -j"$(nproc)" libelf.a

    mkdir -p "$SYSROOT_DIR/lib" "$SYSROOT_DIR/include"
    cp libelf.a "$SYSROOT_DIR/lib/"
    cp "$ELFUTILS_SRC/libelf/libelf.h" "$SYSROOT_DIR/include/"
    cp "$ELFUTILS_SRC/libelf/gelf.h" "$SYSROOT_DIR/include/"
    cp "$ELFUTILS_SRC/lib/nlist.h" "$SYSROOT_DIR/include/" 2>/dev/null || true
    echo "libelf.a installed to $SYSROOT_DIR/lib/"
fi

# ============================================================
# 4. 复制 zlib（NDK sysroot 自带）
# ============================================================
if [ -f "$SYSROOT_DIR/lib/libz.a" ]; then
    echo "libz.a already exists in $SYSROOT_DIR/lib/"
else
    echo "Copying zlib from NDK sysroot..."

    mkdir -p "$SYSROOT_DIR/lib" "$SYSROOT_DIR/include"
    cp "$NDK_SYSROOT/usr/lib/aarch64-linux-android/libz.a" "$SYSROOT_DIR/lib/"
    cp "$NDK_SYSROOT/usr/include/zlib.h" "$SYSROOT_DIR/include/"
    cp "$NDK_SYSROOT/usr/include/zconf.h" "$SYSROOT_DIR/include/"
    echo "libz.a installed to $SYSROOT_DIR/lib/"
fi

# ============================================================
# 5. 复制 elf.h（NDK sysroot 自带）
# ============================================================
if [ ! -f "$SYSROOT_DIR/include/elf.h" ]; then
    cp "$NDK_SYSROOT/usr/include/elf.h" "$SYSROOT_DIR/include/"
fi

# ============================================================
# 完成
# ============================================================
echo ""
echo "=========================================="
echo "NDK sysroot ready: $SYSROOT_DIR"
echo "=========================================="
echo ""
ls -la "$SYSROOT_DIR/lib/"
echo ""
echo "Now you can run: ./build_android.sh"

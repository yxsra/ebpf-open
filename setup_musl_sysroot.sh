#!/bin/bash
# 准备 musl 交叉编译环境：下载 musl-cross 工具链、编译 elfutils libelf 和 zlib
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SYSROOT_DIR=$PROJECT_DIR/sysroot-musl
MUSL_CROSS_DIR=/home/root/aarch64-linux-musl-cross
WORK_DIR=/tmp/musl-sysroot-build

mkdir -p "$WORK_DIR"

# ============================================================
# 1. 下载并安装 musl-cross 工具链
# ============================================================
if [ -x "$MUSL_CROSS_DIR/bin/aarch64-linux-musl-gcc" ]; then
    echo "musl-cross toolchain already installed at $MUSL_CROSS_DIR"
else
    echo "Downloading musl-cross toolchain..."
    cd /tmp
    wget -q --show-progress https://musl.cc/aarch64-linux-musl-cross.tgz
    echo "Extracting to $MUSL_CROSS_DIR..."
    tar xf aarch64-linux-musl-cross.tgz -C "$(dirname "$MUSL_CROSS_DIR")"
    echo "musl-cross toolchain installed."
fi


export CC="$MUSL_CROSS_DIR/bin/aarch64-linux-musl-gcc"
export AR="$MUSL_CROSS_DIR/bin/aarch64-linux-musl-ar"
export RANLIB="$MUSL_CROSS_DIR/bin/aarch64-linux-musl-ranlib"

# ============================================================
# 2. 添加 Rust target
# ============================================================
if rustup target list --installed | grep -q aarch64-unknown-linux-musl; then
    echo "Rust target aarch64-unknown-linux-musl already installed."
else
    echo "Adding Rust target aarch64-unknown-linux-musl..."
    rustup target add aarch64-unknown-linux-musl
fi

# ============================================================
# 3. 编译 zlib（必须在 elfutils 之前，因为 elfutils configure 依赖 zlib）
# ============================================================
ZLIB_VER=1.3.2
ZLIB_SRC=$WORK_DIR/zlib-$ZLIB_VER
ZLIB_PREFIX=$WORK_DIR/zlib-install

if [ -f "$SYSROOT_DIR/lib/libz.a" ]; then
    echo "libz.a already exists in $SYSROOT_DIR/lib/"
else
    echo "Building zlib for musl..."

    if [ ! -d "$ZLIB_SRC" ]; then
        cd "$WORK_DIR"
      
        wget -q --show-progress "https://zlib.net/zlib-$ZLIB_VER.tar.gz" || wget -q --show-progress "https://zlib.net/current/zlib.tar.gz" || echo "wget zlib err" 
      
        ZIPL_NAME="zlib-$ZLIB_VER.tar.gz"
        if [ ! -f "$ZIPL_NAME" ]; then
            ZIPL_NAME="zlib.tar.gz"
        fi
        echo "Extracting $ZIPL_NAME..."
        tar xf "$ZIPL_NAME"
    fi

    cd "$ZLIB_SRC"
    ./configure --static --prefix="$ZLIB_PREFIX"
    make -j"$(nproc)"
    make install

    mkdir -p "$SYSROOT_DIR/lib" "$SYSROOT_DIR/include"
    cp "$ZLIB_PREFIX/lib/libz.a" "$SYSROOT_DIR/lib/"
    cp "$ZLIB_PREFIX/include/zlib.h" "$SYSROOT_DIR/include/"
    cp "$ZLIB_PREFIX/include/zconf.h" "$SYSROOT_DIR/include/"
    echo "libz.a installed to $SYSROOT_DIR/lib/"
fi

# ============================================================
# 4. 编译 elfutils libelf.a
# ============================================================
ELFUTILS_VER=0.191
ELFUTILS_SRC=$WORK_DIR/elfutils-$ELFUTILS_VER

if [ -f "$SYSROOT_DIR/lib/libelf.a" ]; then
    echo "libelf.a already exists in $SYSROOT_DIR/lib/"
else
    echo "Building elfutils libelf for musl..."

    if [ ! -d "$ELFUTILS_SRC" ]; then
        cd "$WORK_DIR"
        wget -q --show-progress "https://sourceware.org/elfutils/ftp/$ELFUTILS_VER/elfutils-$ELFUTILS_VER.tar.bz2"
        tar xf "elfutils-$ELFUTILS_VER.tar.bz2"
    fi

    # 修补 lib/eu-config.h：libintl.h 在 musl 中也不可用
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

    # configure：跳过 argp 和 obstack 检查（musl 没有这些 glibc 特有库）
    # CFLAGS/LDFLAGS 指向 sysroot，让 configure 找到已编译的 zlib
    CFLAGS="-O2 -D_GNU_SOURCE -I$SYSROOT_DIR/include" \
    LDFLAGS="-L$SYSROOT_DIR/lib" \
    ./configure \
        --host=aarch64-linux-musl \
        --disable-debuginfod --disable-libdebuginfod \
        --disable-demangler --disable-nls \
        ac_cv_null_dereference=no \
        ac_cv_c11_thread_local=no \
        ac_cv_search_argp_parse="none required" \
        ac_cv_search__obstack_free="none required" \
        ac_cv_search_fts_close="none required"

    cd libelf && make -j"$(nproc)" libelf.a

    mkdir -p "$SYSROOT_DIR/lib" "$SYSROOT_DIR/include"
    cp libelf.a "$SYSROOT_DIR/lib/"
    cp "$ELFUTILS_SRC/libelf/libelf.h" "$SYSROOT_DIR/include/"
    cp "$ELFUTILS_SRC/libelf/gelf.h" "$SYSROOT_DIR/include/"
    cp "$ELFUTILS_SRC/lib/nlist.h" "$SYSROOT_DIR/include/" 2>/dev/null || true
    echo "libelf.a installed to $SYSROOT_DIR/lib/"
fi

# ============================================================
# 5. 复制 elf.h（musl-cross sysroot 自带）
# ============================================================
MUSL_SYSROOT=$MUSL_CROSS_DIR/aarch64-linux-musl
if [ ! -f "$SYSROOT_DIR/include/elf.h" ]; then
    cp "$MUSL_SYSROOT/include/elf.h" "$SYSROOT_DIR/include/"
fi

# ============================================================
# 完成
# ============================================================
echo ""
echo "=========================================="
echo "musl sysroot ready: $SYSROOT_DIR"
echo "=========================================="
echo ""
ls -la "$SYSROOT_DIR/lib/"
echo ""
echo "Now you can run: ./build_musl.sh"

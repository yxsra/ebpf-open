use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/file_monitor.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"))
        .join("src")
        .join("bpf")
        .join("file_monitor.skel.rs");

    let libbpf_include = env::var("DEP_BPF_INCLUDE").expect("DEP_BPF_INCLUDE not set");

    // BPF 源文件目录，用于解析 #include "common/..." 和 "aarch64/..."
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let bpf_src_dir = manifest_dir.join("src").join("bpf");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            "-Wno-compare-distinct-pointer-types",
            &format!("-I{libbpf_include}"),
            &format!("-I{}", bpf_src_dir.display()),
        ])
        .build_and_generate(&out)
        .expect("failed to build and generate BPF skeleton");

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/bpf/common/types.h");
    println!("cargo:rerun-if-changed=src/bpf/common/maps.h");
    println!("cargo:rerun-if-changed=src/bpf/common/helpers.h");
    println!("cargo:rerun-if-changed=src/bpf/common/misc.h");
    println!("cargo:rerun-if-changed=src/bpf/common/utils.h");
    println!("cargo:rerun-if-changed=src/bpf/aarch64/vmlinux_510.h");
    println!("cargo:rerun-if-changed=src/bpf/aarch64/vmlinux_5.15.h");
    println!("cargo:rerun-if-changed=src/bpf/aarch64/vmlinux_608.h");

    // sysroot 在 workspace 根目录，需要向上两级
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let sysroot_lib = workspace_root.join("sysroot").join("lib");
    println!("cargo:rustc-link-search=native={}", sysroot_lib.display());
}

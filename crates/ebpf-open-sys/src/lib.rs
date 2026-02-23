#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code
)]
mod bpf {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/file_monitor.skel.rs"));
}

pub use bpf::*;

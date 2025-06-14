//! Build script for the `runqslower` example.

use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/file.bpf.c";
// const HEADER: &str = "src/bpf/runqslower.h";

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("file.skel.rs");

  let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let vmlinux_root = vmlinux::include_path_root();              // e.g. "/…/vmlinux.h"
    let vmlinux_arch_dir = vmlinux_root.join(&arch);              // e.g. "/…/vmlinux.h/x86_64"
    let my_bpf_dir     = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                             .join("src")
                             .join("bpf");                        // "…/src/bpf"

    SkeletonBuilder::new()
        .source(SRC)
   .clang_args(&[
            OsStr::new("-I"), vmlinux_arch_dir.as_os_str(),      // for <vmlinux.h>
            OsStr::new("-I"), my_bpf_dir.as_os_str(),             // for your own headers
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    // println!("cargo:rerun-if-changed={HEADER}");
}

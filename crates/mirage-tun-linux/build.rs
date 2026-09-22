// Compile the eBPF program (bpf-progs/mirage_bpf.c) to a BPF ELF object with
// `clang -target bpf` and place it in OUT_DIR. firewall.rs embeds it via
// include_bytes! and loads it at runtime with the aya loader.
//
// Self-contained C (no libbpf headers) → compiles with the clang present in the
// canonical messense/rust-musl-cross image (and any clang + linux-libc-dev).

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf-progs/mirage_bpf.c");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let obj = PathBuf::from(&out_dir).join("mirage_bpf.o");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    // HOST != TARGET means this is a cross-compile/type-check run (e.g. `cargo
    // check --target x86_64-unknown-linux-gnu` from a Windows or macOS
    // workstation with no `clang -target bpf` available). The binary produced
    // there is never a real deployment artifact — only a *native* Linux build
    // (HOST == TARGET == linux) is. Keep the strict "clang or panic" behavior
    // for that case; only a genuine cross-host run gets the placeholder.
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    let native_linux_build = target_os == "linux" && host == target;

    if native_linux_build {
        let status = Command::new("clang")
            .args([
                "-O2",
                "-g",
                "-target",
                "bpf",
                // asm/ headers for the multiarch include path (Debian/Ubuntu).
                "-I/usr/include/x86_64-linux-gnu",
                "-c",
                "bpf-progs/mirage_bpf.c",
                "-o",
            ])
            .arg(&obj)
            .status()
            .expect("clang not found: the BPF object needs clang (present in the messense build image)");
        assert!(status.success(), "clang failed to compile bpf-progs/mirage_bpf.c");
    } else {
        // Non-native build (non-Linux target, or a Linux target cross-checked
        // from a non-Linux host): the aya loader is never exercised there —
        // write an empty object so include_bytes! resolves and the crate
        // still type-checks.
        if target_os == "linux" {
            println!(
                "cargo:warning=mirage-tun-linux: cross-compiling for linux from host '{host}' — \
                 writing a placeholder eBPF object (no clang cross toolchain here); this build is \
                 for type-checking only, not a real deployment artifact"
            );
        }
        std::fs::write(&obj, []).expect("failed to write placeholder BPF object");
    }
}

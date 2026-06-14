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

    if target_os == "linux" {
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
        // Non-Linux host build (e.g. a cross-check): the aya loader is never
        // exercised there; write an empty object so include_bytes! resolves.
        std::fs::write(&obj, []).expect("failed to write placeholder BPF object");
    }
}

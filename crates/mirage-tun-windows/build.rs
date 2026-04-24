use std::path::Path;

fn main() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let src = workspace_root.join("tun.json");
    if src.exists() {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        // OUT_DIR is deep inside target/; walk up to target/{profile}/
        let profile_dir = Path::new(&out_dir)
            .ancestors()
            .find(|p| p.file_name().map(|n| n == "release" || n == "debug").unwrap_or(false))
            .expect("could not find profile dir in OUT_DIR");
        let dst = profile_dir.join("tun.json");
        if !dst.exists() {
            std::fs::copy(&src, &dst).expect("failed to copy tun.json");
        }
    }
    println!("cargo:rerun-if-changed={}", src.display());
}

fn main() {
    println!("cargo:rerun-if-changed=src/android_api9_compat.c");
    if std::env::var("TARGET").as_deref() != Ok("arm-linux-androideabi") {
        return;
    }

    cc::Build::new()
        .file("src/android_api9_compat.c")
        .flag("-march=armv6")
        .flag("-mfloat-abi=soft")
        .warnings(true)
        .cargo_metadata(false)
        .compile("android_api9_compat");
    let output = std::env::var("OUT_DIR").expect("Cargo did not provide OUT_DIR");
    println!("cargo:rustc-link-search=native={output}");
    println!("cargo:rustc-link-lib=static:+whole-archive=android_api9_compat");
}

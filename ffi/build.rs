fn main() {
    let compatibility = "../android-jni/src/android_api9_compat.c";
    println!("cargo:rerun-if-changed={compatibility}");
    if std::env::var("TARGET").as_deref() != Ok("arm-linux-androideabi") {
        return;
    }

    cc::Build::new()
        .file(compatibility)
        .flag("-march=armv6")
        .flag("-mfloat-abi=soft")
        .warnings(true)
        .cargo_metadata(false)
        .compile("android_api9_compat");
    let output = std::env::var("OUT_DIR").expect("Cargo did not provide OUT_DIR");
    println!("cargo:rustc-link-search=native={output}");
    println!("cargo:rustc-link-lib=static:+whole-archive=android_api9_compat");
}

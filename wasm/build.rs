fn main() {
    println!("cargo:rerun-if-env-changed=CRYPT_SERVER_PUBLIC_KEY_B64");

    let key = std::env::var("CRYPT_SERVER_PUBLIC_KEY_B64")
        .expect("CRYPT_SERVER_PUBLIC_KEY_B64 must be set when building mst5-client WASM");
    if key.trim().is_empty() {
        panic!("CRYPT_SERVER_PUBLIC_KEY_B64 must not be empty");
    }

    println!("cargo:rustc-env=CRYPT_SERVER_PUBLIC_KEY_B64={}", key.trim());
}

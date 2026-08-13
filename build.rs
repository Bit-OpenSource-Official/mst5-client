use std::env;

const KEY_ENV: &str = "CRYPT_SERVER_PUBLIC_KEY_B64";

fn main() {
    println!("cargo:rerun-if-env-changed={KEY_ENV}");

    let Ok(value) = env::var(KEY_ENV) else {
        return;
    };
    let value = value.trim();
    if value.is_empty() {
        // GitHub does not expose repository secrets to untrusted pull request
        // workflows, where the workflow-level variable consequently is empty.
        return;
    }
    if decoded_base64_len(value).ok() != Some(32) {
        panic!("{KEY_ENV} must be valid Base64 that decodes to exactly 32 bytes");
    }
}

fn decoded_base64_len(value: &str) -> Result<usize, ()> {
    let bytes: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return Err(());
    }
    let mut padded = bytes;
    while padded.len() % 4 != 0 {
        padded.push(b'=');
    }
    let chunks = padded.chunks_exact(4);
    let mut decoded = 0;
    let chunk_count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        let last = index + 1 == chunk_count;
        if !is_base64(chunk[0]) || !is_base64(chunk[1]) {
            return Err(());
        }
        let c_pad = chunk[2] == b'=';
        let d_pad = chunk[3] == b'=';
        if c_pad && !d_pad
            || (!c_pad && !is_base64(chunk[2]))
            || (!d_pad && !is_base64(chunk[3]))
            || (!last && (c_pad || d_pad))
        {
            return Err(());
        }
        decoded += 1 + usize::from(!c_pad) + usize::from(!d_pad);
    }
    Ok(decoded)
}

fn is_base64(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

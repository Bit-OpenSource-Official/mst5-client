//! Application-level E2E message version 4, legacy version 3, and password backup version 2.
//!
//! Private key material never needs to leave this module: applications can keep
//! an [`Identity`] behind an opaque native handle and expose only public keys,
//! fingerprints and encrypted envelopes to managed-language callers.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const ENVELOPE_VERSION: u8 = 4;
pub const LEGACY_ENVELOPE_VERSION: u8 = 3;
pub const BACKUP_VERSION: u8 = 2;
const IDENTITY_MAGIC: &[u8; 8] = b"MST5E2E3";
const CONTEXT: &[u8] = b"ove-messenger-e2e-v3";
const MESSAGE_V4_CONTEXT: &[u8] = b"ove-messenger-e2e-v4";
const MESSAGE_V4_HEADER: &[u8; 4] = b"M4TZ";
const MESSAGE_V4_ZSTD: u8 = 1;
const MESSAGE_COMPRESSION_THRESHOLD: usize = 1024;
const MESSAGE_COMPRESSION_SAVINGS_NUMERATOR: usize = 9;
const MESSAGE_COMPRESSION_SAVINGS_DENOMINATOR: usize = 10;
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: usize = 64;
const BACKUP_CONTEXT: &[u8] = b"ove-messenger-e2e-backup-v2";
const ARGON_MEMORY_KIB: u32 = 19 * 1024;
const ARGON_ITERATIONS: u32 = 2;
const ARGON_PARALLELISM: u32 = 1;

thread_local! {
    static E2E_ZSTD_COMPRESSOR: RefCell<Option<zstd::bulk::Compressor<'static>>> = const { RefCell::new(None) };
    static E2E_ZSTD_DECOMPRESSOR: RefCell<Option<zstd::bulk::Decompressor<'static>>> = const { RefCell::new(None) };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub version: u8,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// A group message carries one ordinary E2E envelope per recipient. The
/// ciphertext is never shared between recipients, so removing a member does
/// not grant access to messages sent after their removal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEnvelope {
    pub version: u8,
    pub recipients: HashMap<String, Envelope>,
}

/// Versioned, streamable encrypted-media container.  It is intentionally
/// independent of MST5 stream frame boundaries: media nodes store bytes and
/// may return them in differently-sized chunks.
pub const MEDIA_ENVELOPE_VERSION: u8 = 2;
pub const MEDIA_CHUNK_SIZE: usize = 64 * 1024;
pub const MEDIA_HEADER_SIZE: usize = 32;
const MEDIA_MAGIC: &[u8; 4] = b"M5EM";
const MEDIA_CONTEXT: &[u8] = b"ove-messenger-e2e-media-v2";
const MEDIA_TAG_SIZE: usize = 16;

/// Stateful V2 media encryptor.  A caller writes [`Self::header`] once and
/// then serializes each result of [`Self::seal_chunk`].
pub struct MediaEncryptor {
    cipher: XChaCha20Poly1305,
    aad_prefix: Vec<u8>,
    nonce_prefix: [u8; 16],
    plaintext_size: u64,
    written: u64,
    index: u64,
}

/// Stateful V2 media decryptor. Feed arbitrary byte slices into
/// [`Self::push`]; it returns zero or more recovered plaintext chunks.
pub struct MediaDecryptor {
    cipher: XChaCha20Poly1305,
    aad_prefix: Vec<u8>,
    nonce_prefix: [u8; 16],
    plaintext_size: u64,
    written: u64,
    index: u64,
    pending: Vec<u8>,
    header_read: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backup {
    pub version: u8,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub struct Identity {
    private: StaticSecret,
    public: PublicKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("public", &self.public.as_bytes())
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn generate() -> io::Result<Self> {
        let mut private = [0_u8; 32];
        getrandom::fill(&mut private)
            .map_err(|error| other(format!("OS randomness failed: {error}")))?;
        Ok(Self::from_private(private))
    }

    pub fn from_private(mut private: [u8; 32]) -> Self {
        let private_key = StaticSecret::from(private);
        private.zeroize();
        let public = PublicKey::from(&private_key);
        Self {
            private: private_key,
            public,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Returns a copy for platform key stores. Callers must persist it only
    /// through an OS/browser protected keystore and should zeroize the copy
    /// immediately after handing it off.
    pub fn private_key(&self) -> [u8; 32] {
        self.private.to_bytes()
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(self.public.as_bytes())
    }

    pub fn seal(
        &self,
        peer_public: [u8; 32],
        from_id: &str,
        to_id: &str,
        plaintext: &[u8],
    ) -> io::Result<Envelope> {
        let key = self.session_key_with_label(peer_public, from_id, to_id, b"message-v4-key")?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce)
            .map_err(|error| other(format!("OS randomness failed: {error}")))?;
        let aad = message_v4_aad(from_id, to_id);
        let encoded = Zeroizing::new(encode_message_v4(plaintext)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| invalid("invalid E2E key"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: encoded.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| invalid("E2E encryption failed"))?;
        Ok(Envelope {
            version: ENVELOPE_VERSION,
            nonce,
            ciphertext,
        })
    }

    pub fn open(
        &self,
        peer_public: [u8; 32],
        from_id: &str,
        to_id: &str,
        envelope: &Envelope,
    ) -> io::Result<Vec<u8>> {
        if !matches!(envelope.version, LEGACY_ENVELOPE_VERSION | ENVELOPE_VERSION)
            || envelope.ciphertext.len() < 16
        {
            return Err(invalid("unsupported or invalid E2E envelope"));
        }
        let (key, aad) = if envelope.version == LEGACY_ENVELOPE_VERSION {
            (
                self.session_key(peer_public, from_id, to_id)?,
                message_aad(from_id, to_id),
            )
        } else {
            (
                self.session_key_with_label(peer_public, from_id, to_id, b"message-v4-key")?,
                message_v4_aad(from_id, to_id),
            )
        };
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| invalid("invalid E2E key"))?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| invalid("E2E message authentication failed"))?;
        if envelope.version == LEGACY_ENVELOPE_VERSION {
            return Ok(plaintext);
        }
        decode_message_v4(&plaintext)
    }

    pub fn seal_group(
        &self,
        recipients: &[(String, [u8; 32])],
        from_id: &str,
        plaintext: &[u8],
    ) -> io::Result<GroupEnvelope> {
        if recipients.is_empty() || recipients.len() > 256 {
            return Err(invalid("group E2E recipients must be 1..256"));
        }
        let mut envelopes = HashMap::with_capacity(recipients.len());
        for (recipient_id, public_key) in recipients {
            if recipient_id.is_empty() || recipient_id.len() > 64 {
                return Err(invalid("invalid group E2E recipient"));
            }
            envelopes.insert(
                recipient_id.clone(),
                self.seal(*public_key, from_id, recipient_id, plaintext)?,
            );
        }
        Ok(GroupEnvelope { version: 5, recipients: envelopes })
    }

    pub fn open_group(
        &self,
        sender_public: [u8; 32],
        sender_id: &str,
        recipient_id: &str,
        envelope: &GroupEnvelope,
    ) -> io::Result<Vec<u8>> {
        if envelope.version != 5 {
            return Err(invalid("unsupported group E2E envelope"));
        }
        let selected = envelope
            .recipients
            .get(recipient_id)
            .ok_or_else(|| invalid("group E2E recipient is not present"))?;
        self.open(sender_public, sender_id, recipient_id, selected)
    }

    #[cfg(test)]
    fn seal_legacy_v3(
        &self,
        peer_public: [u8; 32],
        from_id: &str,
        to_id: &str,
        plaintext: &[u8],
    ) -> io::Result<Envelope> {
        let key = self.session_key(peer_public, from_id, to_id)?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce)
            .map_err(|error| other(format!("OS randomness failed: {error}")))?;
        let aad = message_aad(from_id, to_id);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| invalid("invalid E2E key"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| invalid("E2E encryption failed"))?;
        Ok(Envelope {
            version: LEGACY_ENVELOPE_VERSION,
            nonce,
            ciphertext,
        })
    }

    /// Starts V2 attachment encryption. `file_id` binds a ciphertext to its
    /// media-node object and prevents substitution between attachments.
    pub fn media_encryptor(
        &self,
        peer_public: [u8; 32],
        from_id: &str,
        to_id: &str,
        file_id: &str,
        plaintext_size: u64,
    ) -> io::Result<MediaEncryptor> {
        let key =
            self.session_key_with_label(peer_public, from_id, to_id, b"media-stream-v2-key")?;
        MediaEncryptor::with_key(
            key.as_slice(),
            media_aad(from_id, to_id, file_id),
            plaintext_size,
        )
    }

    /// Starts V2 attachment decryption. The first supplied bytes must contain
    /// the V2 header; V1 deliberately has no compatibility path.
    pub fn media_decryptor(
        &self,
        peer_public: [u8; 32],
        from_id: &str,
        to_id: &str,
        file_id: &str,
    ) -> io::Result<MediaDecryptor> {
        let key =
            self.session_key_with_label(peer_public, from_id, to_id, b"media-stream-v2-key")?;
        MediaDecryptor::with_key(key.as_slice(), media_aad(from_id, to_id, file_id))
    }

    /// Derives the media stream key so a caller can wrap it for multiple
    /// group recipients while encrypting the bytes only once.
    pub fn media_key(&self, peer_public: [u8; 32], from_id: &str, to_id: &str) -> io::Result<[u8; 32]> {
        let key = self.session_key_with_label(peer_public, from_id, to_id, b"media-stream-v2-key")?;
        Ok(*key)
    }

    pub fn backup(&self, password: &str) -> io::Result<Backup> {
        if password.len() < 3 {
            return Err(invalid(
                "backup password must contain at least 3 characters",
            ));
        }
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut salt)
            .map_err(|error| other(format!("OS randomness failed: {error}")))?;
        getrandom::fill(&mut nonce)
            .map_err(|error| other(format!("OS randomness failed: {error}")))?;
        let key = backup_key(password, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| invalid("invalid backup key"))?;
        let private = Zeroizing::new(self.private.to_bytes());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: private.as_slice(),
                    aad: BACKUP_CONTEXT,
                },
            )
            .map_err(|_| invalid("E2E backup encryption failed"))?;
        Ok(Backup {
            version: BACKUP_VERSION,
            salt,
            nonce,
            ciphertext,
        })
    }

    pub fn restore(backup: &Backup, password: &str) -> io::Result<Self> {
        if backup.version != BACKUP_VERSION || backup.ciphertext.len() != 48 {
            return Err(invalid("unsupported or invalid E2E backup"));
        }
        let key = backup_key(password, &backup.salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| invalid("invalid backup key"))?;
        let private = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&backup.nonce),
                    Payload {
                        msg: &backup.ciphertext,
                        aad: BACKUP_CONTEXT,
                    },
                )
                .map_err(|_| invalid("wrong password or damaged E2E backup"))?,
        );
        let bytes: [u8; 32] = private
            .as_slice()
            .try_into()
            .map_err(|_| invalid("invalid E2E private key"))?;
        Ok(Self::from_private(bytes))
    }

    fn session_key(
        &self,
        peer_public: [u8; 32],
        left: &str,
        right: &str,
    ) -> io::Result<Zeroizing<[u8; 32]>> {
        self.session_key_with_label(peer_public, left, right, b"message-key")
    }

    fn session_key_with_label(
        &self,
        peer_public: [u8; 32],
        left: &str,
        right: &str,
        label: &[u8],
    ) -> io::Result<Zeroizing<[u8; 32]>> {
        let shared = self.private.diffie_hellman(&PublicKey::from(peer_public));
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(invalid("invalid X25519 peer key"));
        }
        let (first, second) = ordered_ids(left, right);
        let mut salt_hash = Sha256::new();
        salt_hash.update(CONTEXT);
        salt_hash.update([0]);
        salt_hash.update(first.as_bytes());
        salt_hash.update([0]);
        salt_hash.update(second.as_bytes());
        let salt = salt_hash.finalize();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(label, key.as_mut())
            .map_err(|_| invalid("E2E HKDF failed"))?;
        Ok(key)
    }
}

fn media_aad(from: &str, to: &str, file_id: &str) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(MEDIA_CONTEXT.len() + from.len() + to.len() + file_id.len() + 3);
    aad.extend_from_slice(MEDIA_CONTEXT);
    aad.push(0);
    aad.extend_from_slice(from.as_bytes());
    aad.push(0);
    aad.extend_from_slice(to.as_bytes());
    aad.push(0);
    aad.extend_from_slice(file_id.as_bytes());
    aad
}

/// Returns the exact number of opaque bytes stored on the media node for a
/// V2 encrypted object. This is needed before obtaining its upload ticket.
pub fn encrypted_media_size(plaintext_size: u64) -> io::Result<u64> {
    let chunks = plaintext_size.div_ceil(MEDIA_CHUNK_SIZE as u64);
    let overhead = chunks
        .checked_mul((4 + MEDIA_TAG_SIZE) as u64)
        .and_then(|value| value.checked_add(MEDIA_HEADER_SIZE as u64))
        .ok_or_else(|| invalid("E2E media size overflow"))?;
    plaintext_size
        .checked_add(overhead)
        .ok_or_else(|| invalid("E2E media size overflow"))
}

impl MediaEncryptor {
    fn new(key: &[u8], aad_prefix: Vec<u8>, plaintext_size: u64) -> io::Result<Self> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| invalid("invalid E2E media key"))?;
        let mut nonce_prefix = [0u8; 16];
        getrandom::fill(&mut nonce_prefix)
            .map_err(|error| other(format!("OS randomness failed: {error}")))?;
        Ok(Self {
            cipher,
            aad_prefix,
            nonce_prefix,
            plaintext_size,
            written: 0,
            index: 0,
        })
    }

    pub fn with_key(key: &[u8], aad_prefix: Vec<u8>, plaintext_size: u64) -> io::Result<Self> {
        Self::new(key, aad_prefix, plaintext_size)
    }

    pub fn header(&self) -> [u8; MEDIA_HEADER_SIZE] {
        let mut header = [0u8; MEDIA_HEADER_SIZE];
        header[..4].copy_from_slice(MEDIA_MAGIC);
        header[4] = MEDIA_ENVELOPE_VERSION;
        header[5] = 16; // 2^16 = 64 KiB chunks
        header[8..16].copy_from_slice(&self.plaintext_size.to_be_bytes());
        header[16..].copy_from_slice(&self.nonce_prefix);
        header
    }

    pub fn seal_chunk(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        if plaintext.is_empty() || plaintext.len() > MEDIA_CHUNK_SIZE {
            return Err(invalid("invalid E2E media chunk size"));
        }
        let next = self
            .written
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| invalid("E2E media size overflow"))?;
        if next > self.plaintext_size
            || (next != self.plaintext_size && plaintext.len() != MEDIA_CHUNK_SIZE)
        {
            return Err(invalid("E2E media chunks do not match declared size"));
        }
        let nonce = media_nonce(&self.nonce_prefix, self.index);
        let aad = media_chunk_aad(
            &self.aad_prefix,
            &self.header(),
            self.index,
            plaintext.len() as u32,
        );
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| invalid("E2E media encryption failed"))?;
        let mut out = Vec::with_capacity(4 + ciphertext.len());
        out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&ciphertext);
        self.written = next;
        self.index = self
            .index
            .checked_add(1)
            .ok_or_else(|| invalid("E2E media chunk index overflow"))?;
        Ok(out)
    }

    pub fn finish(&self) -> io::Result<()> {
        if self.written == self.plaintext_size {
            Ok(())
        } else {
            Err(invalid("E2E media source is shorter than declared size"))
        }
    }
}

impl MediaDecryptor {
    fn new(key: &[u8], aad_prefix: Vec<u8>) -> io::Result<Self> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| invalid("invalid E2E media key"))?;
        Ok(Self {
            cipher,
            aad_prefix,
            nonce_prefix: [0; 16],
            plaintext_size: 0,
            written: 0,
            index: 0,
            pending: Vec::with_capacity(MEDIA_CHUNK_SIZE + 4 + MEDIA_TAG_SIZE),
            header_read: false,
        })
    }

    pub fn with_key(key: &[u8], aad_prefix: Vec<u8>) -> io::Result<Self> {
        Self::new(key, aad_prefix)
    }

    pub fn push(&mut self, bytes: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        self.pending.extend_from_slice(bytes);
        if !self.header_read {
            if self.pending.len() < MEDIA_HEADER_SIZE {
                return Ok(Vec::new());
            }
            let header: [u8; MEDIA_HEADER_SIZE] =
                self.pending[..MEDIA_HEADER_SIZE].try_into().unwrap();
            if &header[..4] != MEDIA_MAGIC
                || header[4] != MEDIA_ENVELOPE_VERSION
                || header[5] != 16
                || header[6] != 0
                || header[7] != 0
            {
                return Err(invalid(
                    "unsupported E2E media version; update the application",
                ));
            }
            self.plaintext_size = u64::from_be_bytes(header[8..16].try_into().unwrap());
            self.nonce_prefix.copy_from_slice(&header[16..]);
            self.pending.drain(..MEDIA_HEADER_SIZE);
            self.header_read = true;
        }
        let mut output = Vec::new();
        while self.written < self.plaintext_size {
            if self.pending.len() < 4 {
                break;
            }
            let ciphertext_len = u32::from_be_bytes(self.pending[..4].try_into().unwrap()) as usize;
            let remaining = (self.plaintext_size - self.written) as usize;
            let expected_plain = remaining.min(MEDIA_CHUNK_SIZE);
            if ciphertext_len != expected_plain + MEDIA_TAG_SIZE
                || self.pending.len() < 4 + ciphertext_len
            {
                if ciphertext_len != expected_plain + MEDIA_TAG_SIZE {
                    return Err(invalid("invalid E2E media chunk length"));
                }
                break;
            }
            let header = self.header();
            let nonce = media_nonce(&self.nonce_prefix, self.index);
            let aad = media_chunk_aad(&self.aad_prefix, &header, self.index, expected_plain as u32);
            let plaintext = self
                .cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &self.pending[4..4 + ciphertext_len],
                        aad: &aad,
                    },
                )
                .map_err(|_| invalid("E2E media authentication failed"))?;
            self.pending.drain(..4 + ciphertext_len);
            self.written += plaintext.len() as u64;
            self.index = self
                .index
                .checked_add(1)
                .ok_or_else(|| invalid("E2E media chunk index overflow"))?;
            output.push(plaintext);
        }
        Ok(output)
    }

    pub fn finish(&self) -> io::Result<u64> {
        if !self.header_read || self.written != self.plaintext_size || !self.pending.is_empty() {
            return Err(invalid("E2E media is truncated or has trailing bytes"));
        }
        Ok(self.written)
    }

    fn header(&self) -> [u8; MEDIA_HEADER_SIZE] {
        let mut header = [0u8; MEDIA_HEADER_SIZE];
        header[..4].copy_from_slice(MEDIA_MAGIC);
        header[4] = MEDIA_ENVELOPE_VERSION;
        header[5] = 16;
        header[8..16].copy_from_slice(&self.plaintext_size.to_be_bytes());
        header[16..].copy_from_slice(&self.nonce_prefix);
        header
    }
}

fn media_nonce(prefix: &[u8; 16], index: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn media_chunk_aad(
    prefix: &[u8],
    header: &[u8; MEDIA_HEADER_SIZE],
    index: u64,
    plaintext_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + header.len() + 12);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad
}

fn encode_message_v4(plaintext: &[u8]) -> io::Result<Vec<u8>> {
    if plaintext.len() > MAX_MESSAGE_BYTES {
        return Err(invalid("E2E message is too large"));
    }
    let mut flags = 0_u8;
    let encoded = if plaintext.len() >= MESSAGE_COMPRESSION_THRESHOLD {
        let compressed = e2e_zstd_compress(plaintext)?;
        if compressed
            .len()
            .saturating_mul(MESSAGE_COMPRESSION_SAVINGS_DENOMINATOR)
            <= plaintext
                .len()
                .saturating_mul(MESSAGE_COMPRESSION_SAVINGS_NUMERATOR)
            && plaintext.len() <= compressed.len().saturating_mul(MAX_COMPRESSION_RATIO)
        {
            flags |= MESSAGE_V4_ZSTD;
            compressed
        } else {
            plaintext.to_vec()
        }
    } else {
        plaintext.to_vec()
    };
    let mut output = Vec::with_capacity(MESSAGE_V4_HEADER.len() + 1 + 4 + encoded.len());
    output.extend_from_slice(MESSAGE_V4_HEADER);
    output.push(flags);
    output.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    output.extend_from_slice(&encoded);
    Ok(output)
}

fn decode_message_v4(plaintext: &[u8]) -> io::Result<Vec<u8>> {
    const HEADER_LEN: usize = 9;
    if plaintext.len() < HEADER_LEN || &plaintext[..4] != MESSAGE_V4_HEADER {
        return Err(invalid("invalid E2E v4 message payload"));
    }
    let flags = plaintext[4];
    if flags & !MESSAGE_V4_ZSTD != 0 {
        return Err(invalid("unsupported E2E v4 message encoding"));
    }
    let original_len =
        u32::from_be_bytes(plaintext[5..9].try_into().expect("v4 header length")) as usize;
    if original_len > MAX_MESSAGE_BYTES {
        return Err(invalid("E2E v4 message is too large"));
    }
    let body = &plaintext[HEADER_LEN..];
    let output = if flags & MESSAGE_V4_ZSTD != 0 {
        if body.is_empty() {
            return Err(invalid("empty E2E v4 zstd payload"));
        }
        let output = e2e_zstd_decompress(body, original_len)?;
        if output.len() > body.len().saturating_mul(MAX_COMPRESSION_RATIO) {
            return Err(invalid("E2E v4 compression ratio exceeds limit"));
        }
        output
    } else {
        body.to_vec()
    };
    if output.len() != original_len {
        return Err(invalid("invalid E2E v4 message length"));
    }
    Ok(output)
}

fn e2e_zstd_compress(input: &[u8]) -> io::Result<Vec<u8>> {
    E2E_ZSTD_COMPRESSOR.with(|state| {
        let mut state = state.borrow_mut();
        if state.is_none() {
            *state = Some(
                zstd::bulk::Compressor::new(3)
                    .map_err(|_| other("E2E zstd initialization failed"))?,
            );
        }
        state
            .as_mut()
            .unwrap()
            .compress(input)
            .map_err(|_| other("E2E zstd compression failed"))
    })
}

fn e2e_zstd_decompress(input: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    E2E_ZSTD_DECOMPRESSOR.with(|state| {
        let mut state = state.borrow_mut();
        if state.is_none() {
            *state = Some(
                zstd::bulk::Decompressor::new()
                    .map_err(|_| invalid("E2E zstd initialization failed"))?,
            );
        }
        state
            .as_mut()
            .unwrap()
            .decompress(input, limit)
            .map_err(|_| invalid("invalid or oversized E2E v4 zstd payload"))
    })
}

pub struct IdentityStore {
    path: PathBuf,
}

impl IdentityStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> io::Result<Option<Identity>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let file = File::open(&self.path)?;
        let mut encoded = Zeroizing::new(Vec::new());
        file.take(64).read_to_end(&mut encoded)?;
        if encoded.len() != 40 || &encoded[..8] != IDENTITY_MAGIC {
            return Err(invalid("invalid E2E identity file"));
        }
        let private: [u8; 32] = encoded[8..]
            .try_into()
            .map_err(|_| invalid("invalid E2E identity file"))?;
        Ok(Some(Identity::from_private(private)))
    }

    pub fn load_or_create(&self) -> io::Result<Identity> {
        if let Some(identity) = self.load()? {
            return Ok(identity);
        }
        let identity = Identity::generate()?;
        self.save(&identity)?;
        Ok(identity)
    }

    pub fn save(&self, identity: &Identity) -> io::Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("identity path has no parent"))?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(
            ".{}.tmp",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("identity")
        ));
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(IDENTITY_MAGIC)?;
        let private = Zeroizing::new(identity.private.to_bytes());
        file.write_all(private.as_slice())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &self.path)?;
        sync_parent(parent)?;
        Ok(())
    }

    pub fn remove(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => sync_parent(self.path.parent().unwrap_or(Path::new("."))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(public_key);
    hash[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn backup_key(password: &str, salt: &[u8; 16]) -> io::Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(
        ARGON_MEMORY_KIB,
        ARGON_ITERATIONS,
        ARGON_PARALLELISM,
        Some(32),
    )
    .map_err(|error| invalid(format!("invalid Argon2 parameters: {error}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|error| other(format!("Argon2 failed: {error}")))?;
    Ok(key)
}

fn ordered_ids<'a>(left: &'a str, right: &'a str) -> (&'a str, &'a str) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn message_aad(from: &str, to: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CONTEXT.len() + from.len() + to.len() + 2);
    aad.extend_from_slice(CONTEXT);
    aad.push(0);
    aad.extend_from_slice(from.as_bytes());
    aad.push(0);
    aad.extend_from_slice(to.as_bytes());
    aad
}

fn message_v4_aad(from: &str, to: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MESSAGE_V4_CONTEXT.len() + from.len() + to.len() + 2);
    aad.extend_from_slice(MESSAGE_V4_CONTEXT);
    aad.push(0);
    aad.extend_from_slice(from.as_bytes());
    aad.push(0);
    aad.extend_from_slice(to.as_bytes());
    aad
}

fn sync_parent(parent: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn other(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_round_trip_and_tamper_rejection() {
        let alice = Identity::from_private([1; 32]);
        let bob = Identity::from_private([2; 32]);
        let envelope = alice.seal(bob.public_key(), "1", "2", b"secret").unwrap();
        assert_eq!(
            bob.open(alice.public_key(), "1", "2", &envelope).unwrap(),
            b"secret"
        );
        let mut tampered = envelope.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(bob.open(alice.public_key(), "1", "2", &tampered).is_err());
        assert!(bob.open(alice.public_key(), "2", "1", &envelope).is_err());
    }

    #[test]
    fn message_v4_compresses_before_encryption_and_reads_v3() {
        let alice = Identity::from_private([11; 32]);
        let bob = Identity::from_private([12; 32]);
        let mut state = 0x1234_5678_u32;
        let block: Vec<u8> = (0..512)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        let text = block.repeat(16);
        let v4 = alice.seal(bob.public_key(), "11", "12", &text).unwrap();
        assert_eq!(v4.version, ENVELOPE_VERSION);
        assert!(v4.ciphertext.len() < text.len() / 2);
        assert_eq!(bob.open(alice.public_key(), "11", "12", &v4).unwrap(), text);

        let v3 = alice
            .seal_legacy_v3(bob.public_key(), "11", "12", b"historic message")
            .unwrap();
        assert_eq!(
            bob.open(alice.public_key(), "11", "12", &v3).unwrap(),
            b"historic message"
        );
    }

    #[test]
    fn message_v4_rejects_invalid_compression_payload() {
        let alice = Identity::from_private([13; 32]);
        let bob = Identity::from_private([14; 32]);
        let mut envelope = alice.seal(bob.public_key(), "13", "14", b"text").unwrap();
        envelope.ciphertext[0] ^= 1;
        assert!(bob.open(alice.public_key(), "13", "14", &envelope).is_err());
    }

    #[test]
    fn group_envelope_seals_and_opens_per_recipient() {
        let alice = Identity::from_private([21; 32]);
        let bob = Identity::from_private([22; 32]);
        let carol = Identity::from_private([23; 32]);
        let recipients = vec![
            ("22".to_string(), bob.public_key()),
            ("23".to_string(), carol.public_key()),
        ];
        let group = alice.seal_group(&recipients, "21", b"group secret").unwrap();
        assert_eq!(group.version, 5);
        assert_eq!(group.recipients.len(), 2);
        assert_eq!(
            bob.open_group(alice.public_key(), "21", "22", &group).unwrap(),
            b"group secret"
        );
        assert_eq!(
            carol.open_group(alice.public_key(), "21", "23", &group).unwrap(),
            b"group secret"
        );
        assert!(bob.open_group(alice.public_key(), "21", "24", &group).is_err());
    }

    #[test]
    fn media_key_can_be_reused_for_group_wrapping() {
        let alice = Identity::from_private([31; 32]);
        let bob = Identity::from_private([32; 32]);
        let key = alice.media_key(bob.public_key(), "31", "32").unwrap();
        let bytes = b"group media";
        let mut enc = MediaEncryptor::with_key(&key, media_aad("31", "32", "f"), bytes.len() as u64).unwrap();
        let mut wire = enc.header().to_vec();
        wire.extend(enc.seal_chunk(bytes).unwrap());
        enc.finish().unwrap();
        let mut dec = MediaDecryptor::with_key(&key, media_aad("31", "32", "f")).unwrap();
        let mut opened = Vec::new();
        for chunk in wire.chunks(7) { opened.extend(dec.push(chunk).unwrap().into_iter().flatten()); }
        dec.finish().unwrap();
        assert_eq!(opened, bytes);
    }

    #[test]
    fn media_round_trip_binds_file_id_and_is_distinct_from_text() {
        let alice = Identity::from_private([3; 32]);
        let bob = Identity::from_private([4; 32]);
        let plaintext = vec![0x5a; MEDIA_CHUNK_SIZE + 17];
        let mut encryptor = alice
            .media_encryptor(bob.public_key(), "3", "4", "file-a", plaintext.len() as u64)
            .unwrap();
        let mut encoded = encryptor.header().to_vec();
        encoded.extend(
            encryptor
                .seal_chunk(&plaintext[..MEDIA_CHUNK_SIZE])
                .unwrap(),
        );
        encoded.extend(
            encryptor
                .seal_chunk(&plaintext[MEDIA_CHUNK_SIZE..])
                .unwrap(),
        );
        encryptor.finish().unwrap();
        assert_eq!(
            encoded.len() as u64,
            encrypted_media_size(plaintext.len() as u64).unwrap()
        );
        let mut decryptor = bob
            .media_decryptor(alice.public_key(), "3", "4", "file-a")
            .unwrap();
        let mut opened = Vec::new();
        for piece in encoded.chunks(127) {
            for chunk in decryptor.push(piece).unwrap() {
                opened.extend(chunk);
            }
        }
        decryptor.finish().unwrap();
        assert_eq!(opened, plaintext);
        let mut wrong_file = bob
            .media_decryptor(alice.public_key(), "3", "4", "file-b")
            .unwrap();
        assert!(wrong_file.push(&encoded).is_err());
        let text = alice
            .seal(bob.public_key(), "3", "4", b"photo bytes")
            .unwrap();
        assert_ne!(&encoded[MEDIA_HEADER_SIZE..], text.ciphertext.as_slice());
    }

    #[test]
    fn backup_round_trip_and_wrong_password() {
        let identity = Identity::from_private([7; 32]);
        let backup = identity.backup("correct horse").unwrap();
        let restored = Identity::restore(&backup, "correct horse").unwrap();
        assert_eq!(restored.public_key(), identity.public_key());
        assert!(Identity::restore(&backup, "wrong password").is_err());
    }

    #[test]
    fn identity_store_round_trip() {
        let path = std::env::temp_dir().join(format!("mst5-e2e-{}-{}.key", std::process::id(), 17));
        let store = IdentityStore::new(&path);
        let identity = Identity::from_private([9; 32]);
        store.save(&identity).unwrap();
        assert_eq!(
            store.load().unwrap().unwrap().public_key(),
            identity.public_key()
        );
        store.remove().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}

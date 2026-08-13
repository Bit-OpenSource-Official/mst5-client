//! Application-level E2E version 3 and password backup version 2.
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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const ENVELOPE_VERSION: u8 = 3;
pub const BACKUP_VERSION: u8 = 2;
const IDENTITY_MAGIC: &[u8; 8] = b"MST5E2E3";
const CONTEXT: &[u8] = b"ove-messenger-e2e-v3";
const BACKUP_CONTEXT: &[u8] = b"ove-messenger-e2e-backup-v2";
const ARGON_MEMORY_KIB: u32 = 19 * 1024;
const ARGON_ITERATIONS: u32 = 2;
const ARGON_PARALLELISM: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub version: u8,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
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
        getrandom::fill(&mut private).map_err(|error| other(format!("OS randomness failed: {error}")))?;
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

    pub fn fingerprint(&self) -> String {
        fingerprint(self.public.as_bytes())
    }

    pub fn seal(&self, peer_public: [u8; 32], from_id: &str, to_id: &str, plaintext: &[u8]) -> io::Result<Envelope> {
        let key = self.session_key(peer_public, from_id, to_id)?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|error| other(format!("OS randomness failed: {error}")))?;
        let aad = message_aad(from_id, to_id);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| invalid("invalid E2E key"))?;
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| invalid("E2E encryption failed"))?;
        Ok(Envelope {
            version: ENVELOPE_VERSION,
            nonce,
            ciphertext,
        })
    }

    pub fn open(&self, peer_public: [u8; 32], from_id: &str, to_id: &str, envelope: &Envelope) -> io::Result<Vec<u8>> {
        if envelope.version != ENVELOPE_VERSION || envelope.ciphertext.len() < 16 {
            return Err(invalid("unsupported or invalid E2E envelope"));
        }
        let key = self.session_key(peer_public, from_id, to_id)?;
        let aad = message_aad(from_id, to_id);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| invalid("invalid E2E key"))?;
        cipher
            .decrypt(XNonce::from_slice(&envelope.nonce), Payload { msg: &envelope.ciphertext, aad: &aad })
            .map_err(|_| invalid("E2E message authentication failed"))
    }

    pub fn backup(&self, password: &str) -> io::Result<Backup> {
        if password.len() < 3 {
            return Err(invalid("backup password must contain at least 3 characters"));
        }
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut salt).map_err(|error| other(format!("OS randomness failed: {error}")))?;
        getrandom::fill(&mut nonce).map_err(|error| other(format!("OS randomness failed: {error}")))?;
        let key = backup_key(password, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| invalid("invalid backup key"))?;
        let private = Zeroizing::new(self.private.to_bytes());
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: private.as_slice(), aad: BACKUP_CONTEXT })
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
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| invalid("invalid backup key"))?;
        let private = Zeroizing::new(
            cipher
                .decrypt(XNonce::from_slice(&backup.nonce), Payload { msg: &backup.ciphertext, aad: BACKUP_CONTEXT })
                .map_err(|_| invalid("wrong password or damaged E2E backup"))?,
        );
        let bytes: [u8; 32] = private
            .as_slice()
            .try_into()
            .map_err(|_| invalid("invalid E2E private key"))?;
        Ok(Self::from_private(bytes))
    }

    fn session_key(&self, peer_public: [u8; 32], left: &str, right: &str) -> io::Result<Zeroizing<[u8; 32]>> {
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
        hkdf.expand(b"message-key", key.as_mut()).map_err(|_| invalid("E2E HKDF failed"))?;
        Ok(key)
    }
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
        let private: [u8; 32] = encoded[8..].try_into().map_err(|_| invalid("invalid E2E identity file"))?;
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
        let parent = self.path.parent().ok_or_else(|| invalid("identity path has no parent"))?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".{}.tmp", self.path.file_name().and_then(|name| name.to_str()).unwrap_or("identity")));
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
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_PARALLELISM, Some(32))
        .map_err(|error| invalid(format!("invalid Argon2 parameters: {error}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|error| other(format!("Argon2 failed: {error}")))?;
    Ok(key)
}

fn ordered_ids<'a>(left: &'a str, right: &'a str) -> (&'a str, &'a str) {
    if left <= right { (left, right) } else { (right, left) }
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
        assert_eq!(bob.open(alice.public_key(), "1", "2", &envelope).unwrap(), b"secret");
        let mut tampered = envelope.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(bob.open(alice.public_key(), "1", "2", &tampered).is_err());
        assert!(bob.open(alice.public_key(), "2", "1", &envelope).is_err());
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
        assert_eq!(store.load().unwrap().unwrap().public_key(), identity.public_key());
        store.remove().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}

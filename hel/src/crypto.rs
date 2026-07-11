//! Inline encrypted blobs for hel records.
//!
//! A TOTP seed (mode `T`) or an `!`-text secret is stored inside a record's
//! comment as an armored, authenticated blob. The encryption key is derived from
//! the entry's UNFOLDED iterated-SHA-1 state (`Password::kek_material` — full
//! 160 bits, hex; never the folded 64-bit rendering) via argon2id — so a blob
//! decrypts from master + record alone, inherits the `^`-hierarchy, and keeps a
//! strong master's entropy above the word-encoding's 64-bit fold. The KEK
//! depends only on (name, seq, chain): mode/prefix/length edits never orphan
//! a blob. See the crate design notes.
//!
//! Blob layout (before base64url armor):
//! ```text
//!   magic "hT" (2) | version (1) | kdf_id (1) | salt (16) | nonce (24) | ct+tag
//! ```
//! AAD = magic | version | type_tag('#'/'!') | name_utf8 | 0x00 | seq_le32,
//! binding a blob to its exact entry, sequence, and token type.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64URL_NOPAD;
use thiserror::Error;

const MAGIC: [u8; 2] = *b"hT";
// v2 = KEK is the unfolded 160-bit derivation (v1 keyed off the folded encode();
// no real v1 blobs exist — clean break, v1 rejected loudly as Version(1)).
const VERSION: u8 = 2;
const KDF_DEFAULT: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 2 + 1 + 1 + SALT_LEN + NONCE_LEN; // 44
const MIN_BLOB_LEN: usize = HEADER_LEN + TAG_LEN; // empty-plaintext floor

#[derive(Debug, Error, PartialEq)]
pub enum CryptoError {
    #[error("random source unavailable")]
    Random,
    #[error("argon2 key derivation failed")]
    Kdf,
    #[error("bad token armor")]
    Armor,
    #[error("not a hel blob")]
    NotABlob,
    #[error("unsupported blob version {0}")]
    Version(u8),
    #[error("unknown kdf id {0}")]
    KdfId(u8),
    #[error("wrong key or corrupt/tampered blob")]
    Decrypt,
    #[error("decrypted data is not valid UTF-8")]
    Utf8,
}

/// Which inline token a blob belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// `#` — an encrypted TOTP secret / otpauth URI.
    Totp,
    /// `!` — encrypted free text.
    Text,
}

impl TokenType {
    pub fn ch(&self) -> char {
        match self {
            TokenType::Totp => '#',
            TokenType::Text => '!',
        }
    }
    fn tag(&self) -> u8 {
        match self {
            TokenType::Totp => b'#',
            TokenType::Text => b'!',
        }
    }
}

fn kdf_params(id: u8) -> Result<Params, CryptoError> {
    // id 1: OWASP argon2id baseline (19 MiB, t=2, p=1) — the v1 default.
    // id 2: 64 MiB, t=16, p=1 — ~0.5 s native on an M-series core, ~1 s as wasm
    //   on a modern iPhone; sized so brute-forcing a folded 64-bit chain value
    //   stays cost-prohibitive even for a well-funded attacker. New ids may
    //   raise cost without breaking old blobs (the id travels in the header).
    let (m_kib, t, p) = match id {
        1 => (19_456u32, 2u32, 1u32),
        2 => (65_536u32, 16u32, 1u32),
        other => return Err(CryptoError::KdfId(other)),
    };
    Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|_| CryptoError::Kdf)
}

fn derive_key(passphrase: &str, salt: &[u8], kdf_id: u8) -> Result<[u8; KEY_LEN], CryptoError> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, kdf_params(kdf_id)?);
    let mut key = [0u8; KEY_LEN];
    argon.hash_password_into(passphrase.as_bytes(), salt, &mut key).map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

fn aad(ttype: TokenType, name: &str, seq: u32) -> Vec<u8> {
    let mut a = Vec::with_capacity(MAGIC.len() + 2 + name.len() + 1 + 4);
    a.extend_from_slice(&MAGIC);
    a.push(VERSION);
    a.push(ttype.tag());
    a.extend_from_slice(name.as_bytes());
    a.push(0);
    a.extend_from_slice(&seq.to_le_bytes());
    a
}

fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(buf).map_err(|_| CryptoError::Random)
}

/// Encrypt `plaintext` for entry (`name`, `seq`) using `passphrase` (the entry's
/// hel-derived password), returning the base64url armor (WITHOUT the `#`/`!`
/// prefix character — the caller adds that).
pub fn seal(ttype: TokenType, plaintext: &str, passphrase: &str, name: &str, seq: u32) -> Result<String, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;
    let key = derive_key(passphrase, &salt, KDF_DEFAULT)?;
    let cipher = XChaCha20Poly1305::new(&key.into());
    let aad = aad(ttype, name, seq);
    let ct = cipher
        .encrypt(&nonce.into(), Payload { msg: plaintext.as_bytes(), aad: &aad })
        .map_err(|_| CryptoError::Decrypt)?;
    let mut blob = Vec::with_capacity(HEADER_LEN + ct.len());
    blob.extend_from_slice(&MAGIC);
    blob.push(VERSION);
    blob.push(KDF_DEFAULT);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(BASE64URL_NOPAD.encode(&blob))
}

/// Decrypt an armored blob (WITHOUT the `#`/`!` prefix) for entry (`name`, `seq`).
pub fn open(ttype: TokenType, armor: &str, passphrase: &str, name: &str, seq: u32) -> Result<String, CryptoError> {
    let blob = BASE64URL_NOPAD.decode(armor.as_bytes()).map_err(|_| CryptoError::Armor)?;
    if blob.len() < MIN_BLOB_LEN {
        return Err(CryptoError::NotABlob);
    }
    if blob[0..2] != MAGIC {
        return Err(CryptoError::NotABlob);
    }
    if blob[2] != VERSION {
        return Err(CryptoError::Version(blob[2]));
    }
    let kdf_id = blob[3];
    let salt = &blob[4..4 + SALT_LEN];
    let nonce = &blob[4 + SALT_LEN..HEADER_LEN];
    let ct = &blob[HEADER_LEN..];
    let key = derive_key(passphrase, salt, kdf_id)?;
    let cipher = XChaCha20Poly1305::new(&key.into());
    let aad = aad(ttype, name, seq);
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::NotABlob)?;
    let pt = cipher
        .decrypt(&nonce, Payload { msg: ct, aad: &aad })
        .map_err(|_| CryptoError::Decrypt)?;
    String::from_utf8(pt).map_err(|_| CryptoError::Utf8)
}

/// True if `armor` decodes to something that looks like a hel blob (right magic
/// + minimum length). Lets `reveal` skip ordinary `#hashtag` comment words
/// without attempting decryption.
pub fn looks_like_blob(armor: &str) -> bool {
    match BASE64URL_NOPAD.decode(armor.as_bytes()) {
        Ok(b) => b.len() >= MIN_BLOB_LEN && b[0..2] == MAGIC,
        Err(_) => false,
    }
}

/// Redact any plaintext add-by-value markers (`#"..."` / `!"..."`, incl. an
/// unterminated `#"seed`) so a line that FAILED to parse never lands in history
/// with a secret in it.
pub fn sanitize_for_history(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if (c == '#' || c == '!') && chars.peek() == Some(&'"') {
            out.push(c);
            out.push_str("<redacted>");
            chars.next(); // consume opening quote
                          // skip to (and including) the closing quote, or end-of-line if unterminated
            while let Some(nc) = chars.next() {
                if nc == '"' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let pass = "x ross beau week held yoga anti";
        let a = seal(TokenType::Totp, "otpauth://totp/x?secret=ABC", pass, "binance81t", 99).unwrap();
        assert!(looks_like_blob(&a));
        let p = open(TokenType::Totp, &a, pass, "binance81t", 99).unwrap();
        assert_eq!(p, "otpauth://totp/x?secret=ABC");
    }

    #[test]
    fn wrong_key_fails() {
        let a = seal(TokenType::Text, "recovery-code-42", "right pass", "e", 99).unwrap();
        assert_eq!(open(TokenType::Text, &a, "wrong pass", "e", 99), Err(CryptoError::Decrypt));
    }

    #[test]
    fn aad_binding_rejects_relocation_and_type_confusion() {
        let pass = "same pass";
        let a = seal(TokenType::Text, "sekret", pass, "entryA", 99).unwrap();
        // moved to another entry name -> AAD mismatch
        assert_eq!(open(TokenType::Text, &a, pass, "entryB", 99), Err(CryptoError::Decrypt));
        // different seq -> AAD mismatch
        assert_eq!(open(TokenType::Text, &a, pass, "entryA", 50), Err(CryptoError::Decrypt));
        // reinterpreted as the other token type -> AAD mismatch
        assert_eq!(open(TokenType::Totp, &a, pass, "entryA", 99), Err(CryptoError::Decrypt));
    }

    #[test]
    fn nonces_differ_per_seal() {
        let p = "p";
        let a = seal(TokenType::Totp, "same", p, "n", 99).unwrap();
        let b = seal(TokenType::Totp, "same", p, "n", 99).unwrap();
        assert_ne!(a, b); // random salt+nonce -> distinct armor
    }

    #[test]
    fn v1_blob_rejected_by_version() {
        // A v1 blob (folded-encode KEK era) must fail LOUDLY as Version(1),
        // never as a confusing Decrypt error.
        let a = seal(TokenType::Totp, "s", "p", "n", 99).unwrap();
        let mut blob = BASE64URL_NOPAD.decode(a.as_bytes()).unwrap();
        blob[2] = 1;
        let a1 = BASE64URL_NOPAD.encode(&blob);
        assert_eq!(open(TokenType::Totp, &a1, "p", "n", 99), Err(CryptoError::Version(1)));
    }

    #[test]
    fn not_a_blob_detection() {
        assert!(!looks_like_blob("hashtag"));
        assert!(!looks_like_blob("not base64url !!!"));
    }

    #[test]
    fn sanitize_redacts_plaintext_markers() {
        assert_eq!(
            sanitize_for_history(r#"add x t T 99 now #"otpauth://totp/x?secret=ABC""#),
            "add x t T 99 now #<redacted>"
        );
        // unterminated quote (parse failure) still fully redacted
        assert_eq!(sanitize_for_history(r#"add e R 99 now !"half"#), "add e R 99 now !<redacted>");
        // a stored (already-encrypted) token has no quote -> untouched
        assert_eq!(sanitize_for_history("add x t T 99 now #hTabc"), "add x t T 99 now #hTabc");
    }
}

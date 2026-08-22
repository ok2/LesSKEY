//! The `pass` cache: master and parent passwords held for this session only.
//!
//! Two properties a plain `HashMap<Name, String>` does not have:
//!
//! - **Encrypted at rest in memory.** Every value is sealed with
//!   XChaCha20-Poly1305 under a random key minted at first use and rotated on
//!   each sweep, so a core dump, a swapped page, a hibernation image or a
//!   browser heap snapshot finds ciphertext where a master used to sit. This
//!   shrinks the plaintext *residency* window — it is NOT a boundary against an
//!   attacker who can read the live process, since key and ciphertext share one
//!   address space. Plaintext exists only between `get` and the drop of the
//!   `Zeroizing<String>` it hands out.
//! - **Expiry.** A cached password can age out, idle (`hel_pass_ttl`, reset by
//!   each use) or absolutely (`hel_pass_max_age`, counted from entry). Expiry
//!   is checked lazily on every read, so an expired secret is never usable even
//!   if no sweep ran; `sweep` is what actually wipes it and rotates the key.
//!
//! Both limits default to off, so with no `set` in `~/.helrc` this behaves like
//! the old cache, minus the plaintext.

use crate::crypto::{fill_random, CryptoError};
use crate::password::Name;
use crate::structs::config_get;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::cell::Cell;
use std::collections::HashMap;
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// Domain separator, so a sealed cache entry can never be confused with an
/// entry's inline `#`/`!` blob (`crypto::seal`, different key and AAD anyway).
const CONTEXT: &[u8] = b"hel-pass-cache-v1";

/// A reading of both clocks. Elapsed time is whichever advanced MORE, so a
/// rewound wall clock (or a monotonic clock that stood still across a suspend)
/// can only shorten a cached password's life, never extend it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub wall_ms: u64,
    pub mono_ms: u64,
}

impl Stamp {
    pub fn now() -> Self {
        Stamp { wall_ms: wall_ms(), mono_ms: mono_ms() }
    }

    /// For tests: a stamp where both clocks read `ms`.
    pub fn at(ms: u64) -> Self {
        Stamp { wall_ms: ms, mono_ms: ms }
    }

    fn elapsed_to(&self, later: &Stamp) -> u64 {
        let wall = later.wall_ms.saturating_sub(self.wall_ms);
        let mono = later.mono_ms.saturating_sub(self.mono_ms);
        wall.max(mono)
    }
}

fn wall_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn mono_ms() -> u64 {
    lazy_static! {
        static ref START: std::time::Instant = std::time::Instant::now();
    }
    START.elapsed().as_millis() as u64
}

// The browser build has no monotonic clock here (`Instant` traps on wasm32 and
// hel's core does not link js_sys), so expiry rides on the wall clock alone.
#[cfg(target_arch = "wasm32")]
fn mono_ms() -> u64 {
    0
}

/// How long a cached password may live. `None` on both = the old behaviour:
/// cached until `unpass`, `reset` or the process ends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// Time since the password was last USED (`hel_pass_ttl`).
    pub idle_ms: Option<u64>,
    /// Time since it was ENTERED, regardless of use (`hel_pass_max_age`).
    pub max_age_ms: Option<u64>,
}

impl Policy {
    /// Read from the live config, so a `set hel_pass_ttl …` takes effect on the
    /// very next command without restarting.
    pub fn from_config() -> Self {
        Policy {
            idle_ms: config_get("hel_pass_ttl").as_deref().and_then(parse_duration_ms),
            max_age_ms: config_get("hel_pass_max_age").as_deref().and_then(parse_duration_ms),
        }
    }

    pub fn is_off(&self) -> bool {
        self.idle_ms.is_none() && self.max_age_ms.is_none()
    }
}

/// `900` (bare number = seconds), `45s`, `15m`, `2h`, `1d`, and the spelled-out
/// forms (`15 min`, `2 hours`). `0`, an empty string and anything unparseable
/// mean "no limit" — a typo must not silently shorten a life, and `cmd_set`
/// rejects a value this cannot read.
pub fn parse_duration_ms(v: &str) -> Option<u64> {
    let v = v.trim().to_lowercase();
    if v.is_empty() {
        return None;
    }
    let digits: String = v.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    if n == 0 {
        return None;
    }
    let unit = v[digits.len()..].trim();
    let mult = match unit {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => 1_000,
        "m" | "min" | "mins" | "minute" | "minutes" => 60_000,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000,
        "d" | "day" | "days" => 86_400_000,
        _ => return None,
    };
    n.checked_mul(mult)
}

struct Secret {
    ct: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    born: Stamp,
    used: Cell<Stamp>,
}

impl Secret {
    fn expired(&self, now: &Stamp, policy: &Policy) -> bool {
        if let Some(max) = policy.max_age_ms {
            if self.born.elapsed_to(now) >= max {
                return true;
            }
        }
        if let Some(idle) = policy.idle_ms {
            if self.used.get().elapsed_to(now) >= idle {
                return true;
            }
        }
        false
    }
}

/// The cache itself. Cloning is deliberately not implemented: one live copy of
/// a master is enough.
pub struct Secrets {
    key: Zeroizing<[u8; KEY_LEN]>,
    map: HashMap<Name, Secret>,
}

impl Secrets {
    pub fn new() -> Self {
        Secrets { key: Zeroizing::new(mint_key()), map: HashMap::new() }
    }

    /// The cached password for `name`, or `None` when there is none or it has
    /// aged out. Reading refreshes the idle clock. The plaintext lives only as
    /// long as the returned value.
    pub fn get(&self, name: &str) -> Option<Zeroizing<String>> {
        self.get_at(name, Stamp::now(), Policy::from_config())
    }

    pub fn get_at(&self, name: &str, now: Stamp, policy: Policy) -> Option<Zeroizing<String>> {
        let secret = self.map.get(name)?;
        if secret.expired(&now, &policy) {
            return None;
        }
        secret.used.set(now);
        self.open(name, secret)
    }

    /// Is a live (non-expired) password cached for `name`? Presence only.
    pub fn contains_key(&self, name: &str) -> bool {
        self.contains_key_at(name, Stamp::now(), Policy::from_config())
    }

    pub fn contains_key_at(&self, name: &str, now: Stamp, policy: Policy) -> bool {
        self.map.get(name).map_or(false, |s| !s.expired(&now, &policy))
    }

    /// Cache `value` for `name`, replacing any previous one. `false` means it
    /// was NOT cached (no OS randomness, or sealing failed) — the caller should
    /// say so rather than assume the password is held.
    pub fn insert(&mut self, name: Name, value: &str) -> bool {
        self.insert_at(name, value, Stamp::now())
    }

    pub fn insert_at(&mut self, name: Name, value: &str, now: Stamp) -> bool {
        let mut nonce = [0u8; NONCE_LEN];
        if fill_random(&mut nonce).is_err() {
            return false;
        }
        match seal(&self.key, &nonce, &name, value) {
            Ok(ct) => {
                self.map.insert(name, Secret { ct, nonce, born: now, used: Cell::new(now) });
                true
            }
            Err(_) => false,
        }
    }

    /// Forget one name. `true` if something was actually held.
    pub fn remove(&mut self, name: &str) -> bool {
        self.map.remove(name).is_some()
    }

    /// Forget everything and mint a fresh key, so the old ciphertext left in
    /// freed memory decrypts under a key that no longer exists.
    pub fn clear(&mut self) {
        self.map.clear();
        self.key = Zeroizing::new(mint_key());
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Wipe every aged-out password and rotate the key, re-sealing the
    /// survivors. Returns the names that were dropped, so the caller can say
    /// what happened. This is what turns a lazy `None` into an actual wipe.
    pub fn sweep(&mut self) -> Vec<Name> {
        self.sweep_at(Stamp::now(), Policy::from_config())
    }

    pub fn sweep_at(&mut self, now: Stamp, policy: Policy) -> Vec<Name> {
        let mut dropped: Vec<Name> = Vec::new();
        if !policy.is_off() {
            for (name, secret) in self.map.iter() {
                if secret.expired(&now, &policy) {
                    dropped.push(name.clone());
                }
            }
            for name in &dropped {
                self.map.remove(name);
            }
        }
        self.rotate();
        dropped
    }

    /// Re-key the whole cache. A key recovered from a memory image is then
    /// worth only the window it was live for. Any failure keeps the old key —
    /// losing a cached master would be worse than a longer-lived key.
    fn rotate(&mut self) -> bool {
        if self.map.is_empty() {
            self.key = Zeroizing::new(mint_key());
            return true;
        }
        let key = Zeroizing::new(mint_key());
        let mut fresh: HashMap<Name, Secret> = HashMap::with_capacity(self.map.len());
        for (name, secret) in self.map.iter() {
            let plain = match self.open(name, secret) {
                Some(p) => p,
                None => return false,
            };
            let mut nonce = [0u8; NONCE_LEN];
            if fill_random(&mut nonce).is_err() {
                return false;
            }
            match seal(&key, &nonce, name, &plain) {
                Ok(ct) => {
                    fresh.insert(
                        name.clone(),
                        Secret { ct, nonce, born: secret.born, used: Cell::new(secret.used.get()) },
                    );
                }
                Err(_) => return false,
            }
        }
        self.key = key;
        self.map = fresh;
        true
    }

    fn open(&self, name: &str, secret: &Secret) -> Option<Zeroizing<String>> {
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let nonce = XNonce::try_from(&secret.nonce[..]).ok()?;
        let plain = cipher
            .decrypt(&nonce, Payload { msg: &secret.ct, aad: &aad(name) })
            .ok()?;
        let plain = Zeroizing::new(plain);
        String::from_utf8(plain.to_vec()).ok().map(Zeroizing::new)
    }
}

impl Default for Secrets {
    fn default() -> Self {
        Secrets::new()
    }
}

/// Compares the CACHED VALUES, ignoring timing — `LK::eq` (and the tests built
/// on it) ask "same passwords held?", not "held since the same instant".
impl PartialEq for Secrets {
    fn eq(&self, other: &Self) -> bool {
        if self.map.len() != other.map.len() {
            return false;
        }
        self.map.iter().all(|(name, secret)| match (self.open(name, secret), other.map.get(name)) {
            (Some(mine), Some(theirs)) => other.open(name, theirs).map_or(false, |t| *t == *mine),
            _ => false,
        })
    }
}

/// Never prints names or values: a `{:?}` of the whole `LK` must stay safe to
/// paste into a bug report.
impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets").field("entries", &self.map.len()).finish()
    }
}

fn mint_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    // A failure here leaves an all-zero key: the cache still works, it just
    // stops being a hurdle. Sealing itself is what refuses to store on a
    // randomness failure (see `insert`), so nothing is written under it.
    let _ = fill_random(&mut key);
    key
}

fn aad(name: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(CONTEXT.len() + 1 + name.len());
    a.extend_from_slice(CONTEXT);
    a.push(0);
    a.extend_from_slice(name.as_bytes());
    a
}

fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], name: &str, value: &str) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(&(*nonce).into(), Payload { msg: value.as_bytes(), aad: &aad(name) })
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFF: Policy = Policy { idle_ms: None, max_age_ms: None };

    #[test]
    fn roundtrip_and_isolation() {
        let mut s = Secrets::new();
        assert!(s.insert("/".to_string(), "root master"));
        assert!(s.insert("+bohr".to_string(), "bohr master"));
        assert_eq!(*s.get("/").unwrap(), "root master");
        assert_eq!(*s.get("+bohr").unwrap(), "bohr master");
        assert!(s.get("nope").is_none());
        assert_eq!(s.len(), 2);
        // the name is authenticated: a value cannot be moved between entries
        let stolen = s.map.get("+bohr").unwrap();
        assert!(s.open("/", stolen).is_none());
    }

    #[test]
    fn idle_ttl_resets_on_use() {
        let p = Policy { idle_ms: Some(1_000), max_age_ms: None };
        let mut s = Secrets::new();
        s.insert_at("/".to_string(), "m", Stamp::at(0));
        // used at 900 -> the idle clock restarts there
        assert!(s.get_at("/", Stamp::at(900), p).is_some());
        assert!(s.get_at("/", Stamp::at(1_800), p).is_some());
        // untouched for a full second -> gone
        assert!(s.get_at("/", Stamp::at(2_900), p).is_none());
        assert!(!s.contains_key_at("/", Stamp::at(2_900), p));
        // ... but only lazily: the value is still there until a sweep
        assert_eq!(s.len(), 1);
        assert_eq!(s.sweep_at(Stamp::at(2_900), p), vec!["/".to_string()]);
        assert!(s.is_empty());
    }

    #[test]
    fn max_age_ignores_use() {
        let p = Policy { idle_ms: None, max_age_ms: Some(1_000) };
        let mut s = Secrets::new();
        s.insert_at("/".to_string(), "m", Stamp::at(0));
        for t in [200, 400, 600, 800] {
            assert!(s.get_at("/", Stamp::at(t), p).is_some(), "kept alive at {}", t);
        }
        assert!(s.get_at("/", Stamp::at(1_000), p).is_none());
    }

    #[test]
    fn expiry_takes_the_faster_clock() {
        let p = Policy { idle_ms: Some(1_000), max_age_ms: None };
        let mut s = Secrets::new();
        s.insert_at("/".to_string(), "m", Stamp { wall_ms: 10_000, mono_ms: 0 });
        // wall clock rewound by an hour, monotonic says two seconds passed
        let now = Stamp { wall_ms: 6_400_000 - 6_400_000, mono_ms: 2_000 };
        assert!(s.get_at("/", now, p).is_none());
    }

    #[test]
    fn sweep_rotates_the_key_and_keeps_survivors() {
        let p = Policy { idle_ms: Some(1_000), max_age_ms: None };
        let mut s = Secrets::new();
        s.insert_at("old".to_string(), "gone", Stamp::at(0));
        s.insert_at("new".to_string(), "kept", Stamp::at(2_000));
        let before = *s.key;
        assert_eq!(s.sweep_at(Stamp::at(2_500), p), vec!["old".to_string()]);
        assert_ne!(before, *s.key, "the key must change on every sweep");
        assert_eq!(*s.get_at("new", Stamp::at(2_500), p).unwrap(), "kept");
    }

    #[test]
    fn clear_and_remove() {
        let mut s = Secrets::new();
        s.insert("a".to_string(), "1");
        s.insert("b".to_string(), "2");
        assert!(s.remove("a"));
        assert!(!s.remove("a"));
        let key = *s.key;
        s.clear();
        assert!(s.is_empty());
        assert_ne!(key, *s.key, "clear must re-key too");
    }

    #[test]
    fn equality_is_by_value() {
        let mut a = Secrets::new();
        let mut b = Secrets::new();
        a.insert("/".to_string(), "m");
        b.insert("/".to_string(), "m");
        assert_eq!(a, b, "different keys, same cached password");
        b.insert("/".to_string(), "other");
        assert_ne!(a, b);
    }

    #[test]
    fn debug_leaks_nothing() {
        let mut s = Secrets::new();
        s.insert("github".to_string(), "hunter2");
        let shown = format!("{:?}", s);
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("github"));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_ms("900"), Some(900_000));
        assert_eq!(parse_duration_ms("45s"), Some(45_000));
        assert_eq!(parse_duration_ms("15m"), Some(900_000));
        assert_eq!(parse_duration_ms("15 minutes"), Some(900_000));
        assert_eq!(parse_duration_ms("2h"), Some(7_200_000));
        assert_eq!(parse_duration_ms("1d"), Some(86_400_000));
        // off / unreadable
        assert_eq!(parse_duration_ms("0"), None);
        assert_eq!(parse_duration_ms(""), None);
        assert_eq!(parse_duration_ms("soon"), None);
        assert_eq!(parse_duration_ms("15 fortnights"), None);
    }
}

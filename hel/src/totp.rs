//! RFC 6238 TOTP over a decrypted seed (a bare base32 secret or a full
//! `otpauth://totp/...` URI). Kept pure (clock is passed in) so it unit-tests
//! against the RFC vectors; callers pass `chrono::Utc::now().timestamp()`.

use data_encoding::BASE32_NOPAD;
use hmac::{digest::KeyInit, Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum TotpError {
    #[error("bad base32 secret")]
    Base32,
    #[error("empty secret")]
    EmptySecret,
    #[error("unsupported algorithm {0}")]
    Algorithm(String),
    #[error("bad digits/period")]
    Param,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totp {
    pub secret: Vec<u8>,
    pub algorithm: Algo,
    pub digits: u32,
    pub period: u64,
}

fn base32_decode(s: &str) -> Result<Vec<u8>, TotpError> {
    let up: String = s.trim().to_uppercase().split_whitespace().collect();
    let up = up.trim_end_matches('=');
    if up.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    BASE32_NOPAD.decode(up.as_bytes()).map_err(|_| TotpError::Base32)
}

/// Minimal percent-decoding for otpauth query values.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse either a bare base32 secret (defaults SHA1/6/30) or an `otpauth://totp/…`
/// URI. The `otpauth://hotp/…` form is not a time code and is rejected.
pub fn parse(input: &str) -> Result<Totp, TotpError> {
    let s = input.trim();
    if let Some(rest) = s.strip_prefix("otpauth://") {
        let (kind, rest) = rest.split_once('/').unwrap_or((rest, ""));
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(TotpError::Algorithm(kind.to_string()));
        }
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut secret = None;
        let mut algorithm = Algo::Sha1;
        let mut digits = 6u32;
        let mut period = 30u64;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v);
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(v),
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algo::Sha1,
                        "SHA256" => Algo::Sha256,
                        "SHA512" => Algo::Sha512,
                        other => return Err(TotpError::Algorithm(other.to_string())),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| TotpError::Param)?,
                "period" => period = v.parse().map_err(|_| TotpError::Param)?,
                _ => {}
            }
        }
        let secret = secret.ok_or(TotpError::EmptySecret)?;
        build(base32_decode(&secret)?, algorithm, digits, period)
    } else {
        build(base32_decode(s)?, Algo::Sha1, 6, 30)
    }
}

fn build(secret: Vec<u8>, algorithm: Algo, digits: u32, period: u64) -> Result<Totp, TotpError> {
    if secret.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    if !(1..=10).contains(&digits) || period == 0 {
        return Err(TotpError::Param);
    }
    Ok(Totp {
        secret,
        algorithm,
        digits,
        period,
    })
}

fn hmac_digest<D: Mac + KeyInitFromSlice>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = D::new_slice(key);
    m.update(msg);
    m.finalize_bytes()
}

// Small shim so the three hash types share one code path without generics gymnastics.
trait KeyInitFromSlice {
    fn new_slice(key: &[u8]) -> Self;
    fn finalize_bytes(self) -> Vec<u8>;
}
macro_rules! impl_mac {
    ($t:ty) => {
        impl KeyInitFromSlice for $t {
            fn new_slice(key: &[u8]) -> Self {
                <$t as KeyInit>::new_from_slice(key).expect("hmac accepts any key length")
            }
            fn finalize_bytes(self) -> Vec<u8> {
                self.finalize().into_bytes().to_vec()
            }
        }
    };
}
impl_mac!(Hmac<Sha1>);
impl_mac!(Hmac<Sha256>);
impl_mac!(Hmac<Sha512>);

impl Totp {
    /// The code at a given unix timestamp (seconds).
    pub fn code_at(&self, unix_time: i64) -> String {
        let counter = if unix_time < 0 {
            0
        } else {
            unix_time as u64 / self.period
        };
        let msg = counter.to_be_bytes();
        let digest = match self.algorithm {
            Algo::Sha1 => hmac_digest::<Hmac<Sha1>>(&self.secret, &msg),
            Algo::Sha256 => hmac_digest::<Hmac<Sha256>>(&self.secret, &msg),
            Algo::Sha512 => hmac_digest::<Hmac<Sha512>>(&self.secret, &msg),
        };
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let bin = ((digest[offset] & 0x7f) as u64) << 24
            | (digest[offset + 1] as u64) << 16
            | (digest[offset + 2] as u64) << 8
            | (digest[offset + 3] as u64);
        let modulo = 10u64.pow(self.digits);
        format!("{:0width$}", bin % modulo, width = self.digits as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (8-digit codes, T0=0, X=30).
    // SHA1 secret = ASCII "12345678901234567890" -> base32:
    const SEED_SHA1_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_sha1_vectors() {
        let t = Totp {
            secret: base32_decode(SEED_SHA1_B32).unwrap(),
            algorithm: Algo::Sha1,
            digits: 8,
            period: 30,
        };
        assert_eq!(t.code_at(59), "94287082");
        assert_eq!(t.code_at(1111111109), "07081804");
        assert_eq!(t.code_at(1111111111), "14050471");
        assert_eq!(t.code_at(20000000000), "65353130");
    }

    #[test]
    fn bare_secret_defaults() {
        let t = parse("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(t.algorithm, Algo::Sha1);
        assert_eq!(t.digits, 6);
        assert_eq!(t.period, 30);
        assert_eq!(t.code_at(0).len(), 6);
    }

    #[test]
    fn otpauth_parse() {
        let t = parse("otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30").unwrap();
        assert_eq!(t.digits, 8);
        assert_eq!(t.code_at(59), "94287082");
    }

    #[test]
    fn lowercase_and_spaced_base32() {
        // GA "manual entry" secrets are often lowercase and space-grouped.
        let t = parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(t.code_at(59), "287082"); // 6-digit default = 94287082 mod 10^6
    }

    #[test]
    fn hotp_rejected() {
        assert!(parse("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=0").is_err());
    }
}

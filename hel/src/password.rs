use crate::skey::SKey;
use crate::structs::Mode;
use crate::utils::date::Date;
use parking_lot::ReentrantMutex;
use std::cell::RefCell;
use std::sync::Arc;

/// `+`-led names are independent roots: their password is ENTERED (via `pass`
/// or a prompt), never derived from a parent — chain resolution stops there.
/// `/` is the unnamed default root with the same semantics.
pub fn is_plus_root(name: &str) -> bool {
    name.starts_with('+')
}

/// A name carries the `$` unfold marker when it starts with `$` (after an
/// optional `+` root prefix): `$acct`, `+$vault`. The marker makes the entry —
/// and its whole subtree, see `Password::is_unfolded` — derive UNFOLDED
/// (full-width 160-bit values instead of the 64-bit folded S/KEY).
pub fn has_unfold_marker(name: &str) -> bool {
    name.strip_prefix('+').unwrap_or(name).starts_with('$')
}

pub type Name = String;
pub type Prefix = Option<String>;
pub type Comment = Option<String>;
pub type PasswordRef = Arc<ReentrantMutex<RefCell<Password>>>;
pub type Parent = Option<PasswordRef>;
pub type Length = Option<u32>;
pub type Seq = u32;

#[derive(Debug)]
pub struct Password {
    pub parent: Parent,
    pub prefix: Prefix,
    pub name: Name,
    pub length: Length,
    pub mode: Mode,
    pub seq: Seq,
    pub date: Date,
    pub comment: Comment,
}

impl Password {
    pub fn new(
        prefix: Prefix,
        name: Name,
        length: Length,
        mode: Mode,
        seq: Seq,
        date: Date,
        comment: Comment,
    ) -> Password {
        Password {
            prefix,
            name: name,
            length,
            mode,
            date,
            comment,
            parent: None,
            seq,
        }
    }

    pub fn from_password_ref(password: &Password) -> PasswordRef {
        Arc::new(ReentrantMutex::new(RefCell::new(Self {
            parent: password.parent.clone(),
            prefix: password.prefix.clone(),
            name: password.name.clone(),
            length: password.length.clone(),
            mode: password.mode.clone(),
            seq: password.seq,
            date: password.date.clone(),
            comment: password.comment.clone(),
        })))
    }

    pub fn from_password(password: Password) -> PasswordRef {
        Arc::new(ReentrantMutex::new(RefCell::new(password)))
    }

    /// `$`-subtree membership: this entry or any `^`-ancestor carries the `$`
    /// unfold marker in its name. Members derive UNFOLDED — the marker
    /// propagates, so it is set once on the base and never repeated below.
    pub fn is_unfolded(&self) -> bool {
        if has_unfold_marker(&self.name) {
            return true;
        }
        let mut cur = self.parent.clone();
        let mut depth = 0;
        while let Some(p) = cur {
            if depth > 256 {
                return false; // safety net; real cycles are broken by fix_password_recursion
            }
            if has_unfold_marker(&p.lock().borrow().name) {
                return true;
            }
            cur = p.lock().borrow().parent.clone();
            depth += 1;
        }
        false
    }

    pub fn encode(&self, secret: &str) -> String {
        let (sep, len) = match (&self.length, &self.mode) {
            (Some(n), Mode::NoSpace | Mode::NoSpaceUpcase) => ("", n),
            (Some(n), Mode::Base64 | Mode::Base64Upcase | Mode::Hex | Mode::HexUpcase) => ("", n),
            (Some(n), _) => ("", n),
            (None, Mode::NoSpace | Mode::NoSpaceUpcase) => ("-", &0_u32),
            (None, Mode::Base64 | Mode::Base64Upcase | Mode::Hex | Mode::HexUpcase | Mode::NoSpaceCamel) => {
                ("", &0_u32)
            }
            (None, _) => (" ", &0_u32),
        };
        // A `$`-subtree entry renders the UNFOLDED 160-bit value (15 words / 40
        // hex / …) — same modes, wider input. Chaining goes through this same
        // rendering, so the full width propagates to every descendant's master.
        let result = if self.is_unfolded() {
            let h = SKey::unfolded(&self.name, self.seq, secret);
            match self.mode {
                Mode::Regular | Mode::NoSpace | Mode::Totp => SKey::wide_words(&h).join(sep),
                Mode::RegularUpcase | Mode::NoSpaceUpcase => SKey::wide_words(&h).join(sep).to_uppercase(),
                Mode::NoSpaceCamel => camel_case(&SKey::wide_words(&h)),
                Mode::Hex => SKey::wide_hex(&h),
                Mode::HexUpcase => SKey::wide_hex(&h).to_uppercase(),
                Mode::Base64 => SKey::wide_b64(&h),
                Mode::Base64Upcase => SKey::wide_b64(&h).to_uppercase(),
                Mode::Decimal => SKey::wide_dec(&h).map(|v| v.to_string()).join(sep),
            }
        } else {
            let skey = SKey::new(&self.name, self.seq, secret);
            match self.mode {
                Mode::Regular => skey.to_words().join(sep),
                Mode::RegularUpcase => skey.to_words().join(sep).to_uppercase(),
                Mode::NoSpace => skey.to_words().join(sep),
                Mode::NoSpaceUpcase => skey.to_words().join(sep).to_uppercase(),
                Mode::NoSpaceCamel => camel_case(&skey.to_words()),
                Mode::Hex => skey.to_hex(),
                Mode::HexUpcase => skey.to_hex().to_uppercase(),
                Mode::Base64 => skey.to_b64(),
                Mode::Base64Upcase => skey.to_b64().to_uppercase(),
                Mode::Decimal => skey.to_dec().map(|v| v.to_string()).join(sep),
                // A TOTP entry has no typed password; its Regular rendering is what
                // `correct` verifies (mistype detection). `enc` intercepts T to print
                // the code; the seed itself is keyed by `kek_material` (unfolded).
                Mode::Totp => skey.to_words().join(sep),
            }
        };
        let result = match &self.prefix {
            Some(p) => (p.to_owned() + sep + &result).to_string(),
            None => result,
        };
        if len > &0_u32 {
            result.chars().take(*len as usize).collect()
        } else {
            result
        }
    }

    /// KEK passphrase for this entry's inline blobs: the UNFOLDED iterated
    /// SHA-1 state (full 160 bits) as hex. Unlike `encode`, it never folds to
    /// 64 bits and ignores mode/prefix/length — so blobs survive edits to
    /// those, and a >64-bit master keeps its entropy in the KEK.
    pub fn kek_material(&self, secret: &str) -> String {
        SKey::unfolded(&self.name, self.seq, secret).iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::string::ToString for Password {
    fn to_string(&self) -> String {
        let prefix = match self.prefix.as_ref() {
            Some(s) => format!("{} ", s),
            None => "".to_string(),
        };
        let length = match self.length {
            Some(l) => format!("{}", l),
            None => "".to_string(),
        };
        let comment = match self.comment.as_ref() {
            Some(s) => format!(" {}", s),
            None => "".to_string(),
        };
        let parent = match &self.parent {
            Some(s) => format!(" ^{}", s.lock().borrow().name),
            None => "".to_string(),
        };
        format!("{:>6}{} {}{} {} {}{}{}", prefix, self.name, length, self.mode, self.seq, self.date, comment, parent)
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && match (&self.parent, &other.parent) {
                (Some(s), Some(o)) => *s.lock() == *o.lock(),
                (None, None) => true,
                _ => false,
            }
            && self.prefix == other.prefix
            && self.length == other.length
            && self.mode == other.mode
            && self.seq == other.seq
    }
}

fn camel_case(words: &[&str]) -> String {
    let mut camel_case_string = String::new();

    for word in words.iter() {
        let mut chars = word.chars();
        camel_case_string.push(chars.next().unwrap().to_uppercase().next().unwrap());
        camel_case_string.extend(chars);
    }

    camel_case_string
}

pub fn fix_password_recursion(entry: PasswordRef) {
    let mut t1 = entry.clone();
    let mut t2 = entry;
    let mut t3: Option<PasswordRef> = None;
    loop {
        t2 = match &t2.clone().lock().borrow().parent {
            Some(o) => o.clone(),
            None => break,
        };
        if std::ptr::eq(&*t1.lock().borrow(), &*t2.lock().borrow()) {
            t3 = Some(t2.clone());
            break;
        }
        t1 = match &t1.clone().lock().borrow().parent {
            Some(o) => o.clone(),
            None => break,
        };
        t2 = match &t2.clone().lock().borrow().parent {
            Some(o) => o.clone(),
            None => break,
        };
        if std::ptr::eq(&*t1.lock().borrow(), &*t2.lock().borrow()) {
            t3 = Some(t2.clone());
            break;
        }
    }
    match t3 {
        Some(o) => o.lock().borrow_mut().parent = None,
        None => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_recursion_test() {
        let p1 = Password::from_password(Password::new(
            None,
            "p1".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        ));

        {
            p1.lock().borrow_mut().parent = Some(p1.clone());
        };
        fix_password_recursion(p1.clone());
        assert_eq!(p1.lock().borrow().parent.is_none(), true);

        let p2 = Password::from_password(Password::new(
            None,
            "p2".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        ));
        p2.lock().borrow_mut().parent = Some(p1.clone());
        let p3 = Password::from_password(Password::new(
            None,
            "p3".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        ));
        p3.lock().borrow_mut().parent = Some(p2.clone());
        let p4 = Password::from_password(Password::new(
            None,
            "p4".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        ));
        p4.lock().borrow_mut().parent = Some(p3.clone());
        let p5 = Password::from_password(Password::new(
            None,
            "p5".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        ));
        p5.lock().borrow_mut().parent = Some(p4.clone());

        p1.lock().borrow_mut().parent = Some(p3.clone());
        fix_password_recursion(p5.clone());
        assert_eq!(p3.lock().borrow().parent.is_none(), true);
    }

    #[test]
    fn exec_encode_test() {
        let sec = "my secret";
        let dat = Date::new(2022, 12, 3);

        let mut pwd = Password::new(None, "test1".to_string(), None, Mode::Regular, 99, dat, None);
        assert_eq!(pwd.encode(sec), "ross beau week held yoga anti");
        pwd.mode = Mode::NoSpaceCamel;
        assert_eq!(pwd.encode(sec), "RossBeauWeekHeldYogaAnti");
        pwd.mode = Mode::Decimal;
        assert_eq!(pwd.encode(sec), "1684 680 1995 1203 2046 619");
        pwd.mode = Mode::RegularUpcase;
        assert_eq!(pwd.encode(sec), "ROSS BEAU WEEK HELD YOGA ANTI");
        pwd.mode = Mode::Regular;
        pwd.prefix = Some("#Q3a".to_string());
        assert_eq!(pwd.encode(sec), "#Q3a ross beau week held yoga anti");
        pwd.mode = Mode::NoSpaceCamel;
        assert_eq!(pwd.encode(sec), "#Q3aRossBeauWeekHeldYogaAnti");
        pwd.mode = Mode::NoSpace;
        assert_eq!(pwd.encode(sec), "#Q3a-ross-beau-week-held-yoga-anti");
        pwd.mode = Mode::Base64;
        assert_eq!(pwd.encode(sec), "#Q3a0oqj5cs//Jo");
        pwd.mode = Mode::Base64Upcase;
        assert_eq!(pwd.encode(sec), "#Q3a0OQJ5CS//JO");
        pwd.mode = Mode::Hex;
        assert_eq!(pwd.encode(sec), "#Q3ae5a38ad29afc3fcb");
        pwd.mode = Mode::HexUpcase;
        assert_eq!(pwd.encode(sec), "#Q3aE5A38AD29AFC3FCB");
        pwd.mode = Mode::Decimal;
        assert_eq!(pwd.encode(sec), "#Q3a 1684 680 1995 1203 2046 619");

        let mut pwd = Password::new(None, "test1".to_string(), Some(6), Mode::Regular, 99, dat, None);
        assert_eq!(pwd.encode(sec), "rossbe");
        pwd.mode = Mode::NoSpaceCamel;
        assert_eq!(pwd.encode(sec), "RossBe");
        pwd.mode = Mode::Decimal;
        assert_eq!(pwd.encode(sec), "168468");
        pwd.mode = Mode::Regular;
        pwd.prefix = Some("#Q3a".to_string());
        assert_eq!(pwd.encode(sec), "#Q3aro");
        pwd.mode = Mode::NoSpace;
        assert_eq!(pwd.encode(sec), "#Q3aro");
        pwd.mode = Mode::Base64;
        assert_eq!(pwd.encode(sec), "#Q3a0o");
        pwd.mode = Mode::Hex;
        assert_eq!(pwd.encode(sec), "#Q3ae5");
        pwd.mode = Mode::Decimal;
        assert_eq!(pwd.encode(sec), "#Q3a16");
        pwd.length = Some(10);
        assert_eq!(pwd.encode(sec), "#Q3a168468");
        pwd.mode = Mode::NoSpaceCamel;
        assert_eq!(pwd.encode(sec), "#Q3aRossBe");
    }

    #[test]
    fn kek_material_test() {
        let sec = "my secret";
        let dat = Date::new(2022, 12, 3);
        let mut pwd = Password::new(None, "test1".to_string(), None, Mode::Totp, 99, dat, None);
        // The unfolded chain value (see skey.rs unfolded_test), NOT the folded
        // rendering — 40 hex chars vs encode()'s 16.
        let kek = pwd.kek_material(sec);
        assert_eq!(kek, "fe8d7667b8e895933d69c585a04166ea999c1dd4");
        assert_ne!(kek, pwd.encode(sec));
        // KEK depends only on (name, seq, secret): mode/prefix/length edits
        // must never orphan a blob.
        pwd.mode = Mode::Hex;
        pwd.prefix = Some("#Q3a".to_string());
        pwd.length = Some(10);
        assert_eq!(pwd.kek_material(sec), kek);
        // …while name/seq/master changes rightly re-key.
        pwd.seq = 98;
        assert_ne!(pwd.kek_material(sec), kek);
        pwd.seq = 99;
        pwd.name = "test2".to_string();
        assert_ne!(pwd.kek_material(sec), kek);
        pwd.name = "test1".to_string();
        assert_ne!(pwd.kek_material("other master"), kek);
    }

    #[test]
    fn unfold_marker_test() {
        assert!(has_unfold_marker("$acct"));
        assert!(has_unfold_marker("+$vault"));
        assert!(!has_unfold_marker("+bohr"));
        assert!(!has_unfold_marker("acct"));
        assert!(!has_unfold_marker("ac$ct")); // only a LEADING marker counts
        assert!(is_plus_root("+bohr"));
        assert!(is_plus_root("+$vault"));
        assert!(!is_plus_root("$acct"));
        assert!(!is_plus_root("bohr"));
    }

    #[test]
    fn unfolded_subtree_encode_test() {
        let sec = "my secret";
        let dat = Date::new(2022, 12, 3);
        // `$test1` renders the WIDE value (15 words; see skey wide_rendering_test
        // — but for the name "$test1", so a fresh derivation, not that vector).
        let mut base = Password::new(None, "test1".to_string(), None, Mode::Regular, 99, dat.clone(), None);
        let folded = base.encode(sec);
        assert_eq!(folded.split(' ').count(), 6);
        base.name = "$test1".to_string();
        let wide = base.encode(sec);
        assert_eq!(wide.split(' ').count(), 15);
        // and it IS the wide rendering of the unfolded chain value
        let h = SKey::unfolded("$test1", 99, sec);
        assert_eq!(wide, SKey::wide_words(&h).join(" "));
        // hex mode under $: 40 chars instead of 16
        base.mode = Mode::Hex;
        assert_eq!(base.encode(sec).len(), 40);
        base.mode = Mode::Regular;

        // $-ness PROPAGATES: a plain-named child under `$test1` is unfolded too.
        let base = Password::from_password(base);
        let mut child = Password::new(None, "sub".to_string(), None, Mode::Regular, 99, dat, None);
        child.parent = Some(base.clone());
        assert!(child.is_unfolded());
        assert_eq!(child.encode("x").split(' ').count(), 15);
        // …and a `+bohr` parent does NOT mark the subtree unfolded.
        base.lock().borrow_mut().name = "+bohr".to_string();
        assert!(!child.is_unfolded());
        assert_eq!(child.encode("x").split(' ').count(), 6);
    }
}

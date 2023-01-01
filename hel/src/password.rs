use crate::skey::SKey;
use crate::structs::Mode;
use crate::utils::date::Date;
use std::{cell::RefCell, rc::Rc};

pub type Name = String;
pub type Prefix = Option<String>;
pub type Comment = Option<String>;
pub type PasswordRef = Rc<RefCell<Password>>;
pub type Parent = Option<PasswordRef>;
pub type Length = Option<u32>;
pub type Seq = u32;

#[derive(PartialEq, Debug)]
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

    pub fn from_password(password: &Password) -> PasswordRef {
        Rc::new(RefCell::new(Self {
            parent: password.parent.clone(),
            prefix: password.prefix.clone(),
            name: password.name.clone(),
            length: password.length.clone(),
            mode: password.mode.clone(),
            seq: password.seq,
            date: password.date.clone(),
            comment: password.comment.clone(),
        }))
    }

    pub fn encode(&self, secret: &str) -> String {
        let skey = SKey::new(&self.name, self.seq, secret);
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
        let result = match self.mode {
            Mode::Regular => skey.to_words().join(sep),
            Mode::RegularUpcase => skey.to_words().join(sep).to_uppercase(),
            Mode::NoSpace => skey.to_words().join(sep),
            Mode::NoSpaceUpcase => skey.to_words().join(sep).to_uppercase(),
            Mode::NoSpaceCamel => camel_case(skey.to_words()),
            Mode::Hex => skey.to_hex(),
            Mode::HexUpcase => skey.to_hex().to_uppercase(),
            Mode::Base64 => skey.to_b64(),
            Mode::Base64Upcase => skey.to_b64().to_uppercase(),
            Mode::Decimal => skey.to_dec().map(|v| v.to_string()).join(sep),
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
            Some(s) => format!(" ^{}", s.borrow().name),
            None => "".to_string(),
        };
        format!("{:>6}{} {}{} {} {}{}{}", prefix, self.name, length, self.mode, self.seq, self.date, comment, parent)
    }
}

fn camel_case(words: [&str; 6]) -> String {
    let mut camel_case_string = String::new();

    for word in words.iter() {
        let mut chars = word.chars();
        camel_case_string.push(chars.next().unwrap().to_uppercase().next().unwrap());
        camel_case_string.extend(chars);
    }

    camel_case_string
}

pub fn fix_password_recursion(entry: Rc<RefCell<Password>>) {
    let mut t1 = entry.clone();
    let mut t2 = entry;
    let mut t3: Option<Rc<RefCell<Password>>> = None;
    loop {
        t2 = match &t2.clone().borrow().parent {
            Some(o) => o.clone(),
            None => break,
        };
        if std::ptr::eq(&*t1.borrow(), &*t2.borrow()) {
            t3 = Some(t2.clone());
            break;
        }
        t1 = match &t1.clone().borrow().parent {
            Some(o) => o.clone(),
            None => break,
        };
        t2 = match &t2.clone().borrow().parent {
            Some(o) => o.clone(),
            None => break,
        };
        if std::ptr::eq(&*t1.borrow(), &*t2.borrow()) {
            t3 = Some(t2.clone());
            break;
        }
    }
    match t3 {
        Some(o) => o.borrow_mut().parent = None,
        None => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_recursion_test() {
        let p1 = Rc::new(RefCell::new(Password::new(
            None,
            "p1".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        )));

        p1.borrow_mut().parent = Some(p1.clone());
        fix_password_recursion(p1.clone());
        assert_eq!(p1.borrow().parent, None);

        let p2 = Rc::new(RefCell::new(Password::new(
            None,
            "p2".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        )));
        p2.borrow_mut().parent = Some(p1.clone());
        let p3 = Rc::new(RefCell::new(Password::new(
            None,
            "p3".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        )));
        p3.borrow_mut().parent = Some(p2.clone());
        let p4 = Rc::new(RefCell::new(Password::new(
            None,
            "p4".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        )));
        p4.borrow_mut().parent = Some(p3.clone());
        let p5 = Rc::new(RefCell::new(Password::new(
            None,
            "p5".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 3),
            None,
        )));
        p5.borrow_mut().parent = Some(p4.clone());

        p1.borrow_mut().parent = Some(p3.clone());
        fix_password_recursion(p5.clone());
        assert_eq!(p3.borrow().parent, None);
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
}

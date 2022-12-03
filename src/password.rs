use crate::structs::Mode;
use chrono::naive::NaiveDate;
use std::{cell::RefCell, rc::Rc};

pub type Name = String;
pub type NameRef = Rc<Name>;
pub type Prefix = Option<String>;
pub type Comment = Option<String>;
pub type PasswordRef = Rc<RefCell<Password>>;
pub type Parent = Option<PasswordRef>;
pub type Length = Option<u32>;
pub type Seq = u32;
pub type Date = NaiveDate;

#[derive(PartialEq, Debug)]
pub struct Password {
    pub parent: Parent,
    pub prefix: Prefix,
    pub name: NameRef,
    pub length: Length,
    pub mode: Mode,
    pub seq: Seq,
    pub date: Date,
    pub comment: Comment,
}

impl Password {
    pub fn new(prefix: Prefix, name: Name, length: Length, mode: Mode, seq: Seq, date: Date, comment: Comment) -> Password {
        Password {
            prefix,
            name: Rc::new(name),
            length,
            mode,
            date,
            comment,
            parent: None,
            seq,
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
        format!(
            "{}{} {}{} {} {}{}{}",
            prefix, self.name, length, self.mode, self.seq, self.date, comment, parent
        )
    }
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
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
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
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
            None,
        )));
        p2.borrow_mut().parent = Some(p1.clone());
        let p3 = Rc::new(RefCell::new(Password::new(
            None,
            "p3".to_string(),
            None,
            Mode::Regular,
            99,
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
            None,
        )));
        p3.borrow_mut().parent = Some(p2.clone());
        let p4 = Rc::new(RefCell::new(Password::new(
            None,
            "p4".to_string(),
            None,
            Mode::Regular,
            99,
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
            None,
        )));
        p4.borrow_mut().parent = Some(p3.clone());
        let p5 = Rc::new(RefCell::new(Password::new(
            None,
            "p5".to_string(),
            None,
            Mode::Regular,
            99,
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
            None,
        )));
        p5.borrow_mut().parent = Some(p4.clone());

        p1.borrow_mut().parent = Some(p3.clone());
        fix_password_recursion(p5.clone());
        assert_eq!(p3.borrow().parent, None);
    }
}

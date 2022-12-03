use crate::structs::Mode;
use chrono::naive::NaiveDate;
use std::{cell::RefCell, rc::Rc};

#[derive(PartialEq, Debug)]
pub struct Password {
    pub parent: Option<Rc<RefCell<Password>>>,
    pub prefix: Option<String>,
    pub name: Rc<String>,
    pub length: Option<u32>,
    pub mode: Mode,
    pub seq: u32,
    pub date: NaiveDate,
    pub comment: Option<String>,
}

impl Password {
    pub fn new(prefix: Option<String>, name: String, mode: Mode, date: NaiveDate) -> Password {
        Password {
            prefix,
            mode,
            date,
            parent: None,
            name: Rc::new(name),
            length: None,
            seq: 99,
            comment: None,
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
            Mode::Regular,
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
        )));

        p1.borrow_mut().parent = Some(p1.clone());
        fix_password_recursion(p1.clone());
        assert_eq!(p1.borrow().parent, None);

        let p2 = Rc::new(RefCell::new(Password::new(
            None,
            "p2".to_string(),
            Mode::Regular,
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
        )));
        p2.borrow_mut().parent = Some(p1.clone());
        let p3 = Rc::new(RefCell::new(Password::new(
            None,
            "p3".to_string(),
            Mode::Regular,
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
        )));
        p3.borrow_mut().parent = Some(p2.clone());
        let p4 = Rc::new(RefCell::new(Password::new(
            None,
            "p4".to_string(),
            Mode::Regular,
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
        )));
        p4.borrow_mut().parent = Some(p3.clone());
        let p5 = Rc::new(RefCell::new(Password::new(
            None,
            "p5".to_string(),
            Mode::Regular,
            NaiveDate::from_ymd_opt(2022, 12, 3).unwrap(),
        )));
        p5.borrow_mut().parent = Some(p4.clone());

        p1.borrow_mut().parent = Some(p3.clone());
        fix_password_recursion(p5.clone());
        assert_eq!(p3.borrow().parent, None);
    }
}

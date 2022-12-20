use crate::password::{fix_password_recursion, Name, PasswordRef};
use regex::{Captures, Regex};
use std::collections::HashMap;

#[derive(PartialEq, Debug)]
pub struct LK {
    pub db: HashMap<Name, PasswordRef>,
    pub ls: HashMap<String, PasswordRef>,
    pub secrets: HashMap<Name, String>,
}

impl LK {
    pub fn new() -> Self {
        Self {
            db: HashMap::new(),
            ls: HashMap::new(),
            secrets: HashMap::new(),
        }
    }

    pub fn fix_hierarchy(&self) {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"\s*\^([!-~]+)").unwrap();
        }
        for (_, name) in &self.db {
            let comment = name.borrow().comment.clone();
            match comment {
                Some(comment) => {
                        let mut changed = false;
                    let new = RE.replace(comment.as_str(), |c: &Captures| {
                        let folder = c[1].to_string();
                        match self.db.get(&folder) {
                            Some(entry) => {
                                name.borrow_mut().parent = Some(entry.clone());
                                changed = true;
                            }
                            None => (),
                        }
                        ""
                    }).to_string();
                    if changed && new != comment { name.borrow_mut().comment = if new.len() > 0 { Some(new) } else { None } }
                }
                None => (),
            }
            fix_password_recursion(name.clone());
        }
    }
}

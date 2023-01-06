use crate::password::{fix_password_recursion, Name, PasswordRef};
use parking_lot::ReentrantMutex;
use regex::{Captures, Regex};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

pub type LKRef = Arc<ReentrantMutex<RefCell<LK>>>;

#[derive(Debug)]
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
        for db in vec![&self.db, &self.ls] {
            for (_, name) in db {
                let comment = name.lock().borrow().comment.clone();
                match comment {
                    Some(comment) => {
                        let mut changed = false;
                        let new = RE
                            .replace(comment.as_str(), |c: &Captures| {
                                let folder = c[1].to_string();
                                match self.db.get(&folder) {
                                    Some(entry) => {
                                        name.lock().borrow_mut().parent = Some(entry.clone());
                                        changed = true;
                                    }
                                    None => (),
                                }
                                ""
                            })
                            .trim()
                            .to_string();
                        if changed && new != comment {
                            name.lock().borrow_mut().comment = if new.len() > 0 { Some(new) } else { None }
                        }
                    }
                    None => (),
                }
                fix_password_recursion(name.clone());
            }
        }
    }
}

impl PartialEq for LK {
    fn eq(&self, other: &Self) -> bool {
        if self.db.len() != other.db.len() || self.ls.len() != other.ls.len() || self.secrets != other.secrets {
            return false;
        }
        for (k, v) in &self.db {
            if !other.db.contains_key(k) || *other.db[k].lock() != *v.lock() {
                return false;
            }
        }
        for (k, v) in &self.ls {
            if !other.ls.contains_key(k) || *other.ls[k].lock() != *v.lock() {
                return false;
            }
        }
        true
    }
}

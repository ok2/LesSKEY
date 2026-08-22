use crate::password::{fix_password_recursion, Name, PasswordRef};
use crate::secrets::Secrets;
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
    /// Cached `pass` passwords: encrypted at rest, aged out by policy.
    pub secrets: Secrets,
    /// Serialized dump as of the last load (`source`) or save (`dump`). Used to
    /// show a `< removed` / `> added` diff on save so removals are noticed.
    pub last_dump: Option<String>,
}

impl LK {
    pub fn new() -> Self {
        Self {
            db: HashMap::new(),
            ls: HashMap::new(),
            secrets: Secrets::new(),
            last_dump: None,
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

/// One expiry tick over the shared state: wipe every cached password that has
/// aged out, rotate the cache key, and report what went. Both callers use this
/// — the per-command sweep in `LKEval::eval` and the native sweeper thread —
/// so "what expires" is defined in exactly one place.
pub fn sweep_tick(state: &LKRef) -> Vec<Name> {
    state.lock().borrow_mut().secrets.sweep()
}

/// The line hel prints when a sweep dropped something. Names only, never values.
pub fn expired_note(dropped: &[Name]) -> String {
    if dropped.len() == 1 {
        format!("note: forgot the cached password for {} (expired)", dropped[0])
    } else {
        format!("note: forgot cached passwords for {} (expired)", dropped.join(", "))
    }
}

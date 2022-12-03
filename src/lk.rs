use crate::password::{fix_password_recursion, NameRef, PasswordRef};
use regex::{Captures, Regex};
use std::collections::HashMap;

#[derive(PartialEq, Debug)]
pub struct LK {
    pub db: HashMap<NameRef, PasswordRef>,
}

impl LK {
    pub fn new() -> Self {
        Self { db: HashMap::new() }
    }

    pub fn fix_hierarchy(&self) {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"\s*\^([!-~]+)").unwrap();
        }
        for (_, name) in &self.db {
            if name.borrow().comment.is_some() {
                let mut folder: Option<String> = None;
                let prev_comment = name.borrow().comment.as_ref().unwrap().clone();
                let comment = RE.replace(prev_comment.as_str(), |c: &Captures| {
                    folder = Some(c[1].to_string());
                    ""
                });
                if folder.is_some() {
                    let folder_name = folder.unwrap();
                    for (_, entry) in &self.db {
                        if *entry.borrow().name == *folder_name {
                            let mut tmp = name.borrow_mut();
                            tmp.parent = Some(entry.clone());
                            if comment.len() == 0 {
                                tmp.comment = None
                            } else {
                                tmp.comment = Some(comment.to_string())
                            }
                            break;
                        }
                    }
                }
            }
            fix_password_recursion(name.clone());
        }
    }
}

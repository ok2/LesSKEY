use std::{cell::RefCell, rc::Rc};
use std::collections::HashMap;
use regex::{Regex, Captures};
use crate::structs::Password;

#[derive(PartialEq, Debug)]
pub struct LK {
  pub db: HashMap<Rc<String>, Rc<RefCell<Password>>>,
}

impl LK {
  pub fn fix_hierarchy(&self) {
    lazy_static! {
      static ref RE: Regex = Regex::new(r"\s*\^([!-~]+)").unwrap();
    }
    for (_, name) in &self.db {
      if name.borrow().comment.is_some() {
        let mut folder: Option<String> = None;
        let prev_comment = name.borrow().comment.as_ref().unwrap().clone();
        let comment = RE.replace(prev_comment.as_str(), |c: &Captures| { folder = Some(c[1].to_string()); "" });
        if folder.is_some() {
          let folder_name = folder.unwrap();
          for (_, entry) in &self.db {
            if *entry.borrow().name == *folder_name {
              {
                let mut tmp = name.borrow_mut();
                tmp.parent = Some(entry.clone());
                if comment.len() == 0 { tmp.comment = None }
                else { tmp.comment = Some(comment.to_string()) }
              }
              break;
            }
          }
        }
      }
    }
  }  
}
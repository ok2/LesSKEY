use std::collections::HashMap;
use regex::{Regex, Captures};
use chrono::naive::NaiveDate;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum LKErr<'a> {
  #[error("Error: {0}")]
  Error(&'a str),
  #[error("Failed to read the line: {0}")]
  ReadError(String),
  #[error("Failed to parse {0}: {1}")]
  ParseError(&'a str, &'a str),
  #[error("Failed to parse {0}: {1}")]
  ParseErrorS(&'a str, String),
  #[error("Failed to parse: {0}")]
  PegParseError(peg::error::ParseError<peg::str::LineCol>),
}

#[derive(PartialEq, Debug)]
pub enum Mode {
  Regular,
  RegularUpcase,
  NoSpace,
  NoSpaceUpcase,
  Hex,
  HexUpcase,
  Base64,
  Base64Upcase,
  Decimal,
}

#[derive(PartialEq, Debug)]
pub struct Password {
  parent: Option<Rc<RefCell<Password>>>,
  prefix: Option<String>,
  name: Rc<String>,
  length: Option<u32>,
  mode: Mode,
  seq: u32,
  date: NaiveDate,
  comment: Option<String>,
}

#[derive(PartialEq, Debug)]
pub enum Command<'a> {
  Add(Rc<RefCell<Password>>),
  Ls,
  Mv(String, String),
  Error(LKErr<'a>),
  Help,
  Quit
}

#[derive(Debug)]
struct LK {
  db: HashMap<Rc<String>, Rc<RefCell<Password>>>,
}

impl std::fmt::Display for Mode {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
        Mode::Regular => write!(f, "R"),
        Mode::RegularUpcase => write!(f, "UR"),
        Mode::NoSpace => write!(f, "N"),
        Mode::NoSpaceUpcase => write!(f, "UN"),
        Mode::Hex => write!(f, "H"),
        Mode::HexUpcase => write!(f, "UH"),
        Mode::Base64 => write!(f, "B"),
        Mode::Base64Upcase => write!(f, "UB"),
        Mode::Decimal => write!(f, "D"),
    }
  }
}

impl LK {
  fn fix_hierarchy(&self) {
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
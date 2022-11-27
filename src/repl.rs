use rustyline::Editor;
use std::{cell::RefCell, rc::Rc};

use crate::structs::{LKErr, Command, LK};
use crate::parser::command_parser;

#[derive(Debug)]
pub struct LKRead {
  rl: Editor::<()>,
  prompt: String,
  state: Rc<RefCell<LK>>,
  cmd: String,
}

#[derive(Debug)]
pub struct LKEval<'a> {
  cmd: Command<'a>,
  state: Rc<RefCell<LK>>,
}

#[derive(Debug, PartialEq)]
pub struct LKPrint {
  out: Vec<String>,
  quit: bool,
  state: Rc<RefCell<LK>>,
}

impl LKRead {
  pub fn new(rl: Editor::<()>, prompt: String, state: Rc<RefCell<LK>>) -> Self {
     Self { rl, prompt, state, cmd: "".to_string() }
  }

  pub fn read(&mut self) -> LKEval {
    self.cmd = match self.rl.readline(&*self.prompt) {
      Ok(str) => str,
      Err(err) => return LKEval::new(Command::Error(LKErr::ReadError(err.to_string())), self.state.clone()),
    };
    match command_parser::cmd(self.cmd.as_str()) {
      Ok(cmd) => LKEval::new(cmd, self.state.clone()),
      Err(err) => LKEval::new(Command::Error(LKErr::ParseError(err)), self.state.clone()),
    }
  }

  pub fn refresh(&mut self) {

  }

  pub fn quit(&mut self) {

  }
}

impl<'a> LKEval<'a> {
  pub fn new(cmd: Command<'a>, state: Rc<RefCell<LK>>) -> Self { Self { cmd, state } }

  pub fn eval(&mut self) -> LKPrint {
    let mut out: Vec<String> = vec![];
    let mut quit: bool = false;

    match &self.cmd {
      Command::Quit => {
        out.push("Bye!".to_string());
        quit = true;
      },
      Command::Ls => {
        for (_, name) in &self.state.borrow().db {
          out.push(name.borrow().to_string());
        }
      },
      Command::Add(name) => {
        if self.state.borrow().db.get(&name.borrow().name).is_some() {
          out.push("error: password already exist".to_string());
        } else {
          self.state.borrow_mut().db.insert(name.borrow().name.clone(), name.clone());
          self.state.borrow().fix_hierarchy();
        }
      },
      Command::Help => {
        out.push("HELP".to_string());
      },
      Command::Mv(name, folder) => {
        for (_, tmp) in &self.state.borrow().db {
          if *tmp.borrow().name == *name {
            if folder == "/" { tmp.borrow_mut().parent = None }
            else {
              for (_, fld) in &self.state.borrow().db {
                if *fld.borrow().name == *folder {
                  tmp.borrow_mut().parent = Some(fld.clone());
                  break;
                }
              }
            }
            break;
          }
        }
      },
      Command::Error(err) => {
        match err {
          LKErr::ParseError(e) => { out.push(e.to_string()) },
          LKErr::ReadError(e) => { out.push(e.to_string()) },
          LKErr::Error(e) => { out.push(format!("error: {}", e.to_string())) },
        }
      }
    }

    LKPrint::new(out, quit, self.state.clone())
  }
}

impl LKPrint {
    pub fn new(out: Vec<String>, quit: bool, state: Rc<RefCell<LK>>) -> Self { Self { out, quit, state } }

    pub fn print(&mut self) -> bool {
        for line in &self.out {
            println!("{}", line);
        }
        return !self.quit;
    }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::HashMap;
  use chrono::naive::NaiveDate;
  use crate::structs::*;

  #[test]
  fn exec_cmds_basic() {
    let lk = Rc::new(RefCell::new(LK { db: HashMap::new() }));
    assert_eq!(LKEval::new(Command::Ls, lk.clone()).eval(), LKPrint::new(vec![], false, lk.clone()));
    let pwd = Rc::new(RefCell::new(Password { name: Rc::new("t1".to_string()),
                                              prefix: None,
                                              length: None,
                                              mode: Mode::Regular,
                                              seq: 99,
                                              date: NaiveDate::from_ymd_opt(2022, 12, 30).unwrap(),
                                              comment: Some("comment".to_string()),
                                              parent: None }));
    assert_eq!(LKEval::new(Command::Add(pwd.clone()), lk.clone()).eval().state.borrow().db,
               { let mut db = HashMap::new(); db.insert(pwd.borrow().name.clone(), pwd.clone()); db });
  }
}
#[macro_use]
extern crate lazy_static;

mod lk;
mod parser;
mod password;
mod repl;
mod skey;
mod structs;

use rpassword::prompt_password;
use rustyline::Editor;
use std::{cell::RefCell, rc::Rc};

use crate::lk::LK;
use crate::parser::command_parser;
use crate::repl::{LKEval, LKRead};
use crate::structs::{Command, LKErr, INIT_FILE};

pub fn main() {
    let lk = Rc::new(RefCell::new(LK::new()));

    match std::fs::read_to_string(INIT_FILE.as_path().to_str().unwrap()) {
        Ok(script) => match command_parser::script(&script) {
            Ok(cmd_list) => {
                for cmd in cmd_list {
                    LKEval::new(cmd, lk.clone(), prompt_password).eval().print();
                }
            }
            Err(err) => {
                LKEval::new(Command::Error(LKErr::ParseError(err)), lk.clone(), prompt_password).eval().print();
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
        Err(err) => {
            LKEval::new(Command::Error(LKErr::Error(format!("Failed to read init file {:?}: {}", INIT_FILE.as_path(), err).as_str())), lk.clone(), prompt_password)
                .eval()
                .print();
        }
    }
    let mut lkread = LKRead::new(Editor::<()>::new().unwrap(), String::from("❯ "), lk.clone());

    while lkread.read().eval().print() {
        lkread.refresh();
    }
    lkread.quit();
}

#[macro_use]
extern crate lazy_static;

mod lk;
mod parser;
mod password;
mod repl;
mod structs;

use rustyline::Editor;
use std::{cell::RefCell, rc::Rc};

use crate::lk::LK;
use crate::repl::LKRead;

pub fn main() {
    let lk = Rc::new(RefCell::new(LK::new()));
    let mut lkread = LKRead::new(Editor::<()>::new().unwrap(), String::from("❯ "), lk.clone());

    while lkread.read().eval().print() {
        lkread.refresh();
    }
    lkread.quit();
}

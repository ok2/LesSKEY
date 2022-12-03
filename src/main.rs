#[macro_use]
extern crate lazy_static;

mod structs;
mod password;
mod parser;
mod repl;
mod lk;

use std::{cell::RefCell, rc::Rc};
use rustyline::Editor;

use crate::lk::LK;
use crate::repl::LKRead;

pub fn main() {
    let lk = Rc::new(RefCell::new(LK::new()));
    let mut lkread = LKRead::new(
        Editor::<()>::new().unwrap(),
        String::from("❯ "),
        lk.clone());

    while lkread.read().eval().print() {
        lkread.refresh();
    }
    lkread.quit();
}

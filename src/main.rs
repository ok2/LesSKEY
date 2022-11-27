#[macro_use]
extern crate lazy_static;

mod structs;
mod parser;
mod repl;

use std::{cell::RefCell, rc::Rc};
use std::collections::HashMap;

use rustyline::Editor;

use crate::structs::LK;
use crate::repl::LKRead;

pub fn main() {
    let lk = Rc::new(RefCell::new(LK { db: HashMap::new() }));
    let mut lkread = LKRead::new(
        Editor::<()>::new().unwrap(),
        String::from("❯ "),
        lk.clone());

    while lkread.read().eval().print() {
        lkread.refresh();
    }
    lkread.quit();
}
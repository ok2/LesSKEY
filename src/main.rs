#[macro_use]
extern crate lazy_static;

pub mod structs;
pub mod parser;
pub mod repl;

use rustyline::Editor;
use std::{cell::RefCell, rc::Rc};

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
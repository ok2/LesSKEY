#![recursion_limit = "1024"]
#[macro_use]
extern crate lazy_static;
#[allow(unused_imports)]
#[macro_use(defer)]
extern crate scopeguard;

mod commands;
mod lk;
mod parser;
mod password;
mod repl;
mod skey;
mod structs;
mod utils;

use crate::structs::init;

pub fn main() {
    let mut lkread = match init() { Some(r) => r, None => { return; } };

    while lkread.read().eval().print() {
        lkread.refresh();
    }
    lkread.quit();
}

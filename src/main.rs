#[macro_use] extern crate lazy_static;
#[allow(unused_imports)] #[macro_use(defer)] extern crate scopeguard;

mod lk;
mod commands;
mod parser;
mod password;
mod repl;
mod skey;
mod structs;
mod utils;

use crate::structs::init;

pub fn main() {
    let mut lkread = init();

    while lkread.read().eval().print() {
        lkread.refresh();
    }
    lkread.quit();
}

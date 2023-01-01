extern crate hel;

use hel::structs::init;

pub fn main() {
    let mut lkread = match init() { Some(r) => r, None => { return; } };

    while lkread.read().eval().print() {
        lkread.refresh();
    }
    lkread.quit();
}

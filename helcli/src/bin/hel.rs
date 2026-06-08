extern crate hel;

use hel::structs::init;

pub fn main() {
    // Non-interactive subcommands. These must short-circuit BEFORE init(): they
    // do not start the REPL, read ~/.helrc, or prompt for a master password.
    // That also prevents recursion — a `.helrc` line `source hel load notion:x|`
    // spawns `hel load …`, which lands here and never re-reads `.helrc`.
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("store") => {
            std::process::exit(helcli::run_store(args.get(2).map(String::as_str).unwrap_or("")))
        }
        Some("load") => {
            std::process::exit(helcli::run_load(args.get(2).map(String::as_str).unwrap_or("")))
        }
        _ => {}
    }

    let mut lkread = match init() {
        Some(r) => r,
        None => {
            return;
        }
    };

    while lkread.read().eval().print() {
        lkread.refresh();
    }
    lkread.quit();
}

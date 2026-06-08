//! `helcli` library: the non-interactive `hel store` / `hel load` subcommands
//! that back the `hel` REPL's persistence onto a Notion page.
//!
//! Contract (matches the old Evernote pipe scripts):
//! - `hel store notion:<ref>` reads the dump script from **stdin** and writes it
//!   to the Notion page. Status/errors go to **stderr**; stdout is kept empty so
//!   the parent `hel` prints its own "Passwords saved to command hel".
//! - `hel load notion:<ref>` fetches the page and writes the script to **stdout**
//!   verbatim, for the parent's `source … |` to eval.

pub mod notion;

use std::io::Read;

/// `hel store notion:<ref>` — stdin (dump) → Notion. Returns a process exit code.
pub fn run_store(target: &str) -> i32 {
    let reference = match notion::parse_target(target) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hel store: {}", e);
            return 2;
        }
    };
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("hel store: failed to read stdin: {}", e);
        return 1;
    }
    let client = match notion::Notion::from_env() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("hel store: {}", e);
            return 1;
        }
    };
    let page = match client.resolve_page(reference) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("hel store: {}", e);
            return 1;
        }
    };
    match client.write_dump(&page, &input) {
        Ok(()) => {
            eprintln!("hel store: saved to Notion page {}", page);
            0
        }
        Err(e) => {
            eprintln!("hel store: {}", e);
            1
        }
    }
}

/// `hel load notion:<ref>` — Notion → stdout (dump). Returns a process exit code.
pub fn run_load(target: &str) -> i32 {
    let reference = match notion::parse_target(target) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hel load: {}", e);
            return 2;
        }
    };
    let client = match notion::Notion::from_env() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("hel load: {}", e);
            return 1;
        }
    };
    let page = match client.resolve_page(reference) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("hel load: {}", e);
            return 1;
        }
    };
    match client.read_dump(&page) {
        Ok(text) => {
            print!("{}", text);
            0
        }
        Err(e) => {
            eprintln!("hel load: {}", e);
            1
        }
    }
}

use hel::lk::{LK, LKRef};
use hel::parser::command_parser;
use hel::repl::{LKEval, LKRead};
use hel::structs::LKOut;
use hel::utils::editor::{password, Editor};
use parking_lot::ReentrantMutex;
use std::cell::RefCell;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

lazy_static! {
    static ref STATE: LKRef = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
}

/// Run a single hel command line and return its combined output.
#[wasm_bindgen]
pub fn hel_command(cmd: String) -> String {
    let editor = Editor::new();
    let mut lkread = LKRead::new(editor, "> ".to_string(), STATE.clone());
    lkread.input = Some(cmd);
    let lkeval = lkread.read();
    let lkprint = lkeval.eval();
    lkprint.out.output().join("\n")
}

/// Parse a password spec (e.g. `exa91` or `exa91 20R 99 2020-01-01`) and return
/// the canonical normalized form hel actually uses (name + mode + seq + date +
/// comment), without touching state. Returns the input unchanged if it does not
/// parse. Used by the UI to rewrite the name field on blur.
#[wasm_bindgen]
pub fn hel_parse(spec: String) -> String {
    match command_parser::name(&spec) {
        Ok(p) => p.to_string().trim().to_string(),
        Err(_) => spec,
    }
}

/// Parse a spec and return just the entry name hel resolves it to. Handles a
/// leading prefix (e.g. `*P0 test1 …` → `test1`), which a naive first-token
/// split would get wrong. Falls back to the first whitespace token.
#[wasm_bindgen]
pub fn hel_parse_name(spec: String) -> String {
    match command_parser::name(&spec) {
        Ok(p) => p.name,
        Err(_) => spec.split_whitespace().next().unwrap_or("").to_string(),
    }
}

/// Run a whole multi-line script (every `add …` line, `set …`, etc.) against the
/// shared state in one call. Used to bulk-import a pasted catalog (e.g. the text
/// of the Notion page) and to load the persisted catalog from localStorage.
#[wasm_bindgen]
pub fn hel_load_script(script: String) -> String {
    let out = LKOut::new();
    match command_parser::script(&script) {
        Ok(cmds) => {
            for cmd in cmds {
                let print = LKEval::new(Editor::new(), cmd, STATE.clone(), password).eval();
                print.out.copy(&out);
            }
        }
        Err(e) => out.e(format!("error: {}", e)),
    }
    out.output().join("\n")
}

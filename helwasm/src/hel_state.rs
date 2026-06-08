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

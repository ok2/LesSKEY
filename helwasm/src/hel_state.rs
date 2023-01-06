use hel::lk::{LK, LKRef};
use hel::repl::LKRead;
use hel::utils::editor::Editor;
use std::sync::Arc;
use parking_lot::ReentrantMutex;
use std::cell::RefCell;
use wasm_bindgen::prelude::*;

lazy_static! {
    static ref STATE: LKRef = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
}

#[wasm_bindgen]
pub fn hel_command(cmd: String) -> String {
    let editor = Editor::new();
    let mut lkread = LKRead::new(editor, "> ".to_string(), STATE.clone());
    lkread.cmd = cmd.to_string();
    let lkeval = lkread.read();
    let lkprint = lkeval.eval();
    lkprint.out.output().join("\n")
}

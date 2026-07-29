use hel::lk::{LK, LKRef};
use hel::parser::command_parser;
use hel::repl::{LKEval, LKRead};
use hel::structs::LKOut;
use hel::utils::editor::{password, Editor};
use parking_lot::ReentrantMutex;
use regex::Regex;
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

/// Look up an entry by its exact name and return its canonical stored form
/// (`name [len]mode seq date comment ^parent`), or "" if it is not in the catalog.
/// Read-only. The UI uses this to detect "already stored" and to use the real stored
/// spec (its mode/seq/date/parent) instead of the bare name the user typed.
#[wasm_bindgen]
pub fn hel_entry(name: String) -> String {
    let cell = STATE.lock();
    let lk = cell.borrow();
    match lk.db.get(&name).or_else(|| lk.ls.get(&name)) {
        Some(p) => p.lock().borrow().to_string().trim().to_string(),
        None => String::new(),
    }
}

/// Return catalog entries matching `pattern`, one canonical stored line per
/// line (`name [len]mode seq date comment ^parent` — the dump/export form),
/// sorted — the completion set for a typed name. The pattern is a regular
/// expression matched anywhere in the full canonical line, mirroring `ls`
/// (so `^`/`$` anchor against the whole line, and mode/comment/parent are
/// searchable too). Case-insensitive by default; a leading `(?-i)` forces
/// case-sensitive, exactly like `ls`. A pattern that does not compile (e.g.
/// a half-typed `micro(`) falls back to a literal substring match, so
/// suggestions never vanish mid-keystroke. Read-only: reads `db` values
/// only, so (unlike `ls`) it never rebuilds `lk.ls` or mutates state, and
/// can never add to the catalog.
#[wasm_bindgen]
pub fn hel_names(pattern: String) -> String {
    // Same case rule as cmd_ls: prepend (?i); an inline (?-i) still wins.
    let re = Regex::new(&format!("(?i){}", pattern))
        .or_else(|_| Regex::new(&format!("(?i){}", regex::escape(&pattern))));
    let re = match re {
        Ok(re) => re,
        Err(_) => return String::new(),
    };
    let cell = STATE.lock();
    let lk = cell.borrow();
    let mut lines: Vec<String> = lk
        .db
        .values()
        .map(|p| p.lock().borrow().to_string().trim().to_string())
        .filter(|line| re.find(line).is_some())
        .collect();
    lines.sort(); // lines start with the name → byte-lexicographic like cmd_ls
    lines.join("\n")
}

/// Return the `^parent` chain of `name`, immediate parent first, one per line
/// ("" if `name` is unknown or has no parent). These are exactly the entries
/// `read_master` climbs through when deriving `name`: with no root master given,
/// the UI prompts for each in turn (the name's base, then the base's base, …).
/// Read-only; cycle-guarded.
#[wasm_bindgen]
pub fn hel_chain(name: String) -> String {
    let cell = STATE.lock();
    let lk = cell.borrow();
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cur = lk.db.get(&name).or_else(|| lk.ls.get(&name)).cloned();
    while let Some(p) = cur {
        let parent = p.lock().borrow().parent.clone();
        match parent {
            Some(pn) => {
                let pname = pn.lock().borrow().name.to_string();
                if !seen.insert(pname.clone()) {
                    break; // cycle guard
                }
                out.push(pname);
                cur = Some(pn);
            }
            None => break,
        }
    }
    out.join("\n")
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

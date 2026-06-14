use regex::Regex;
use sha1::{Digest, Sha1};
use std::cmp::min;
use std::collections::HashSet;

use crate::parser::command_parser;
use crate::password::fix_password_recursion;
use crate::password::{Name, Password, PasswordRef};
use crate::repl::LKEval;
use crate::structs::{config_flag, config_get, config_set, Command, LKOut, Radix, CORRECT_FILE, DUMP_FILE};
use crate::utils::editor::password;
// call_cmd_with_input / get_cmd_args_from_command are only used by the native
// (non-wasm) subprocess branches. copy_to_clipboards is native-only, so it is
// referenced fully-qualified at its one call site (not imported here, which
// would break the wasm build).
#[cfg_attr(target_arch = "wasm32", allow(unused_imports))]
use crate::utils::{call_cmd_with_input, get_cmd_args_from_command, rnd};

// In the browser `pb` copies through the host page's clipboard (navigator.clipboard)
// instead of shelling out to pbcopy/xclip.
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = hel_clipboard_write)]
    fn hel_clipboard_write(text: &str);
}

const HELP_OVERVIEW: &str = "\
hel — deterministic S/KEY (RFC 2289) passwords. Your master plus an entry's
name + sequence + date derive the password on the fly; nothing secret is
stored. Default form is six short, memorable words (xkcd 936).

  help <topic>   detail for a command or concept, e.g. `help enc`, `help add`,
                 `help modes`, `help config`, `help files`.

ENTRIES
  add <descriptor>       define an entry            (help add / help name)
  ls [regex]             list entries by name
  ld [regex]             list entries by date (oldest first)
  keep <id>              save list row <id> (left column of ls/gen) to catalog
  mv <name> <folder>     move entry under <folder>  (folder `/` = top level)
  comment <name> [text]  set or clear the comment
  rm <name>              remove an entry

PASSWORDS
  enc <name|id>          show an entry's password
  enc ls|ld <regex>      show the matched entry's password (newest, for ld)
  gen[N] <name>          N variants; name ends G.. (all) or X.. (random) [N=10]
  pb <command>           run a command, copy its output to the clipboard
  pass <name> [pw]       cache a master/override for an entry's subtree
  unpass [name]          forget cached master (unpass / = root, unpass = all)
  correct <name>         trust this password's hash
  uncorrect <name>       untrust it

CATALOG
  dump                   print the catalog as `add …` lines
  save [target]          write it: file / key / - / |command   (help save)
  source <target>        load it: file / key / command|
  set <key> <value>      runtime config                          (help config)

OTHER
  help [topic]           this overview, or detail for one topic
  # text                 a comment (ignored)
  quit                   exit the REPL

An entry id is the number in the left column of `ls`/`ld`/`gen`; use it anywhere
a <name> is expected until the next listing. `ls`/`ld` match the name
case-insensitively as a regular expression.

MODES (the [len][mode] in a descriptor — `help modes` for examples)
  R six words (default)   N hyphenated   C CamelCase   D decimal
  H hex   B base64        U.. = UPPERCASE variant (UR UN UH UB)
  <len> truncates the result to <len> characters (e.g. 20R, 12UB)";

const HELP_NAME: &str = "\
descriptor — used by `add`, `gen`, and every line of the dump/`save` format:

  [prefix] <name> [<len>]<mode> [<seq>] [<date>] [comment] [^parent]

  prefix    optional literal glued onto the output, e.g. #W9 (to satisfy a
            \"must contain a symbol/digit\" rule). Part of the generated value.
  name      entry key, no spaces; feeds the S/KEY hash.
  len       optional: truncate the output to <len> characters.
  mode      output form, default R (see `help modes`).
  seq       S/KEY sequence count, default 99.
  date      YYYY-MM-DD or `now`, default now. `ld` sorts by it; `enc ld <re>`
            takes the newest.
  comment   free text (login, URL, notes).
  ^parent   place this entry under <parent>: the parent's generated password
            becomes the master for this entry (chained). The root master is the
            entry `/`, prompted once or set with `pass /`.

  examples
    add github
    add github 20UR 2024-01-01 me@example.com ^work
    add #W9 ableton 99 2020-12-09 license note";

const HELP_MODES: &str = "\
modes — output form; prefix with a length to truncate (e.g. 20R). For one fixed
entry + master:

  R    six words, spaces       ross beau week held yoga anti     (default)
  UR   R, upper-cased          ROSS BEAU WEEK HELD YOGA ANTI
  N    hyphenated              ross-beau-week-held-yoga-anti
  UN   N, upper-cased          ROSS-BEAU-WEEK-HELD-YOGA-ANTI
  C    CamelCase, no spaces    RossBeauWeekHeldYogaAnti
  H    hex                     e5a38ad29afc3fcb        (UH = upper)
  B    base64                  0oqj5cs//Jo             (UB = upper)
  D    decimal words           1684 680 1995 1203 2046 619
  <len><mode>  truncate to <len> characters, e.g. 20R, 12UB, 6D.
  A prefix (e.g. #Q3a) is prepended to every form.";

const HELP_LS: &str = "\
ls [regex]   list catalog entries sorted by name.
ld [regex]   list catalog entries sorted by date, oldest first (newest last).

The regex (default `.`) matches case-insensitively against the name, the full
descriptor, and the comment. Each row gets an id (left column) reusable as a
<name> in enc/keep/mv/etc. until the next listing. Under `pb`/`enc` the listing
collapses to bare names (newest last for `ld`) — see `help pb`, `help enc`.";

const HELP_ENC: &str = "\
enc <name|id>       show an entry's generated password (to stdout).
enc ls <regex>      encode the last entry of `ls <regex>` (last by name).
enc ld <regex>      encode the last entry of `ld <regex>` (newest by date).

A literal name or list id is tried first; otherwise the argument is run as an
`ls`/`ld` search and the last match is encoded. On more than one match a `note:`
reports the count and the chosen entry. To require a unique match instead:

  set hel_enc_strict 1     # multiple matches become an error

Password goes to stdout, notes/warnings to stderr — so `pb enc …` copies only
the password. Only `ls`/`ld` are valid as the search form (enc never runs a
state-changing command). See `help pb`.";

const HELP_GEN: &str = "\
gen[N] <name>   show N variants of an entry, sorted by password length.

If <name> ends in one or more `G`, every numbered variant is generated
(testG -> test1..test9, testGG -> test1..test99). If it ends in `X`, one random
numbered variant is produced. Otherwise the single entry is shown. N defaults to
10. Results populate the id list (left column) for `keep`/`enc`.";

const HELP_PB: &str = "\
pb <command>   run <command> and copy its stdout to the clipboard.

  pb enc github           copy github's password
  pb enc ld micro.*exa    copy the newest matching entry's password
  pb ld micro             copy the matching names (newest last)

If `hel_pb` (or $HEL_PB) is set, that one command receives the data on stdin.
Otherwise hel copies to every clipboard found on PATH — pbcopy, wl-copy, xclip,
xsel, and tmux inside a session — so a bare `pb` works on macOS, Wayland, X11
and over SSH/tmux with no configuration. With none found, the data is left on
stdout.";

const HELP_PASS: &str = "\
pass <name> [pw]   cache a master for <name> and its subtree for this session.
                   `pass <name>` prompts; `pass <name> pw` sets it inline. Use
                   `pass /` for the ROOT master used by top-level entries.
                   Nothing is written to disk.
unpass [name]      forget a cached master: `unpass <name>` one, `unpass /` the
                   root, `unpass` (no argument) all of them.";

const HELP_CORRECT: &str = "\
correct <name>     remember this password's hash as trusted, in ~/.hel_correct
                   (names + hashes only, never secrets). Later, hel warns if a
                   freshly derived password does not match a trusted hash —
                   catching a mistyped master before you use the result.
uncorrect <name>   drop that trust.";

const HELP_KEEP: &str = "\
keep <id>   copy list row <id> (the left column of `ls`/`ld`/`gen`) into the
            catalog as a permanent entry. Useful after `gen` to keep one of the
            generated variants.";

const HELP_MV: &str = "\
mv <name> <folder>   move <name> under <folder> so <folder>'s password becomes
                     its master (chained derivation). Use `/` as <folder> to
                     move the entry back to the top level. This re-parents; it
                     does not rename — to rename, `rm` and `add` again.";

const HELP_RM: &str = "\
rm <name>   remove an entry from the catalog. Other entries are unaffected;
            `save` to persist the change.";

const HELP_COMMENT: &str = "\
comment <name> [text]   set the entry's comment to <text>, or clear it when no
                        text is given. The comment is searched by `ls`/`ld` and
                        shown in listings.";

const HELP_CATALOG: &str = "\
The catalog is just a script of `add …` lines.

dump             print the whole catalog to the screen.
save [target]    persist it. <target>:
                   (omitted)   hel_dump / $HEL_DUMP / ~/.hel_dump
                   <path>      a file
                   -           print to screen (same as dump)
                   |<command>  pipe the dump into <command>'s stdin
                 A diff (< removed, > added) vs the last load/save is shown.
source <target>  load a catalog. <target>:
                   <path>      a file (a localStorage key in the wasm build)
                   <command>|  run <command>, load its stdout as a script
Notion: `save |hel store notion:<page>` and `source hel load notion:<page>|`
store the catalog in a Notion code block (token via `set hel_notion_token …`).";

const HELP_CONFIG: &str = "\
set <key> <value>   set a runtime config value (typically from ~/.helrc). Keys
                    are case-insensitive and each also reads the UPPER-CASE env
                    var of the same name.

  hel_pb            clipboard command for `pb` (else the built-in multi-sink copy)
  hel_enc_strict    1/true/on -> `enc ls|ld <re>` errors when >1 entry matches
  hel_dump          default `save`/`dump` target
  hel_notion_token  token for the `hel store`/`hel load` Notion subcommands";

const HELP_FILES: &str = "\
files and environment
  ~/.helrc         startup script, run once          $HEL_INIT
  ~/.hel_history   REPL history                        $HEL_HISTORY
  ~/.hel_dump      default catalog file                $HEL_DUMP
  ~/.hel_correct   trusted password hashes             $HEL_CORRECT
  prompt string                                        $HEL_PROMPT
Non-interactive subcommands (run before the REPL, no ~/.helrc, no prompt):
  hel store <notion:ref>    read a catalog on stdin and write it to Notion
  hel load  <notion:ref>    print the catalog stored in a Notion page";

const HELP_QUIT: &str = "\
quit   exit the REPL (also Ctrl-D / EOF). The catalog is NOT saved automatically
       — `save` first if you have unsaved changes.";

impl<'a> LKEval<'a> {
    /// `help [topic]`: the grouped command overview, or detail for one command
    /// or concept. Output goes to stdout; an unknown topic errors on stderr.
    pub fn cmd_help(&self, out: &LKOut, topic: &Option<String>) {
        let text: &str = match topic.as_deref().map(str::to_lowercase).as_deref() {
            None => HELP_OVERVIEW,
            Some("add" | "name" | "desc" | "descriptor" | "entry" | "parent") => HELP_NAME,
            Some("modes" | "mode") => HELP_MODES,
            Some("ls" | "ld" | "list") => HELP_LS,
            Some("enc") => HELP_ENC,
            Some("gen") => HELP_GEN,
            Some("pb") => HELP_PB,
            Some("pass" | "unpass") => HELP_PASS,
            Some("correct" | "uncorrect") => HELP_CORRECT,
            Some("keep") => HELP_KEEP,
            Some("mv" | "move") => HELP_MV,
            Some("rm" | "remove") => HELP_RM,
            Some("comment") => HELP_COMMENT,
            Some("dump" | "save" | "source" | "catalog") => HELP_CATALOG,
            Some("set" | "config") => HELP_CONFIG,
            Some("files" | "file" | "env" | "environment") => HELP_FILES,
            Some("quit" | "exit") => HELP_QUIT,
            Some(other) => {
                out.e(format!(
                    "error: no help for {}; try `help` for the command list",
                    other
                ));
                return;
            }
        };
        out.o(text.to_string());
    }

    pub fn get_password(&self, name: &String) -> Option<PasswordRef> {
        match self.state.lock().borrow().ls.get(name) {
            Some(pwd) => Some(pwd.clone()),
            None => match self.state.lock().borrow().db.get(name) {
                Some(pwd) => Some(pwd.clone()),
                None => None,
            },
        }
    }

    pub fn read_master(&self, out: &LKOut, pwd: PasswordRef, read: bool) -> Option<String> {
        if read {
            match self.read_master(&out, pwd.clone(), false) {
                Some(p) => {
                    return Some(p);
                }
                None => (),
            }
        }
        let parent = match &pwd.lock().borrow().parent {
            Some(p) => p.lock().borrow().name.to_string(),
            None => "/".to_string(),
        };
        let secret = match self.state.lock().borrow().secrets.get(&parent) {
            Some(p) => Some(p.clone()),
            None => None,
        };
        match (pwd.lock().borrow().parent.clone(), secret) {
            (_, Some(s)) => Some(s.to_string()),
            (None, None) => {
                if read {
                    let name = "/".to_string();
                    match (self.read_password)(name.to_string()) {
                        Ok(password) => {
                            if password.len() > 0 {
                                self.cmd_correct(&out, &name, true, Some(password.clone()));
                                self.state.lock().borrow_mut().secrets.insert(name, password.clone());
                                Some(password)
                            } else { None }
                        }
                        Err(_) => None,
                    }
                } else {
                    None
                }
            }
            (Some(pn), None) => {
                let password = if read {
                    (self.read_password)(pn.lock().borrow().name.to_string()).ok()
                } else {
                    None
                };
                if password.is_some() && password.as_ref().unwrap().len() > 0 {
                    let name = pn.lock().borrow().name.to_string();
                    self.cmd_correct(&out, &name, true, Some(password.as_ref().unwrap().clone()));
                    self.state.lock().borrow_mut().secrets.insert(name, password.as_ref().unwrap().clone());
                    password
                } else {
                    match self.read_master(&out, pn.clone(), read) {
                        Some(master) => {
                            let password = pn.lock().borrow().encode(master.as_str());
                            let name = pn.lock().borrow().name.to_string();
                            self.cmd_correct(&out, &name, true, Some(password.to_string()));
                            self.state.lock().borrow_mut().secrets.insert(name, password.clone());
                            Some(password)
                        }
                        None => None,
                    }
                }
            }
        }
    }

    pub fn cmd_add(&self, out: &LKOut, name: &PasswordRef) {
        let state_cell = self.state.lock();
        let mut state = state_cell.borrow_mut();
        let mut fix = false;
        {
            let pwname = &name.lock().borrow().name.to_string();
            if let Some(oldname) = state.db.get(pwname) {
                if name.lock().borrow().to_string() != oldname.lock().borrow().to_string() {
                    out.e(format!("error: password {} already exist", pwname));
                }
            } else {
                state.db.insert(pwname.to_string(), name.clone());
                fix = true;
            }
        }
        if fix {
            state.fix_hierarchy();
        }
    }

    pub fn cmd_keep(&self, out: &LKOut, name: &Name) {
        let pwd = match self.state.lock().borrow().ls.get(name) {
            Some(pwd) => pwd.clone(),
            None => {
                out.e(format!("error: {} not found", name));
                return;
            }
        };
        self.cmd_add(&out, &pwd);
    }

    pub fn cmd_mv(&self, out: &LKOut, name: &String, folder: &String) {
        match self.get_password(name) {
            Some(pwd) => {
                if folder == "/" {
                    pwd.lock().borrow_mut().parent = None
                } else {
                    match self.get_password(folder) {
                        Some(fld) => {
                            pwd.lock().borrow_mut().parent = Some(fld.clone());
                            fix_password_recursion(pwd.clone());
                        }
                        None => out.e(format!("error: folder {} not found", folder)),
                    }
                }
            }
            None => out.e(format!("error: password with name {} not found", name)),
        }
    }

    pub fn cmd_pass(&self, out: &LKOut, name: &String, pass: &Option<String>) {
        match self.get_password(name) {
            Some(p) => {
                let pwd = match pass {
                    Some(pp) => pp.to_string(),
                    None => (self.read_password)(p.lock().borrow().name.to_string()).unwrap(),
                };
                self.cmd_correct(&out, &p.lock().borrow().name, true, Some(pwd.clone()));
                self.state.lock().borrow_mut().secrets.insert(p.lock().borrow().name.to_string(), pwd);
            }
            None => {
                if name == "/" {
                    let pwd = match pass {
                        Some(pp) => pp.to_string(),
                        None => (self.read_password)("/".to_string()).unwrap(),
                    };
                    self.cmd_correct(&out, &"/".to_string(), true, Some(pwd.clone()));
                    self.state.lock().borrow_mut().secrets.insert("/".to_string(), pwd);
                } else {
                    out.e(format!("error: password with name {} not found", name));
                }
            }
        }
    }

    pub fn cmd_comment(&self, out: &LKOut, name: &String, comment: &Option<String>) {
        match self.get_password(name) {
            Some(pwd) => {
                pwd.lock().borrow_mut().comment = match comment {
                    Some(c) => Some(c.to_string()),
                    None => None,
                }
            }
            None => out.e("error: password not found".to_string()),
        }
    }

    pub fn cmd_enc(&self, out: &LKOut, name: &String) -> Option<(String, String)> {
        let root_folder = "/".to_string();
        let (name, pass) = if name == "/" && self.state.lock().borrow().secrets.contains_key(&root_folder) {
            (root_folder.to_string(), self.state.lock().borrow().secrets.get(&root_folder).unwrap().to_string())
        } else {
            let pwd = match self.get_password(name) {
                Some(p) => p.clone(),
                None => {
                    out.e(format!("error: name {} not found", name));
                    return None;
                }
            };
            let name = pwd.lock().borrow().name.to_string();
            if self.state.lock().borrow().secrets.contains_key(&name) {
                (name.clone(), self.state.lock().borrow().secrets.get(&name).unwrap().to_string())
            } else {
                match self.read_master(&out, pwd.clone(), true) {
                    Some(sec) => (name.clone(), pwd.lock().borrow().encode(sec.as_str())),
                    None => {
                        out.e(format!("error: master for {} not found", name));
                        return None;
                    }
                }
            }
        };
        if out.active() {
            out.o(pass.clone());
            self.cmd_correct(&out, &name, true, Some(pass.clone()));
        }
        Some((name, pass))
    }

    /// `enc <arg>`: pick which entry to encode, then encode it. Precedence keeps
    /// the historical `enc <name>` / `enc <id>` behavior working even when a name
    /// collides with a command keyword:
    ///   1. `arg` resolves to a catalog entry or `ls` id -> encode it.
    ///   2. else `arg` parses as an `ls`/`ld` search -> evaluate it capturing
    ///      (so the listing yields bare names), take the LAST non-empty line as
    ///      the entry name (newest for `ld`), and encode that. With >1 match,
    ///      `set hel_enc_strict 1` errors instead of taking the newest.
    ///   3. else -> error.
    /// Only `ls`/`ld` are accepted as producers: enc must never execute a
    /// mutating command (e.g. `rm`) as a side effect of resolving a name.
    pub fn cmd_enc_arg(&self, out: &LKOut, arg: &String) {
        if self.get_password(arg).is_some() {
            self.cmd_enc(out, arg);
            return;
        }
        let cmd = match command_parser::cmd(arg) {
            Ok(c) if matches!(c, Command::Ls(_) | Command::Ld(_)) => c,
            _ => {
                out.e(format!("error: name {} not found", arg));
                return;
            }
        };
        let print = LKEval::new(self.rl.clone(), cmd, self.state.clone(), self.read_password)
            .with_capture(true)
            .eval();
        // Surface the producer's own diagnostics (e.g. a bad regex).
        print.out.copy_err(out);
        let names: Vec<String> = print
            .out
            .data()
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();
        let name = match names.last() {
            Some(n) => n.clone(),
            None => {
                out.e(format!("error: no entry matches {}", arg));
                return;
            }
        };
        if names.len() > 1 {
            if config_flag("hel_enc_strict") {
                out.e(format!(
                    "error: {} entries match {}; refusing under hel_enc_strict (narrow the pattern or use an id)",
                    names.len(),
                    arg
                ));
                return;
            }
            out.e(format!("note: {} names matched; encoding last: {}", names.len(), name));
        }
        self.cmd_enc(out, &name);
    }

    pub fn cmd_pb(&self, out: &LKOut, command: &String) {
        match command_parser::cmd(command) {
            Ok(cmd) => {
                // capture=true so a wrapped `ls`/`ld` yields bare names.
                let print = LKEval::new(self.rl.clone(), cmd, self.state.clone(), self.read_password)
                    .with_capture(true)
                    .eval();
                let data = print.out.data();
                print.out.copy_err(&out);
                if data.len() > 0 {
                    // Clipboard copy shells out to pbcopy/xclip/tmux: native only.
                    // In the browser the page provides a Copy button instead.
                    #[cfg(target_arch = "wasm32")]
                    {
                        hel_clipboard_write(&data);
                        out.o(format!("Copied {} characters to the clipboard", data.chars().count()));
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        // Explicit override (`set hel_pb` or $HEL_PB): one command,
                        // as before. Otherwise fan out to every present clipboard.
                        match config_get("hel_pb").and_then(|s| get_cmd_args_from_command(&s).ok()) {
                            Some((copy_command, copy_cmd_args)) => {
                                match call_cmd_with_input(&copy_command, &copy_cmd_args, &data) {
                                    Ok(s) if s.len() > 0 => {
                                        out.o(format!(
                                            "Copied output with the command {}, and got following output:",
                                            copy_command
                                        ));
                                        out.o(s.trim().to_string());
                                    }
                                    Ok(_) => out.o(format!("Copied output with command {}", copy_command)),
                                    Err(e) => out.e(format!("error: failed to copy: {}", e.to_string())),
                                };
                            }
                            None => {
                                let report = crate::utils::copy_to_clipboards(&data);
                                if !report.ok.is_empty() {
                                    out.o(format!(
                                        "Copied {} chars to clipboard ({})",
                                        data.chars().count(),
                                        report.ok.join(", ")
                                    ));
                                } else {
                                    // No sink and no override: never drop the payload.
                                    out.o(data.clone());
                                    out.e("error: no clipboard available; data left on stdout".to_string());
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => out.e(format!("error: failed to parse command {}: {}", command, e.to_string())),
        };
    }

    pub fn cmd_source(&self, out: &LKOut, source: &String) -> bool {
        out.o(format!("source {}", source));
        let script: String;
        if source.trim().ends_with("|") {
            // Loading from a command's output needs a subprocess: native only.
            #[cfg(target_arch = "wasm32")]
            {
                out.e("error: pipe source is not available in the browser".to_string());
                return false;
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let (cmd, args) = match get_cmd_args_from_command(source.trim().trim_end_matches('|')) {
                    Ok(c) => c,
                    Err(e) => {
                        out.e(format!("error: failed to parse command {:?}: {}", source, e.to_string()));
                        return false;
                    }
                };
                script = match call_cmd_with_input(&cmd, &args, "") {
                    Ok(o) => o,
                    Err(e) => {
                        out.e(format!("error: failed to execute command {}: {}", cmd, e.to_string()));
                        return false;
                    }
                };
            }
        } else {
            // File path on native; localStorage key in the browser.
            let key = shellexpand::full(source).unwrap().into_owned();
            script = match crate::storage::read(&key) {
                Ok(script) => script,
                Err(e) => {
                    out.e(format!("error: failed to read {}: {}", source, e.to_string()));
                    return false;
                }
            };
        }
        match command_parser::script(&script) {
            Ok(cmd_list) => {
                for cmd in cmd_list {
                    let print = LKEval::new(self.rl.clone(), cmd, self.state.clone(), password).eval();
                    print.out.copy(&out);
                    if print.quit {
                        return true;
                    }
                }
            }
            Err(e) => {
                out.e(format!("error: {}", e.to_string()));
            }
        };
        // Baseline for the next save diff: the just-loaded state is the new
        // "previously persisted" reference.
        let snapshot = self.serialize_db();
        self.state.lock().borrow_mut().last_dump = Some(snapshot);
        false
    }

    /// All entries serialized as sorted `add …` lines (the dump format).
    fn serialize_db(&self) -> String {
        let mut vals: Vec<PasswordRef> = self.state.lock().borrow().db.values().cloned().collect();
        vals.sort_by(|a, b| a.lock().borrow().name.cmp(&b.lock().borrow().name));
        vals.iter()
            .map(|v| format!("add {}", v.lock().borrow().to_string()))
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Emit a `< removed` / `> added` line diff of `new` against the last saved/
    /// loaded snapshot (set-based, so dump ordering doesn't matter). No-op until
    /// a baseline exists.
    fn show_dump_diff(&self, out: &LKOut, new: &str) {
        let prev = self.state.lock().borrow().last_dump.clone();
        if let Some(prev) = prev {
            use std::collections::BTreeSet;
            let p: BTreeSet<&str> = prev.lines().filter(|l| !l.is_empty()).collect();
            let n: BTreeSet<&str> = new.lines().filter(|l| !l.is_empty()).collect();
            for l in p.difference(&n) {
                out.o(format!("< {}", l));
            }
            for l in n.difference(&p) {
                out.o(format!("> {}", l));
            }
        }
    }

    pub fn cmd_set(&self, out: &LKOut, key: &String, value: &String) {
        config_set(key, value);
        // Confirm without echoing the value — it may be a secret.
        out.o(format!("set {}", key.to_lowercase()));
    }

    pub fn cmd_dump(&self, out: &LKOut, script: &Option<String>) {
        // Default dump target: `set hel_dump …` > $HEL_DUMP > ~/.hel_dump.
        let script: String = match script {
            Some(p) => p.clone(),
            None => config_get("hel_dump").unwrap_or_else(|| DUMP_FILE.to_str().unwrap().to_string()),
        };
        let script = shellexpand::full(&script).unwrap().into_owned();
        if script.trim().starts_with("|") {
            // Piping the dump to a command needs a subprocess: native only.
            #[cfg(target_arch = "wasm32")]
            {
                out.e("error: pipe dump is not available in the browser".to_string());
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let (cmd, args) = match get_cmd_args_from_command(script.trim().trim_start_matches('|')) {
                    Ok(c) => c,
                    Err(e) => {
                        out.e(format!("error: failed to parse command {:?}: {}", script, e.to_string()));
                        return;
                    }
                };
                let data = self.serialize_db();
                self.show_dump_diff(out, &data);
                let output = match call_cmd_with_input(&cmd, &args, data.as_str()) {
                    Ok(o) => o,
                    Err(e) => {
                        out.e(format!("error: failed to execute command {}: {}", cmd, e.to_string()));
                        return;
                    }
                };
                self.state.lock().borrow_mut().last_dump = Some(data);
                if output.len() > 0 {
                    out.e(format!("Passwords saved to command {} and got following output:", cmd));
                    out.o(output);
                } else {
                    out.o(format!("Passwords saved to command {}", cmd));
                }
            }
        } else if script.trim() == "-" {
            let mut vals = (&self.state.lock().borrow().db).values().map(|v| v.clone()).collect::<Vec<PasswordRef>>();
            vals.sort_by(|a, b| a.lock().borrow().name.cmp(&b.lock().borrow().name));
            for pwd in vals {
                out.o(format!("add {}", pwd.lock().borrow().to_string()))
            }
        } else {
            // File path on native; localStorage key in the browser.
            let data = self.serialize_db();
            self.show_dump_diff(out, &data);
            // Trailing newline to match the historical file format (writeln per line).
            let body = if data.is_empty() { String::new() } else { format!("{}\n", data) };
            match crate::storage::write(&script, &body) {
                Ok(()) => {
                    self.state.lock().borrow_mut().last_dump = Some(data);
                    out.o(format!("Passwords saved to {}", script));
                }
                Err(e) => out.e(format!("error: failed to dump passwords to {}: {}", script, e.to_string())),
            };
        }
    }

    pub fn cmd_ls<F>(&self, out: &LKOut, filter: String, sort_by: F)
    where
        F: Fn(&PasswordRef, &PasswordRef) -> std::cmp::Ordering,
    {
        // Case-insensitive search; an explicit (?-i) in the filter still wins.
        let re = match Regex::new(&format!("(?i){}", filter)) {
            Ok(re) => re,
            Err(e) => {
                out.e(format!("error: failed to parse re: {:?}", e));
                return;
            }
        };
        let mut tmp: Vec<PasswordRef> = vec![];
        for (_, name) in &self.state.lock().borrow().db {
            if re.find(&name.lock().borrow().to_string()).is_some() {
                tmp.push(name.clone());
            } else if re.find(&name.lock().borrow().name).is_some() {
                tmp.push(name.clone());
            } else if name.lock().borrow().comment.is_some()
                && re.find(&name.lock().borrow().comment.as_ref().unwrap()).is_some()
            {
                tmp.push(name.clone());
            }
        }
        tmp.sort_by(|a, b| a.lock().borrow().name.cmp(&b.lock().borrow().name));
        tmp.sort_by(sort_by);
        self.state.lock().borrow_mut().ls.clear();
        let mut counter = 1;
        for pwd in tmp {
            let key = Radix::new(counter, 36).unwrap().to_string();
            counter += 1;
            self.state.lock().borrow_mut().ls.insert(key.clone(), pwd.clone());
            // Captured (under `pb`/`enc`): emit just the entry name — a unique db
            // key that re-resolves via get_password, so it can feed `enc` and
            // makes `pb ls`/`pb ld` copy clean names. Interactive: rich rows.
            if self.capture {
                out.o(pwd.lock().borrow().name.to_string());
            } else {
                out.o(format!("{:>3} {}", key, pwd.lock().borrow().to_string()));
            }
        }
    }

    pub fn cmd_correct(&self, out: &LKOut, name: &String, correct: bool, check: Option<String>) {
        let (check, pwd) = match check {
            Some(p) => (true, Some((name.to_string(), p))),
            None => (
                false,
                self.cmd_enc(
                    &LKOut::from_lkout(
                        None,
                        match &out.err {
                            Some(e) => Some(e.clone()),
                            None => None,
                        },
                    ),
                    &name,
                ),
            ),
        };
        let (name, pwd) = match pwd {
            Some(v) => v,
            None => return,
        };
        fn load_lines() -> std::io::Result<HashSet<String>> {
            let content = crate::storage::read(CORRECT_FILE.to_str().unwrap())?;
            let mut lines = HashSet::new();
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    lines.insert(line.to_owned());
                }
            }
            Ok(lines)
        }
        let mut data = match load_lines() {
            Ok(d) => d,
            Err(_) => HashSet::new(),
        };
        let mut sha1 = Sha1::new();
        sha1.update(name.to_string());
        sha1.update(&pwd);
        let encpwd = format!("{:x}", sha1.finalize());
        if check {
            if data.contains(&encpwd) {
                return;
            }
            out.e(format!("warning: password {} is not marked as correct", name));
            return;
        }
        if correct {
            if data.contains(&encpwd) {
                return;
            }
            data.insert(encpwd);
        } else {
            if !data.contains(&encpwd) {
                return;
            }
            data.remove(&encpwd);
        }
        fn save_lines(data: &HashSet<String>) -> std::io::Result<()> {
            let mut content = String::new();
            for entry in data {
                content.push_str(entry);
                content.push('\n');
            }
            crate::storage::write(CORRECT_FILE.to_str().unwrap(), &content)
        }
        match save_lines(&data) {
            Ok(()) => out.o(format!(
                "Hash of the password {} {} {}",
                name,
                if correct { "remembered to" } else { "removed from" },
                CORRECT_FILE.to_str().unwrap()
            )),
            Err(e) => out.e(format!("error: failed to write: {}", e.to_string())),
        };
    }

    pub fn cmd_gen(&self, out: &LKOut, num: &u32, name: &PasswordRef) {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"^.+?(G+|X+)$").unwrap();
        }
        let num: usize = (*num).try_into().unwrap();
        let pwd = name.lock();
        let mut genpwds: Vec<PasswordRef> = Vec::new();
        match RE.captures(pwd.borrow().name.as_ref()) {
            Some(caps) => {
                let gen = &caps[1];
                if gen.starts_with("G") {
                    let name = pwd.borrow().name.trim_end_matches('G').to_string();
                    for num in 1..10_u32.pow(gen.len().try_into().unwrap()) {
                        let npwd = Password::from_password_ref(&pwd.borrow());
                        npwd.lock().borrow_mut().name = format!("{}{}", name, num).to_string();
                        genpwds.push(npwd);
                    }
                } else {
                    let name = pwd.borrow().name.trim_end_matches('X').to_string();
                    let num = rnd::range(1, 10_u32.pow(gen.len().try_into().unwrap()));
                    let npwd = Password::from_password_ref(&pwd.borrow());
                    npwd.lock().borrow_mut().name = format!("{}{}", name, num).to_string();
                    genpwds.push(npwd);
                }
            }
            None => {
                let npwd = Password::from_password_ref(&pwd.borrow());
                genpwds.push(npwd);
            }
        }
        self.state.lock().borrow_mut().ls.clear();
        let mut counter = 1;
        let mut lspwds: Vec<(PasswordRef, String)> = Vec::new();
        for num in 0..genpwds.len() {
            let pwd = genpwds[num].clone();
            let key = Radix::new(counter, 36).unwrap().to_string();
            counter += 1;
            self.state.lock().borrow_mut().ls.insert(key.to_string(), pwd.clone());
            lspwds.push((pwd, key));
        }
        self.state.lock().borrow().fix_hierarchy();
        let mut err = match &out.err {
            Some(e) => Some(e.clone()),
            None => None,
        };
        let mut encpwds: Vec<(PasswordRef, String)> = Vec::new();
        for (pwd, key) in lspwds {
            let pass = match self.cmd_enc(&LKOut::from_lkout(None, err), &key) {
                Some((name, pass)) => {
                    if name != pwd.lock().borrow().name {
                        panic!("INTERNAL_ERROR: wrong name found: {} != {}", name, pwd.lock().borrow().name);
                    };
                    pass
                }
                None => {
                    out.e(format!("error: failed to encrypt password"));
                    return;
                }
            };
            err = None;
            encpwds.push((pwd.clone(), pass));
        }
        encpwds.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        self.state.lock().borrow_mut().ls.clear();
        let mut counter = 1;
        out.o(format!("{:>3} {:>36} {:>4}       {}", "", "Password", "Len", "Name"));
        for num in (encpwds.len() - min(genpwds.len(), num))..encpwds.len() {
            let (pwd, pass) = (encpwds[num].0.clone(), encpwds[num].1.to_string());
            let key = Radix::new(counter, 36).unwrap().to_string();
            counter += 1;
            self.state.lock().borrow_mut().ls.insert(key.clone(), pwd.clone());
            out.o(format!("{:>3} {:>36} {:>4} {}", key, pass, pass.len(), pwd.lock().borrow().to_string()));
        }
    }
}

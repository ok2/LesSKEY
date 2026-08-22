use regex::Regex;
use sha1::{Digest, Sha1};
use std::cmp::min;
use std::collections::HashSet;

use crate::crypto::{self, TokenType};
use crate::parser::command_parser;
use crate::password::fix_password_recursion;
use crate::password::{is_plus_root, Name, Password, PasswordRef};
use crate::repl::LKEval;
use crate::structs::{config_flag, config_get, config_set, Command, LKOut, LsScope, Mode, Radix, CORRECT_FILE, DUMP_FILE};
use crate::totp;
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
  ls [-ncla] [regex]     list entries by name
  ld [-ncla] [regex]     list entries by date (oldest first)
  keep <id>              save list row <id> (left column of ls/gen) to catalog
  mv <name> <folder>     move entry under <folder>  (folder `/` = top level)
  comment <name> [text]  set or clear the comment
  rm <name>              remove an entry
  reset yes              drop the WHOLE catalog from memory (for a reimport)

PASSWORDS
  enc <name|id>          show an entry's password (a mode-T entry shows its code)
  enc <command>          encode the last name a command prints (ls/ld/gen)
  reveal <name>          decrypt an entry's inline #TOTP / !text blobs
  gen[N] <name>          N variants; name ends G.. (all) or X.. (random) [N=10]
  rnd[N] [descriptor]    gen with a pure-random master per row      (help rnd)
  pb <command>           run a command, copy its output to the clipboard
  pass [name] [pw]       cache a master/override for a subtree (pass = root /)
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
  T TOTP one-time code (RFC 6238; needs an inline #\"…\" seed, see `help add`)
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

  name markers (leading characters of the NAME, chosen by you):
    +name    an independent root: its password is ENTERED (`pass +name` or a
             prompt), never derived — the chain STOPS there, a blank prompt
             does not climb past it. Extra master passwords, compartmented
             subtrees; `/` is the unnamed default root with the same semantics.
    $name    unfolded subtree (combine as `+$name`): this entry and everything
             chained under it derives the full 160-bit UNFOLDED value (15 words
             instead of 6) — set once on a base, descendants inherit. Worth it
             under a root whose entered password is long (>64 bits).

  inline secrets — encrypted with a key derived from THIS entry and its master
  chain (so they unlock from the master + record, and inherit ^parent; edits to
  mode/prefix/length are safe, renames and seq/parent changes re-key):
    #\"<base32 | otpauth://…>\"   a TOTP seed; use with mode T, `enc` shows the code
    !\"<text>\"                    an encrypted note; read it back with `reveal`
  On add/comment these are sealed in place to `#<blob>`/`!<blob>` — the plaintext
  is never written to the catalog or history. `reveal <name>` decrypts them.

  examples
    add github
    add github 20UR 2024-01-01 me@example.com ^work
    add #W9 ableton 99 2020-12-09 license note
    add x totp T 99 now #\"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\" ^important";

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
  A prefix (e.g. #Q3a) is prepended to every form.
  In a `$` (unfolded) subtree the same modes render the full 160-bit value:
  15 words / 40 hex / 27 base64 digits instead of 6 / 16 / 11.";

const HELP_LS: &str = "\
ls [-ncla] [regex]   list catalog entries sorted by name.
ld [-ncla] [regex]   list catalog entries sorted by date, oldest first.

The regex (default `.`) matches case-insensitively; an inline (?-i) still wins.
The optional flag picks what it matches against:

  (none), -l   the whole descriptor line: prefix, name, length/mode, seq, date,
               comment and ^parent — so `^` anchors at the name, `$` at the end
               of the line, e.g. `ls ^ssh` = names starting with ssh.
  -n           the bare name only:      ls -n ^microsoft.*t$
  -c           the bare comment only:   ls -c ^ok@
  -a           any of the three, each anchored on its own — `^re` then hits a
               name start OR a comment start.

The flag counts only when a pattern follows it, so a bare `ls -n` searches for
the literal `-n`. Each row gets an id (left column) reusable as a <name> in
enc/keep/mv/etc. until the next listing. Under `pb`/`enc` the listing collapses
to bare names (newest last for `ld`) — see `help pb`, `help enc`.";

const HELP_ENC: &str = "\
enc <name|id>       show an entry's generated password (to stdout).
enc <command>       run <command> and encode the LAST name in its output:
                      enc ld <re>    newest entry matching <re>
                      enc ls <re>    last entry by name
                      enc gen <nm>   the variant `gen <nm>` would list last

A literal name or list id is tried first; otherwise the argument is run as a
command (like `pb`) and its last output line is taken as the entry name —
`ls`/`ld`/`gen` emit bare names when consumed this way. On more than one
candidate a `note:` reports the count and the chosen entry; to require a unique
result instead:

  set hel_enc_strict 1     # multiple candidates become an error

The password goes to stdout, notes/warnings to stderr, so `pb enc …` copies
only the password. For a mode-`T` entry, `enc` decrypts the inline seed and
prints the current TOTP code instead. See `help pb`, `help gen`, `help reveal`.";

const HELP_REVEAL: &str = "\
reveal <name>   decrypt and print an entry's inline blobs to stdout: a `#` TOTP
                token as its stored otpauth URI / secret, and any `!` token as
                its text. The key derives from the entry and its master chain
                (same as `enc`), so `pb reveal <name>` copies the plaintext.

Add secrets with `add`/`comment` using `#\"<base32|otpauth://…>\"` (TOTP, mode T)
or `!\"<text>\"`; they are encrypted in place and never stored in the clear.";

const HELP_GEN: &str = "\
gen[N] <name>   show N variants of an entry, sorted by password length.

If <name> ends in one or more `G`, every numbered variant is generated
(testG -> test1..test9, testGG -> test1..test99). If it ends in `X`, one random
numbered variant is produced. Otherwise the single entry is shown. N defaults to
10. Results populate the id list (left column) for `keep`/`enc`.

Under `pb`/`enc` it lists just the variant names: `pb gen tX` copies a random
variant's name, `pb enc gen tX` copies that variant's password.";

const HELP_RND: &str = "\
rnd[N] [descriptor]   like `gen`, but each candidate's MASTER is pure OS
                      randomness (160 fresh bits per row) instead of the
                      catalog master. Everything else follows the descriptor as
                      usual: mode/prefix/length, folded 6 words vs wide 15 by
                      the `$` name marker, `G`/`X` suffix expansion (testGG ->
                      test1..test99). A suffix-less name gives N independent
                      candidates; bare `rnd` defaults to `$rnd` (15 words).

Use it to mint a new ROOT password (`+base` / `+$base`): roots must not derive
from an existing master. A `$` candidate carries the full 160 bits (picking
your favourite of N costs only ~log2(N) bits); a folded one carries 64.
The shown passwords are one-off samples, never stored: `keep <id>` files only
the DESCRIPTOR, and `enc` on it derives under the real master as always.
`pb rnd1 …` copies one candidate.

  rnd             ten 15-word passphrases ($rnd, wide)
  rnd5 $vault     five wide candidates for a root password
  rnd3 site C     three folded CamelCase samples
  rnd1 x 20UB     one 20-char upper-base64 value (truncation trims entropy)";

const HELP_PB: &str = "\
pb <command>   run <command> and copy its stdout to the clipboard.

  pb enc github           copy github's password
  pb enc ld micro.*exa    copy the newest matching entry's password
  pb ld micro             copy the matching names (newest last)
  pb gen tX               copy a random variant's name

If `hel_pb` (or $HEL_PB) is set, that one command receives the data on stdin.
Otherwise hel copies to every clipboard found on PATH — pbcopy, wl-copy, xclip,
xsel, and tmux inside a session — so a bare `pb` works on macOS, Wayland, X11
and over SSH/tmux with no configuration. With none found, the data is left on
stdout.";

const HELP_PASS: &str = "\
pass [name] [pw]   cache a master for <name> and its subtree for this session.
                   `pass <name>` prompts; `pass <name> pw` sets it inline. A bare
                   `pass` (or `pass /`) is the ROOT master used by top-level entries.
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

const HELP_RESET: &str = "\
reset yes   drop the WHOLE in-memory catalog (every entry), e.g. before
            reimporting with `source`. Nothing saved is touched until the next
            `save`; cached masters (`pass`) and correct-hashes are kept, so a
            reimport seals inline secrets without re-prompting. A bare `reset`
            only prints this confirmation hint.";

const HELP_CATALOG: &str = "\
The catalog is just a script of `add …` lines.

dump             print the whole catalog to the screen.
save [target]    persist it. <target>:
                   (omitted)   hel_dump / $HEL_DUMP / ~/.hel_dump
                   <path>      a file
                   -           print to screen (same as dump)
                   |<command>  pipe the dump into <command>'s stdin
                 The full diff vs the first load / last save is always shown
                 (< removed, > added; later `source`s count as unsaved changes;
                 `no changes since last load/save` when clean).
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
            Some("modes" | "mode" | "totp") => HELP_MODES,
            Some("ls" | "ld" | "list") => HELP_LS,
            Some("enc") => HELP_ENC,
            Some("reveal") => HELP_REVEAL,
            Some("gen") => HELP_GEN,
            Some("rnd" | "random") => HELP_RND,
            Some("pb") => HELP_PB,
            Some("pass" | "unpass") => HELP_PASS,
            Some("correct" | "uncorrect") => HELP_CORRECT,
            Some("keep") => HELP_KEEP,
            Some("mv" | "move") => HELP_MV,
            Some("rm" | "remove") => HELP_RM,
            Some("reset") => HELP_RESET,
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
        if let Some(pwd) = self.state.lock().borrow().ls.get(name) {
            return Some(pwd.clone());
        }
        if let Some(pwd) = self.state.lock().borrow().db.get(name) {
            return Some(pwd.clone());
        }
        // `gen` variants live only in the `ls` map under a numeric id (not in
        // `db`); also resolve them by entry name, so `enc <variant>` and
        // `enc gen …` (which yields a variant name) can re-encode them.
        self.state.lock().borrow().ls.values().find(|p| p.lock().borrow().name == *name).cloned()
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
        // A `+` entry is an independent root: its "master" IS its own entered
        // password (like `/`), never a derivation — any ^parent is ignored.
        let self_name = pwd.lock().borrow().name.to_string();
        if is_plus_root(&self_name) {
            if let Some(s) = self.state.lock().borrow().secrets.get(&self_name).cloned() {
                return Some(s);
            }
            if !read {
                return None;
            }
            return match (self.read_password)(self_name.to_string()) {
                Ok(password) if !password.is_empty() => {
                    self.cmd_correct(&out, &self_name, true, Some(password.clone()));
                    self.state.lock().borrow_mut().secrets.insert(self_name, password.clone());
                    Some(password)
                }
                _ => {
                    out.e(format!(
                        "error: {} is an independent root: enter its password or set it with `pass {}`",
                        self_name, self_name
                    ));
                    None
                }
            };
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
                } else if is_plus_root(&pn.lock().borrow().name) {
                    // The chain STOPS at a `+` root: it is not derived from any
                    // further base, so a blank entry cannot climb past it.
                    if read {
                        let name = pn.lock().borrow().name.to_string();
                        out.e(format!(
                            "error: {} is an independent root: enter its password or set it with `pass {}`",
                            name, name
                        ));
                    }
                    None
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
                // The stored entry always wins; an `add` never overwrites. An
                // exact re-import (same canonical line) is silently ignored, so
                // `source`-ing a dump you already have stays quiet. A DIFFERING
                // line is surfaced as a dump-diff-style pair — `<` stored/kept,
                // `>` incoming/ignored — so a merge shows exactly what changed;
                // apply it deliberately via `rm` + re-add.
                let old = oldname.lock().borrow().to_string();
                let new = name.lock().borrow().to_string();
                if new != old {
                    out.o(format!("< {}", old.trim()));
                    out.o(format!("> {}", new.trim()));
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
                // Roots take a secret without a catalog entry: `/` always did;
                // a `+` root's password is likewise entered, not derived, so
                // `pass +vault …` may precede loading the catalog it anchors.
                if name == "/" || is_plus_root(name) {
                    let pwd = match pass {
                        Some(pp) => pp.to_string(),
                        None => (self.read_password)(name.to_string()).unwrap(),
                    };
                    self.cmd_correct(&out, name, true, Some(pwd.clone()));
                    self.state.lock().borrow_mut().secrets.insert(name.to_string(), pwd);
                } else {
                    out.e(format!("error: password with name {} not found", name));
                }
            }
        }
    }

    /// `reset yes`: drop the WHOLE in-memory catalog (db + listing) for a clean
    /// reimport. Cached `pass` secrets and correct-hashes are kept, so a
    /// following `source` seals inline secrets without re-prompting; nothing
    /// saved (file / Notion / localStorage) changes until the next `save`.
    pub fn cmd_reset(&self, out: &LKOut, confirm: &Option<Name>) {
        if confirm.as_deref() != Some("yes") {
            out.e("reset drops the WHOLE in-memory catalog; confirm with `reset yes` (the saved catalog stays until `save`)".to_string());
            return;
        }
        let n = {
            let cell = self.state.lock();
            let mut state = cell.borrow_mut();
            let n = state.db.len();
            state.db.clear();
            state.ls.clear();
            n
        };
        out.o(format!("dropped {} entries; the in-memory catalog is empty", n));
        out.e("note: cached masters kept (`unpass` clears them); `source <file>` to reimport, `save` to persist".to_string());
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
        // `/` and a `+` name are ROOTS: their password is entered, never derived, and
        // they need no catalog entry at all. When there is none, the cached `pass`
        // value IS the answer — hand it back instead of hunting for an entry.
        let bare_root = (name == "/" || is_plus_root(name)) && self.get_password(name).is_none();
        if bare_root && !self.state.lock().borrow().secrets.contains_key(name) {
            out.e(format!(
                "error: {} is a root: its password is entered, not derived — set it with `pass {}`",
                name, name
            ));
            return None;
        }
        let (name, pass, pwd_opt) = if bare_root {
            (name.to_string(), self.state.lock().borrow().secrets.get(name).unwrap().to_string(), None)
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
                (name.clone(), self.state.lock().borrow().secrets.get(&name).unwrap().to_string(), Some(pwd))
            } else {
                match self.read_master(&out, pwd.clone(), true) {
                    Some(sec) => {
                        // A `+` root's password IS its entered value (like `enc /`
                        // returns the root master), not a derived rendering.
                        let p = if is_plus_root(&name) { sec } else { pwd.lock().borrow().encode(sec.as_str()) };
                        (name.clone(), p, Some(pwd))
                    }
                    None => {
                        out.e(format!("error: master for {} not found", name));
                        return None;
                    }
                }
            }
        };
        if out.active() {
            let is_totp = pwd_opt.as_ref().map_or(false, |p| p.lock().borrow().mode == Mode::Totp);
            if is_totp {
                // Print the live code instead of `pass`. The seed is keyed by the
                // UNFOLDED derivation, which needs the entry's master (the cached
                // `pass` is the folded rendering — it can't reproduce the KEK).
                let pwd = pwd_opt.as_ref().unwrap();
                match self.read_master(out, pwd.clone(), true) {
                    Some(sec) => {
                        let kek = pwd.lock().borrow().kek_material(sec.as_str());
                        self.cmd_enc_totp(out, pwd, &kek);
                    }
                    None => out.e(format!("error: master for {} not found", name)),
                }
            } else {
                out.o(pass.clone());
            }
            // Trust-check the DERIVED PASSWORD (`pass` — the value that also decrypts
            // a T entry's seed), NEVER the TOTP code. The code is time-varying and is
            // only printed, never hashed; `pass` is the stable R-mode password. So
            // `correct <T>` stores this password's hash and `enc <T>` warns on a
            // mistyped master, exactly like every other mode.
            self.cmd_correct(&out, &name, true, Some(pass.clone()));
        }
        Some((name, pass))
    }

    /// A TOTP entry's `enc`: decrypt its first `#` token with `passphrase` (the
    /// entry's unfolded KEK material) and print the current RFC-6238 code.
    fn cmd_enc_totp(&self, out: &LKOut, pwd: &PasswordRef, passphrase: &str) {
        let name = pwd.lock().borrow().name.clone();
        let seq = pwd.lock().borrow().seq;
        let comment = pwd.lock().borrow().comment.clone();
        let armor = comment
            .as_deref()
            .map(inline_tokens)
            .unwrap_or_default()
            .into_iter()
            .find(|(t, _)| *t == TokenType::Totp)
            .map(|(_, a)| a);
        let armor = match armor {
            Some(a) => a,
            None => {
                out.e(format!("error: {} has no encrypted TOTP token (add one with #\"otpauth://…\")", name));
                return;
            }
        };
        match crypto::open(TokenType::Totp, &armor, passphrase, &name, seq) {
            Ok(plain) => match totp::parse(&plain) {
                Ok(t) => out.o(t.code_at(now_unix())),
                Err(e) => out.e(format!("error: bad TOTP data in {}: {}", name, e)),
            },
            Err(e) => out.e(format!("error: cannot decrypt TOTP for {}: {}", name, e)),
        }
    }

    /// `reveal <name>`: decrypt and print every `#`/`!` blob in an entry's comment
    /// (a TOTP `#` shows its otpauth URI / secret; a `!` shows its text).
    pub fn cmd_reveal(&self, out: &LKOut, name: &String) {
        let pwd = match self.get_password(name) {
            Some(p) => p,
            None => {
                out.e(format!("error: name {} not found", name));
                return;
            }
        };
        let ename = pwd.lock().borrow().name.clone();
        let seq = pwd.lock().borrow().seq;
        let comment = match pwd.lock().borrow().comment.clone() {
            Some(c) => c,
            None => {
                out.e(format!("error: {} has no encrypted tokens", ename));
                return;
            }
        };
        let tokens = inline_tokens(&comment);
        if tokens.is_empty() {
            out.e(format!("error: {} has no encrypted tokens", ename));
            return;
        }
        // KEK = unfolded derivation from the entry's MASTER; the folded password
        // cached in `secrets` can't reproduce it, so always resolve the chain
        // (read_master hits the parent cache — no re-prompt in the common case).
        let passphrase = match self.read_master(out, pwd.clone(), true) {
            Some(sec) => pwd.lock().borrow().kek_material(sec.as_str()),
            None => {
                out.e(format!("error: master for {} not found", ename));
                return;
            }
        };
        for (ttype, armor) in tokens {
            match crypto::open(ttype, &armor, &passphrase, &ename, seq) {
                Ok(plain) => out.o(plain),
                Err(e) => out.e(format!("error: cannot decrypt {} token in {}: {}", ttype.ch(), ename, e)),
            }
        }
    }

    /// Encrypt any `#"..."`/`!"..."` markers in `pwd`'s comment in place, keyed by
    /// the entry's unfolded KEK (`kek_material()`). Returns Ok(true) if markers
    /// were present. On failure the plaintext is REDACTED (never persisted) and
    /// Err is returned — so a missing master or a malformed marker can never leak
    /// a secret into the db, history, or dump.
    pub fn encrypt_inline_tokens(&self, out: &LKOut, pwd: &PasswordRef) -> Result<bool, ()> {
        let comment = match pwd.lock().borrow().comment.clone() {
            Some(c) => c,
            None => return Ok(false),
        };
        if !comment.contains("#\"") && !comment.contains("!\"") {
            return Ok(false);
        }
        let name = pwd.lock().borrow().name.clone();
        let seq = pwd.lock().borrow().seq;
        let master = match self.read_master(out, pwd.clone(), true) {
            Some(m) => m,
            None => {
                pwd.lock().borrow_mut().comment = Some(crypto::sanitize_for_history(&comment));
                out.e(format!(
                    "error: master required to encrypt {}'s inline secret; secret dropped — re-add with the master available",
                    name
                ));
                return Err(());
            }
        };
        let passphrase = pwd.lock().borrow().kek_material(&master);
        match seal_inline_markers(&comment, &passphrase, &name, seq) {
            Ok(sealed) => {
                pwd.lock().borrow_mut().comment = Some(sealed);
                Ok(true)
            }
            Err(_) => {
                pwd.lock().borrow_mut().comment = Some(crypto::sanitize_for_history(&comment));
                out.e(format!("error: failed to encrypt {}'s inline secret; secret dropped", name));
                Err(())
            }
        }
    }

    /// `enc <arg>`: pick which entry to encode, then encode it. Abstract, like
    /// `pb`: the argument is a name/id, or any command whose output names the
    /// entry. Precedence keeps `enc <name>`/`enc <id>` working even when a name
    /// collides with a command keyword:
    ///   1. `arg` resolves to a catalog entry or `ls` id -> encode it.
    ///   2. else `arg` parses as a command -> evaluate it capturing (so
    ///      `ls`/`ld`/`gen` yield bare names), take the LAST non-empty output
    ///      line as the entry name (newest for `ld`), and encode that. With >1
    ///      candidate, `set hel_enc_strict 1` errors instead of taking the last.
    ///   3. else -> error.
    /// Any command is accepted as a producer (parity with `pb`); a producer that
    /// emits something that is not an entry name simply fails to resolve.
    pub fn cmd_enc_arg(&self, out: &LKOut, arg: &String) {
        if arg.trim().is_empty() {
            out.e("error: enc needs a name, a list id, or a command whose output names one (see `help enc`)".to_string());
            return;
        }
        if self.get_password(arg).is_some() {
            self.cmd_enc(out, arg);
            return;
        }
        // A root (`/`, `+name`) may have no catalog entry — `cmd_enc` returns its
        // cached password. Route it there; running it as a sub-command is what made
        // `enc /` report "name / not found".
        if arg == "/" || is_plus_root(arg) {
            self.cmd_enc(out, arg);
            return;
        }
        let cmd = match command_parser::cmd(arg) {
            Ok(c) => c,
            Err(_) => {
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

    pub fn cmd_source(&self, out: &LKOut, missing: bool, source: &String) -> bool {
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
                // For `-m`: remember which names the source ADDS before the list
                // is consumed, so catalog-only names can be reported afterwards.
                let sourced: HashSet<String> = if missing {
                    cmd_list
                        .iter()
                        .filter_map(|c| match c {
                            Command::Add(p) => Some(p.lock().borrow().name.to_string()),
                            _ => None,
                        })
                        .collect()
                } else {
                    Default::default()
                };
                for cmd in cmd_list {
                    let print = LKEval::new(self.rl.clone(), cmd, self.state.clone(), password).eval();
                    print.out.copy(&out);
                    if print.quit {
                        return true;
                    }
                }
                if missing {
                    // Reverse diff: names in the catalog the source never mentioned
                    // (`- name` per line) — nothing is removed, this is a report.
                    let mut only_local: Vec<String> =
                        self.state.lock().borrow().db.keys().filter(|k| !sourced.contains(*k)).cloned().collect();
                    only_local.sort();
                    for name in only_local {
                        out.o(format!("- {}", name));
                    }
                }
            }
            Err(e) => {
                out.e(format!("error: {}", e.to_string()));
            }
        };
        // Baseline for the next save diff: only the FIRST load establishes the
        // "previously persisted" reference. Later `source`s merge into the
        // session, so the baseline stays put and everything they import shows
        // up in the `save` diff like any other unsaved change.
        if self.state.lock().borrow().last_dump.is_none() {
            let snapshot = self.serialize_db();
            self.state.lock().borrow_mut().last_dump = Some(snapshot);
        }
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
    /// loaded snapshot (set-based, so dump ordering doesn't matter). Without a
    /// baseline the whole catalog counts as added, and a clean save says so
    /// explicitly — every save shows its full diff, always.
    fn show_dump_diff(&self, out: &LKOut, new: &str) {
        let prev = self.state.lock().borrow().last_dump.clone().unwrap_or_default();
        use std::collections::BTreeSet;
        let p: BTreeSet<&str> = prev.lines().filter(|l| !l.is_empty()).collect();
        let n: BTreeSet<&str> = new.lines().filter(|l| !l.is_empty()).collect();
        let mut changed = false;
        for l in p.difference(&n) {
            out.o(format!("< {}", l));
            changed = true;
        }
        for l in n.difference(&p) {
            out.o(format!("> {}", l));
            changed = true;
        }
        if !changed {
            out.o("no changes since last load/save".to_string());
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

    pub fn cmd_ls<F>(&self, out: &LKOut, scope: LsScope, filter: String, sort_by: F)
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
            let hit = {
                let pwd = name.lock();
                let pwd = pwd.borrow();
                // The descriptor is left-padded to a fixed prefix column, so it
                // has to be trimmed or `^` could never anchor at the name.
                let line = || re.is_match(pwd.to_string().trim());
                let named = || re.is_match(&pwd.name);
                let commented = || pwd.comment.as_ref().is_some_and(|c| re.is_match(c));
                match scope {
                    LsScope::Line => line(),
                    LsScope::Name => named(),
                    LsScope::Comment => commented(),
                    LsScope::Any => line() || named() || commented(),
                }
            };
            if hit {
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
        let encpwd: String = sha1.finalize().iter().map(|b| format!("{:02x}", b)).collect();
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

    /// `rnd[N] [descriptor]`: like `gen`, but every candidate's MASTER is pure
    /// OS randomness (160 fresh bits per row) instead of the catalog master —
    /// for minting new root passwords (`+`/`+$` bases). The descriptor decides
    /// everything else exactly as usual: mode/prefix/length, folded (6 words)
    /// vs wide (15 words) by the `$` name marker, `G`/`X` suffix expansion; a
    /// suffix-less name yields N independent candidates. Rows list like `gen`
    /// (ids reusable with `keep` to file the DESCRIPTOR; the shown password is
    /// a one-off sample, never stored — `enc <id>` derives under the real
    /// master). Under `pb` it emits bare passwords: `pb rnd1 …` copies one.
    pub fn cmd_rnd(&self, out: &LKOut, num: &u32, name: &PasswordRef) {
        let num: usize = (*num).try_into().unwrap();
        let mut genpwds = expand_variants(name);
        if genpwds.len() == 1 && num > 1 {
            // no G/X expansion: offer N independent candidates of the descriptor
            let one = genpwds[0].clone();
            for _ in 1..num {
                genpwds.push(Password::from_password_ref(&one.lock().borrow()));
            }
        }
        // register + wire ^parent first, so a `$` inherited from an ancestor
        // (or on the name itself) picks the wide rendering, exactly like gen
        self.state.lock().borrow_mut().ls.clear();
        for (i, pwd) in genpwds.iter().enumerate() {
            let key = Radix::new(i as i32 + 1, 36).unwrap().to_string();
            self.state.lock().borrow_mut().ls.insert(key, pwd.clone());
        }
        self.state.lock().borrow().fix_hierarchy();
        let mut encpwds: Vec<(PasswordRef, String)> = Vec::new();
        for pwd in &genpwds {
            let mut h = [0u8; 20];
            if getrandom::getrandom(&mut h).is_err() {
                out.e("error: random source unavailable".to_string());
                return;
            }
            let master: String = h.iter().map(|b| format!("{:02x}", b)).collect();
            let pass = pwd.lock().borrow().encode(&master);
            encpwds.push((pwd.clone(), pass));
        }
        encpwds.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        self.state.lock().borrow_mut().ls.clear();
        let mut counter = 1;
        let start = encpwds.len() - min(encpwds.len(), num);
        let width = std::cmp::max(36, encpwds[start..].iter().map(|(_, p)| p.chars().count()).max().unwrap_or(0));
        if !self.capture {
            out.o(format!("{:>3} {:>width$} {:>4}       {}", "", "Password", "Len", "Name"));
        }
        for i in start..encpwds.len() {
            let (pwd, pass) = (encpwds[i].0.clone(), encpwds[i].1.to_string());
            let key = Radix::new(counter, 36).unwrap().to_string();
            counter += 1;
            self.state.lock().borrow_mut().ls.insert(key.clone(), pwd.clone());
            if self.capture {
                out.o(pass);
            } else {
                out.o(format!("{:>3} {:>width$} {:>4} {}", key, pass, pass.chars().count(), pwd.lock().borrow().to_string()));
            }
        }
    }

    pub fn cmd_gen(&self, out: &LKOut, num: &u32, name: &PasswordRef) {
        let num: usize = (*num).try_into().unwrap();
        let genpwds = expand_variants(name);
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
        // Captured (under `pb`/`enc`): emit just the variant names, like `ls`/`ld`,
        // so `pb gen …` copies names and `enc gen …` resolves one. Interactive:
        // the full key/password/len/name table. The password column grows with
        // the widest listed password (a `$` subtree renders 15 words), floored
        // at the classic 36 so narrow listings keep their familiar shape.
        let start = encpwds.len() - min(genpwds.len(), num);
        let width = std::cmp::max(36, encpwds[start..].iter().map(|(_, p)| p.chars().count()).max().unwrap_or(0));
        if !self.capture {
            out.o(format!("{:>3} {:>width$} {:>4}       {}", "", "Password", "Len", "Name"));
        }
        for num in start..encpwds.len() {
            let (pwd, pass) = (encpwds[num].0.clone(), encpwds[num].1.to_string());
            let key = Radix::new(counter, 36).unwrap().to_string();
            counter += 1;
            self.state.lock().borrow_mut().ls.insert(key.clone(), pwd.clone());
            if self.capture {
                out.o(pwd.lock().borrow().name.to_string());
            } else {
                out.o(format!("{:>3} {:>width$} {:>4} {}", key, pass, pass.chars().count(), pwd.lock().borrow().to_string()));
            }
        }
    }
}

/// Current unix time in seconds (native + wasm via chrono/wasmbind).
fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Expand a descriptor's `G`/`X` name suffix into variant records (shared by
/// `gen` and `rnd`): `testG` -> test1..test9, `testGG` -> test1..test99, `testX`
/// -> one random numbered variant; no suffix -> the entry itself.
fn expand_variants(name: &PasswordRef) -> Vec<PasswordRef> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^.+?(G+|X+)$").unwrap();
    }
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
    genpwds
}

/// The armored payloads of a comment's inline `#`/`!` blobs (whitespace-delimited
/// words whose remainder decodes as a hel blob). `#hashtag`-style words are skipped.
fn inline_tokens(comment: &str) -> Vec<(TokenType, String)> {
    let mut v = Vec::new();
    for w in comment.split_whitespace() {
        let (ttype, rest) = match w.chars().next() {
            Some('#') => (TokenType::Totp, &w[1..]),
            Some('!') => (TokenType::Text, &w[1..]),
            _ => continue,
        };
        if crypto::looks_like_blob(rest) {
            v.push((ttype, rest.to_string()));
        }
    }
    v
}

/// Replace every `#"..."`/`!"..."` marker in `comment` with its armored, encrypted
/// token. Errs on an unterminated quote so the caller can redact instead of persist.
fn seal_inline_markers(
    comment: &str,
    passphrase: &str,
    name: &str,
    seq: u32,
) -> Result<String, crypto::CryptoError> {
    let mut out = String::with_capacity(comment.len());
    let mut chars = comment.chars().peekable();
    while let Some(c) = chars.next() {
        if (c == '#' || c == '!') && chars.peek() == Some(&'"') {
            let ttype = if c == '#' { TokenType::Totp } else { TokenType::Text };
            chars.next(); // opening quote
            let mut inner = String::new();
            let mut closed = false;
            while let Some(nc) = chars.next() {
                if nc == '"' {
                    closed = true;
                    break;
                }
                inner.push(nc);
            }
            if !closed {
                return Err(crypto::CryptoError::Armor);
            }
            out.push(c);
            out.push_str(&crypto::seal(ttype, &inner, passphrase, name, seq)?);
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

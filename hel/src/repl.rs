use crate::lk::LKRef;
use crate::parser::command_parser;
use crate::structs::{Command, LKErr, LKOut, HISTORY_FILE};
use crate::utils::editor::{password, Editor, EditorRef};

#[derive(Debug)]
pub struct LKRead {
    pub rl: EditorRef,
    pub prompt: String,
    pub state: LKRef,
    pub cmd: String,
    pub input: Option<String>,
    pub read_password: fn(String) -> std::io::Result<String>,
}

#[derive(Debug)]
pub struct LKEval<'a> {
    pub rl: EditorRef,
    pub cmd: Command<'a>,
    pub state: LKRef,
    pub read_password: fn(String) -> std::io::Result<String>,
    /// When true, listing commands (`ls`/`ld`) emit bare entry names instead of
    /// the rich `key name mode seq date comment` rows. Set by `pb`/`enc` on the
    /// sub-command they evaluate so the captured output is consumable (names
    /// feed `enc`, and `pb ls`/`pb ld` copy clean names). Interactive evals keep
    /// it false.
    pub capture: bool,
}

#[derive(Debug)]
pub struct LKPrint {
    pub out: LKOut,
    pub quit: bool,
    pub state: LKRef,
}

impl LKRead {
    pub fn new(rl: EditorRef, prompt: String, state: LKRef) -> Self {
        Self {
            rl,
            prompt,
            state,
            cmd: "".to_string(),
            input: None,
            read_password: password,
        }
    }

    pub fn read(&mut self) -> LKEval<'_> {
        let history_file = HISTORY_FILE.to_str().unwrap();
        self.cmd = match &self.input {
            Some(cmd) => cmd.to_string(),
            None => match self.rl.lock().readline(&*self.prompt) {
                Ok(str) => str,
                Err(LKErr::EOF) => "quit".to_string(),
                Err(LKErr::Error(_)) => "quit".to_string(),
                Err(err) => {
                    return LKEval::new(
                        self.rl.clone(),
                        Command::Error(LKErr::ReadError(err.to_string())),
                        self.state.clone(),
                        self.read_password,
                    )
                }
            }
        };
        match command_parser::cmd(&self.cmd) {
            Ok(cmd) => LKEval::new(self.rl.clone(), cmd, self.state.clone(), self.read_password),
            Err(err) => {
                // A line that failed to parse still lands in history; redact any
                // plaintext #"..."/!"..." so a mistyped secret is never persisted.
                self.rl.lock().add_history_entry(crate::crypto::sanitize_for_history(&self.cmd).as_str());
                self.rl.lock().save_history(&history_file).ok();
                LKEval::new(self.rl.clone(), Command::Error(LKErr::ParseError(err)), self.state.clone(), self.read_password)
            },
        }
    }

    pub fn refresh(&mut self) {}

    pub fn quit(&mut self) {}
}

impl<'a> LKEval<'a> {
    pub fn new(rl: EditorRef, cmd: Command<'a>, state: LKRef, read_password: fn(String) -> std::io::Result<String>) -> Self {
        Self {
            rl,
            cmd,
            state,
            read_password,
            capture: false,
        }
    }

    /// Builder: mark this eval as capturing (see `LKEval::capture`).
    pub fn with_capture(mut self, capture: bool) -> Self {
        self.capture = capture;
        self
    }

    pub fn news(cmd: Command<'a>, state: LKRef) -> Self {
        LKEval::new(Editor::new(), cmd, state, |_| { Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "could not read password")) })
    }

    pub fn newd(cmd: Command<'a>, state: LKRef, read_password: fn(String) -> std::io::Result<String>) -> Self {
        LKEval::new(Editor::new(), cmd, state, read_password)
    }

    pub fn eval(&self) -> LKPrint {
        let out = LKOut::new();
        let mut quit: bool = false;
        let history_file = HISTORY_FILE.to_str().unwrap();
        let mut to_history = true;

        self.rl.lock().clear_history();
        self.rl.lock().load_history(&history_file).ok();

        match &self.cmd {
            Command::Quit => {
                out.e("Bye!".to_string());
                quit = true;
            }
            Command::Ls(scope, filter) => self.cmd_ls(&out, *scope, filter.to_string(), |a, b| {
                a.lock().borrow().name.cmp(&b.lock().borrow().name)
            }),
            Command::Ld(scope, filter) => self.cmd_ls(&out, *scope, filter.to_string(), |a, b| {
                a.lock().borrow().date.cmp(&b.lock().borrow().date)
            }),
            Command::Add(name) => {
                self.cmd_add(&out, &name);
                // Auto-encrypt any #"..."/!"..." the user typed (borrow-safe here:
                // cmd_add's state borrow is released). The mutation is on the same
                // shared PasswordRef the Add-history Display reads, so the history
                // line below is already ciphertext.
                let _ = self.encrypt_inline_tokens(&out, &name);
            }
            Command::Keep(name) => self.cmd_keep(&out, &name),
            Command::Comment(name, comment) => {
                self.cmd_comment(&out, &name, &comment);
                // Comment's Display reads its own plaintext copy, so the shared-ref
                // trick doesn't cover it: encrypt in place, then write the sealed
                // line to history ourselves (and skip the generic push).
                to_history = false;
                if let Some(pwd) = self.get_password(name) {
                    let _ = self.encrypt_inline_tokens(&out, &pwd);
                    let line = match pwd.lock().borrow().comment.clone() {
                        Some(c) => format!("comment {} {}", name, c),
                        None => format!("comment {}", name),
                    };
                    self.rl.lock().add_history_entry(crate::crypto::sanitize_for_history(&line).as_str());
                    self.rl.lock().save_history(&history_file).ok();
                }
            }
            Command::Rm(name) => match self.get_password(name) {
                Some(pwd) => {
                    self.state.lock().borrow_mut().db.remove(&pwd.lock().borrow().name);
                    out.o(format!("removed {}", pwd.lock().borrow().name));
                }
                None => out.e(format!("error: password {} not found", name)),
            },
            Command::Reset(confirm) => self.cmd_reset(&out, confirm),
            Command::Enc(arg) => {
                self.cmd_enc_arg(&out, arg);
            }
            Command::Reveal(name) => self.cmd_reveal(&out, name),
            Command::Gen(num, name) => self.cmd_gen(&out, &num, &name),
            Command::Rnd(num, name) => self.cmd_rnd(&out, &num, &name),
            Command::PasteBuffer(command) => self.cmd_pb(&out, command),
            Command::Source(missing, script) => {
                quit = self.cmd_source(&out, *missing, script);
            }
            Command::Dump(script) => self.cmd_dump(&out, script),
            Command::Set(key, value) => { to_history = false; self.cmd_set(&out, key, value); }
            Command::Pass(name, None) => self.cmd_pass(&out, &name, &None),
            Command::Pass(name, pass) => { to_history = false; self.cmd_pass(&out, &name, &pass); },
            Command::UnPass(Some(name)) => match self.state.lock().borrow_mut().secrets.remove(name) {
                Some(_) => out.o(format!("Removed saved password for {}", name)),
                None => out.e(format!("error: saved password for {} not found", name)),
            },
            Command::UnPass(None) => {
                self.state.lock().borrow_mut().secrets.clear();
                out.o("forgot all cached masters".to_string());
            },
            Command::Correct(name) => self.cmd_correct(&out, name, true, None),
            Command::Uncorrect(name) => self.cmd_correct(&out, name, false, None),
            Command::Noop => { to_history = false; },
            Command::Help(topic) => self.cmd_help(&out, topic),
            Command::Mv(name, folder) => self.cmd_mv(&out, &name, &folder),
            Command::Error(error) => {
                to_history = false;
                match error {
                    LKErr::ParseError(e) => out.e(e.to_string()),
                    LKErr::ReadError(e) => out.e(e.to_string()),
                    LKErr::EOF => out.e("error: end of file".to_string()),
                    LKErr::Error(e) => out.e(format!("error: {}", e.to_string())),
                };
            },
        }

        if to_history {
            // Defense in depth: the Add path already sealed the shared record, but
            // route every history line through the redactor so no plaintext marker
            // can slip through.
            let line = crate::crypto::sanitize_for_history(&self.cmd.to_string());
            self.rl.lock().add_history_entry(line.as_str());
            self.rl.lock().save_history(&history_file).ok();
        }

        LKPrint::new(out, quit, self.state.clone())
    }
}

impl LKPrint {
    pub fn new(out: LKOut, quit: bool, state: LKRef) -> Self {
        Self { out, quit, state }
    }

    pub fn print(&mut self) -> bool {
        self.out.print_err();
        self.out.print_out();
        return !self.quit;
    }
}

impl PartialEq for LKPrint {
    fn eq(&self, other: &Self) -> bool {
        self.out == other.out && self.quit == other.quit && *self.state.lock() == *other.state.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use crate::lk::LK;
    use crate::password::Password;
    use crate::structs::{LsScope, Mode};
    use crate::utils::date::Date;
    use parking_lot::ReentrantMutex;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn exec_cmds_basic() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        assert_eq!(
            LKEval::news(Command::Ls(LsScope::Line, ".".to_string()), lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec![], vec![]), false, lk.clone())
        );
        let pwd1 = Password::from_password(Password {
            name: "t1".to_string(),
            prefix: None,
            length: None,
            mode: Mode::Regular,
            seq: 99,
            date: Date::new(2022, 12, 30),
            comment: Some("comment".to_string()),
            parent: None,
        });
        assert_eq!(
            LKEval::news(Command::Add(pwd1.clone()), lk.clone())
                .eval()
                .state
                .lock()
                .borrow()
                .db
                .iter()
                .map(|x| (x.0.to_string(), x.1.lock().borrow().to_string()))
                .collect::<HashSet<(String, String)>>(),
            {
                let mut db = HashMap::new();
                db.insert(pwd1.lock().borrow().name.to_string(), pwd1.clone());
                db.into_iter()
                    .map(|x| (x.0.to_string(), x.1.lock().borrow().to_string()))
                    .collect::<HashSet<(String, String)>>()
            }
        );
        assert_eq!(
            LKEval::news(Command::Ls(LsScope::Line, ".".to_string()), lk.clone()).eval(),
            LKPrint::new(
                LKOut::from_vecs(vec!["  1       t1 R 99 2022-12-30 comment".to_string()], vec![]),
                false,
                lk.clone()
            )
        );
        assert_eq!(
            LKEval::news(Command::Quit, lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec![], vec!["Bye!".to_string()]), true, lk.clone())
        );
        let pwd2 = Password::from_password(Password {
            name: "t2".to_string(),
            prefix: None,
            length: None,
            mode: Mode::Regular,
            seq: 99,
            date: Date::new(2022, 12, 31),
            comment: Some("bli blup".to_string()),
            parent: None,
        });
        assert_eq!(
            LKEval::news(Command::Add(pwd2.clone()), lk.clone())
                .eval()
                .state
                .lock()
                .borrow()
                .db
                .iter()
                .map(|x| (x.0.to_string(), x.1.lock().borrow().to_string()))
                .collect::<HashSet<(String, String)>>(),
            {
                let mut db = HashMap::new();
                db.insert(pwd1.lock().borrow().name.to_string(), pwd1.clone());
                db.insert(pwd2.lock().borrow().name.to_string(), pwd2.clone());
                db.into_iter().map(|x| (x.0, x.1.lock().borrow().to_string())).collect::<HashSet<(String, String)>>()
            }
        );
        assert_eq!(
            LKEval::news(Command::Ls(LsScope::Line, ".".to_string()), lk.clone()).eval(),
            LKPrint::new(
                LKOut::from_vecs(
                    vec![
                        "  1       t1 R 99 2022-12-30 comment".to_string(),
                        "  2       t2 R 99 2022-12-31 bli blup".to_string()
                    ],
                    vec![]
                ),
                false,
                lk.clone()
            )
        );
        assert_eq!(
            LKEval::news(Command::Rm("2".to_string()), lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec!["removed t2".to_string()], vec![]), false, lk.clone())
        );
        assert_eq!(
            LKEval::news(Command::Ls(LsScope::Line, ".".to_string()), lk.clone()).eval(),
            LKPrint::new(
                LKOut::from_vecs(vec!["  1       t1 R 99 2022-12-30 comment".to_string()], vec![]),
                false,
                lk.clone()
            )
        );
    }

    #[test]
    fn read_pwd_test() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let t1 = Password::from_password(Password::new(
            None,
            "t1".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 30),
            None,
        ));
        let t2 = Password::from_password(Password::new(
            None,
            "t2".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 30),
            None,
        ));
        let t3 = Password::from_password(Password::new(
            None,
            "t3".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 30),
            None,
        ));
        assert_eq!(
            LKEval::news(Command::Add(t1.clone()), lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec![], vec![]), false, lk.clone())
        );
        assert_eq!(
            LKEval::news(Command::Add(t2.clone()), lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec![], vec![]), false, lk.clone())
        );
        assert_eq!(
            LKEval::news(Command::Add(t3.clone()), lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec![], vec![]), false, lk.clone())
        );
        assert_eq!(
            LKEval::news(Command::Mv("t3".to_string(), "t2".to_string()), lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec![], vec![]), false, lk.clone())
        );
        assert_eq!(
            LKEval::news(Command::Mv("t2".to_string(), "t1".to_string()), lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec![], vec![]), false, lk.clone())
        );
        assert_eq!(
            LKEval::newd(Command::Enc("t3".to_string()), lk.clone(), |p| if p == "NULL" {
                Ok("a".to_string())
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "test"))
            })
            .eval(),
            LKPrint::new(
                LKOut::from_vecs(vec![], vec!["error: master for t3 not found".to_string()]),
                false,
                lk.clone()
            )
        );
        assert_eq!(
            LKEval::newd(Command::Enc("t3".to_string()), lk.clone(), |p| if p == "/" {
                Ok("a".to_string())
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "test"))
            })
            .eval(),
            LKPrint::new(
                LKOut::from_vecs(
                    vec!["san bud most noon jaw cash".to_string()],
                    vec![
                        "warning: password / is not marked as correct".to_string(),
                        "warning: password t1 is not marked as correct".to_string(),
                        "warning: password t2 is not marked as correct".to_string(),
                        "warning: password t3 is not marked as correct".to_string(),
                    ]
                ),
                false,
                lk.clone()
            )
        );
        assert_eq!(
            LKEval::newd(Command::Enc("t2".to_string()), lk.clone(), |p| if p == "NULL" {
                Ok("a".to_string())
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "test"))
            })
            .eval(),
            LKPrint::new(
                LKOut::from_vecs(
                    vec!["alga barn wise tim skin mock".to_string()],
                    vec!["warning: password t2 is not marked as correct".to_string()]
                ),
                false,
                lk.clone()
            )
        );
        assert_eq!(
            LKEval::newd(Command::Enc("t1".to_string()), lk.clone(), |p| if p == "NULL" {
                Ok("a".to_string())
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "test"))
            })
            .eval(),
            LKPrint::new(
                LKOut::from_vecs(
                    vec!["lime rudy jay my kong tack".to_string()],
                    vec!["warning: password t1 is not marked as correct".to_string()]
                ),
                false,
                lk.clone()
            )
        );
    }

    #[test]
    fn totp_add_seal_enc_reveal() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        // master prompt returns "master" for the root; anything else empty.
        let rp = |p: String| -> std::io::Result<String> {
            if p == "/" { Ok("master".to_string()) } else { Ok("".to_string()) }
        };
        let secret = "JBSWY3DPEHPK3PXP";
        let uri = format!("otpauth://totp/x?secret={}", secret);
        // add-by-value: the #"…" is sealed in place using the entry's own password.
        let addline = format!("add x t T 99 now #\"{}\"", uri);
        let add = command_parser::cmd(&addline).unwrap();
        LKEval::newd(add, lk.clone(), rp).eval();

        // the stored record must hold a #<blob>, never the plaintext secret/URI.
        let pwd = lk.lock().borrow().db.get("t").unwrap().clone();
        let comment = pwd.lock().borrow().comment.clone().unwrap();
        assert!(!comment.contains(secret), "plaintext leaked into comment: {}", comment);
        assert!(!comment.contains("otpauth://"), "plaintext uri leaked: {}", comment);
        assert!(comment.starts_with('#') && !comment.contains('"'));
        assert!(!pwd.lock().borrow().to_string().contains(secret));

        // reveal round-trips back to the exact otpauth URI.
        let pr = LKEval::newd(command_parser::cmd("reveal t").unwrap(), lk.clone(), rp).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock().clone(), vec![uri.clone()]);

        // enc prints a 6-digit TOTP code (not the R password).
        let pr = LKEval::newd(command_parser::cmd("enc t").unwrap(), lk.clone(), rp).eval();
        let code = pr.out.out.as_ref().unwrap().lock()[0].clone();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()), "not a code: {}", code);

        // the sealed entry (dumped) loaded elsewhere decrypts only with the right
        // master: a wrong one fails the AEAD tag — no code, a clear error.
        let dump = LKEval::news(Command::Dump(Some("-".to_string())), lk.clone()).eval();
        let line = dump.out.out.as_ref().unwrap().lock()[0].clone();
        let lk2 = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let rp_wrong = |p: String| -> std::io::Result<String> {
            if p == "/" { Ok("WRONG".to_string()) } else { Ok("".to_string()) }
        };
        LKEval::newd(command_parser::cmd(&line).unwrap(), lk2.clone(), rp_wrong).eval();
        let pr = LKEval::newd(command_parser::cmd("enc t").unwrap(), lk2.clone(), rp_wrong).eval();
        assert!(pr.out.out.as_ref().unwrap().lock().is_empty(), "should not print a code with the wrong master");
        assert!(pr.out.err.as_ref().unwrap().lock().iter().any(|l| l.contains("cannot decrypt")));
    }

    #[test]
    fn totp_correct_hashes_derived_password_not_code() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let rp = |p: String| -> std::io::Result<String> {
            if p == "/" { Ok("master".to_string()) } else { Ok("".to_string()) }
        };
        let addline = "add x t T 99 now #\"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\"".to_string();
        LKEval::newd(command_parser::cmd(&addline).unwrap(), lk.clone(), rp).eval();

        // `correct <T>` hashes what cmd_enc returns (called with an INACTIVE out).
        // That value must be the entry's stable R-mode derived password — the key
        // that decrypts the seed — NEVER the time-varying 6-digit code.
        let ev = LKEval::newd(Command::Noop, lk.clone(), rp);
        let full = LKOut::new();
        let inactive = LKOut::from_lkout(None, full.err.clone());
        let (name, pass) = ev.cmd_enc(&inactive, &"t".to_string()).unwrap();
        assert_eq!(name, "t");
        let pwd = lk.lock().borrow().db.get("t").unwrap().clone();
        assert_eq!(pass, pwd.lock().borrow().encode("master"), "correct must hash the derived password");
        assert!(pass.contains(' '), "derived password is R-mode words, not a 6-digit code: {:?}", pass);
    }

    #[test]
    fn plus_root_chain_stops_and_uses_entered_value() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        // prompts: only `/` would answer — a `+` root must NEVER fall through to it
        let rp = |p: String| -> std::io::Result<String> {
            if p == "/" { Ok("rootmaster".to_string()) } else { Ok("".to_string()) }
        };
        LKEval::newd(command_parser::cmd("add +bohr R 99 2026-1-1").unwrap(), lk.clone(), rp).eval();
        LKEval::newd(command_parser::cmd("add sub R 99 2026-1-1 ^+bohr").unwrap(), lk.clone(), rp).eval();
        let sub = lk.lock().borrow().db.get("sub").unwrap().clone();
        assert_eq!(sub.lock().borrow().parent.as_ref().unwrap().lock().borrow().name, "+bohr");

        // Blank at the `+bohr` prompt: chain STOPS with an error — no climb to `/`.
        let pr = LKEval::newd(command_parser::cmd("enc sub").unwrap(), lk.clone(), rp).eval();
        assert!(pr.out.out.as_ref().unwrap().lock().is_empty(), "must not derive via the root master");
        assert!(pr.out.err.as_ref().unwrap().lock().iter().any(|l| l.contains("independent root")));

        // With the root's password entered (`pass`), the child derives from the
        // ENTERED value directly (no encode of the + root in between).
        LKEval::news(Command::Pass("+bohr".to_string(), Some("entered pw".to_string())), lk.clone()).eval();
        let pr = LKEval::newd(command_parser::cmd("enc sub").unwrap(), lk.clone(), rp).eval();
        let got = pr.out.out.as_ref().unwrap().lock()[0].clone();
        assert_eq!(got, sub.lock().borrow().encode("entered pw"));

        // `enc +bohr` prints the entered value itself (like `enc /`), not a derivation.
        let pr = LKEval::newd(command_parser::cmd("enc +bohr").unwrap(), lk.clone(), rp).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock()[0], "entered pw");

        // Uncached `+` root: the prompt asks for the root's OWN name and the
        // entered value is used verbatim (and cached).
        let rp2 = |p: String| -> std::io::Result<String> {
            if p == "+solo" { Ok("solo pw".to_string()) } else { Ok("".to_string()) }
        };
        LKEval::newd(command_parser::cmd("add +solo R 99 2026-1-1").unwrap(), lk.clone(), rp2).eval();
        let pr = LKEval::newd(command_parser::cmd("enc +solo").unwrap(), lk.clone(), rp2).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock()[0], "solo pw");
        assert_eq!(lk.lock().borrow().secrets[&"+solo".to_string()], "solo pw");

        // `pass +root` works BEFORE the catalog holds the entry (like `pass /`),
        // so an import script can set all roots up front.
        let lk2 = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let pr = LKEval::newd(command_parser::cmd("pass +early xyz").unwrap(), lk2.clone(), rp).eval();
        assert!(pr.out.err.as_ref().unwrap().lock().iter().all(|l| !l.contains("not found")));
        assert_eq!(lk2.lock().borrow().secrets[&"+early".to_string()], "xyz");
    }

    #[test]
    fn unfolded_subtree_chain_e2e() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let rp = |p: String| -> std::io::Result<String> {
            if p == "/" { Ok("rootmaster".to_string()) } else { Ok("".to_string()) }
        };
        LKEval::newd(command_parser::cmd("add $acct R 99 2026-1-1").unwrap(), lk.clone(), rp).eval();
        LKEval::newd(command_parser::cmd("add sub R 99 2026-1-1 ^$acct").unwrap(), lk.clone(), rp).eval();

        // The `$` base renders WIDE (15 words) from the root master…
        let pr = LKEval::newd(command_parser::cmd("enc $acct").unwrap(), lk.clone(), rp).eval();
        let base_pw = pr.out.out.as_ref().unwrap().lock()[0].clone();
        let h = crate::skey::SKey::unfolded("$acct", 99, "rootmaster");
        assert_eq!(base_pw, crate::skey::SKey::wide_words(&h).join(" "));

        // …and the plain-named child inherits $-ness: wide render, chained off
        // the base's WIDE password.
        let pr = LKEval::newd(command_parser::cmd("enc sub").unwrap(), lk.clone(), rp).eval();
        let sub_pw = pr.out.out.as_ref().unwrap().lock()[0].clone();
        let hs = crate::skey::SKey::unfolded("sub", 99, &base_pw);
        assert_eq!(sub_pw, crate::skey::SKey::wide_words(&hs).join(" "));
        assert_eq!(sub_pw.split(' ').count(), 15);
    }

    #[test]
    fn totp_under_plus_root_seals_and_reveals() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let rp = |p: String| -> std::io::Result<String> {
            if p == "+vault" { Ok("vault master".to_string()) } else { Ok("".to_string()) }
        };
        let uri = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
        LKEval::newd(command_parser::cmd("add +vault R 99 2026-1-1").unwrap(), lk.clone(), rp).eval();
        let addline = format!("add vt T 99 now #\"{}\" ^+vault", uri);
        LKEval::newd(command_parser::cmd(&addline).unwrap(), lk.clone(), rp).eval();

        // sealed, no plaintext; reveal + enc work off the + root's entered value
        let pwd = lk.lock().borrow().db.get("vt").unwrap().clone();
        let comment = pwd.lock().borrow().comment.clone().unwrap();
        assert!(!comment.contains("JBSWY3DP") && !comment.contains("otpauth"));
        let pr = LKEval::newd(command_parser::cmd("reveal vt").unwrap(), lk.clone(), rp).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock().clone(), vec![uri.to_string()]);
        let pr = LKEval::newd(command_parser::cmd("enc vt").unwrap(), lk.clone(), rp).eval();
        let code = pr.out.out.as_ref().unwrap().lock()[0].clone();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn rnd_generates_random_passphrases_without_master() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        // capture -> bare passwords; news' read_password always errors, which
        // proves rnd never asks for a master
        let cap = |cmd: &str| {
            LKEval::news(command_parser::cmd(cmd).unwrap(), lk.clone()).with_capture(true).eval()
        };
        // bare rnd = `$rnd` descriptor -> wide 15-word candidates, all distinct
        let pr = cap("rnd3");
        let lines = pr.out.out.as_ref().unwrap().lock().clone();
        assert_eq!(lines.len(), 3);
        for l in &lines {
            assert_eq!(l.split(' ').count(), 15, "wide rendering: {}", l);
        }
        assert_ne!(lines[0], lines[1]);
        assert!(pr.out.err.as_ref().unwrap().lock().is_empty());

        // a name WITHOUT `$` respects the folded rendering (6 words)
        let pr = cap("rnd3 vault");
        let lines = pr.out.out.as_ref().unwrap().lock().clone();
        assert_eq!(lines.len(), 3);
        for l in &lines {
            assert_eq!(l.split(' ').count(), 6, "folded rendering: {}", l);
        }
        assert_ne!(lines[0], lines[1]);

        // mode/length honored per $-ness: a folded UB value is 11 b64 chars
        // (len 20 cannot extend it); the wide one is 27, truncated to 20
        let pr = cap("rnd1 x 20UB");
        let lines = pr.out.out.as_ref().unwrap().lock().clone();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].chars().count(), 11);
        assert_eq!(lines[0], lines[0].to_uppercase());
        let pr = cap("rnd1 $x 20UB");
        let lines = pr.out.out.as_ref().unwrap().lock().clone();
        assert_eq!(lines[0].chars().count(), 20);

        // G-suffix expands numbered variants, table row names like gen's
        let pr = LKEval::news(command_parser::cmd("rnd4 testGG R 99 2026-1-1").unwrap(), lk.clone()).eval();
        let rows = pr.out.out.as_ref().unwrap().lock().clone();
        assert_eq!(rows.len(), 5); // header + 4 rows
        assert!(rows[0].contains("Password") && rows[0].contains("Name"));
        for r in &rows[1..] {
            assert!(r.contains(" test"), "variant name in row: {}", r);
        }
    }

    #[test]
    fn reset_drops_catalog_only_with_confirmation() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let rp = |_: String| -> std::io::Result<String> { Ok("".to_string()) };
        LKEval::newd(command_parser::cmd("add one R 99 2026-1-1").unwrap(), lk.clone(), rp).eval();
        LKEval::newd(command_parser::cmd("add two R 99 2026-1-1").unwrap(), lk.clone(), rp).eval();
        LKEval::news(Command::Pass("/".to_string(), Some("m".to_string())), lk.clone()).eval();

        // bare `reset` only hints; nothing is dropped
        let pr = LKEval::newd(command_parser::cmd("reset").unwrap(), lk.clone(), rp).eval();
        assert!(pr.out.err.as_ref().unwrap().lock().iter().any(|l| l.contains("reset yes")));
        assert_eq!(lk.lock().borrow().db.len(), 2);

        // `reset yes` empties db + listing but keeps cached masters
        let pr = LKEval::newd(command_parser::cmd("reset yes").unwrap(), lk.clone(), rp).eval();
        assert!(pr.out.out.as_ref().unwrap().lock().iter().any(|l| l.contains("dropped 2 entries")));
        assert_eq!(lk.lock().borrow().db.len(), 0);
        assert_eq!(lk.lock().borrow().ls.len(), 0);
        assert_eq!(lk.lock().borrow().secrets[&"/".to_string()], "m");

        // reimport works cleanly after the reset (no "already exist")
        let pr = LKEval::newd(command_parser::cmd("add one R 99 2026-1-1").unwrap(), lk.clone(), rp).eval();
        assert!(pr.out.err.as_ref().unwrap().lock().is_empty());
        assert_eq!(lk.lock().borrow().db.len(), 1);
    }

    #[test]
    fn exec_cmd_pass() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let t1 = Password::from_password(Password::new(
            None,
            "t1".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 12, 30),
            None,
        ));
        LKEval::news(Command::Add(t1.clone()), lk.clone()).eval();
        LKEval::newd(Command::Pass("t1".to_string(), None), lk.clone(), |_| { Ok("test pwd1".to_string()) }).eval();
        assert_eq!(lk.lock().borrow().secrets[&"t1".to_string()], "test pwd1");
        LKEval::news(Command::Pass("t1".to_string(), Some("other pw".to_string())), lk.clone()).eval();
        assert_eq!(lk.lock().borrow().secrets[&"t1".to_string()], "other pw");
    }

    #[test]
    fn exec_cmd_enc_root() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        // A root has no catalog entry: `enc /` (and `enc +bohr`) must hand back the
        // password `pass` cached for it, not report "name / not found".
        LKEval::news(Command::Pass("/".to_string(), Some("root master".to_string())), lk.clone()).eval();
        LKEval::news(Command::Pass("+bohr".to_string(), Some("bohr master".to_string())), lk.clone()).eval();
        let pr = LKEval::news(Command::Enc("/".to_string()), lk.clone()).eval();
        assert_eq!(pr.out.data(), "root master");
        let pr = LKEval::news(Command::Enc("+bohr".to_string()), lk.clone()).eval();
        assert_eq!(pr.out.data(), "bohr master");
        // an uncached root explains itself instead of failing as a missing name
        let pr = LKEval::news(Command::Enc("+none".to_string()), lk.clone()).eval();
        assert!(pr.out.err.as_ref().unwrap().lock().join("").contains("is a root: its password is entered"));
        // bare `enc` is a usage line, not a parse error
        let pr = LKEval::news(Command::Enc("".to_string()), lk.clone()).eval();
        assert!(pr.out.err.as_ref().unwrap().lock().join("").contains("enc needs a name"));
    }

    fn mk(name: &str, y: i32, m: u32, d: u32) -> crate::password::PasswordRef {
        Password::from_password(Password {
            name: name.to_string(),
            prefix: None,
            length: None,
            mode: Mode::Regular,
            seq: 99,
            date: Date::new(y, m, d),
            comment: None,
            parent: None,
        })
    }

    #[test]
    fn capture_names_test() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        LKEval::news(Command::Add(mk("btest", 2022, 1, 2)), lk.clone()).eval();
        LKEval::news(Command::Add(mk("atest", 2024, 5, 6)), lk.clone()).eval();

        // Captured ls -> bare names, sorted by name.
        let pr = LKEval::news(Command::Ls(LsScope::Line, ".".to_string()), lk.clone()).with_capture(true).eval();
        assert_eq!(pr.out, LKOut::from_vecs(vec!["atest".to_string(), "btest".to_string()], vec![]));

        // Captured ld -> bare names, sorted by date ascending (newest last).
        let pr = LKEval::news(Command::Ld(LsScope::Line, ".".to_string()), lk.clone()).with_capture(true).eval();
        assert_eq!(pr.out, LKOut::from_vecs(vec!["btest".to_string(), "atest".to_string()], vec![]));

        // Interactive ls keeps the rich rows (key + mode + date), not bare names.
        let pr = LKEval::news(Command::Ls(LsScope::Line, ".".to_string()), lk.clone()).eval();
        let rows = pr.out.out.as_ref().unwrap().lock();
        assert!(rows.iter().any(|l| l.contains("atest R 99 2024-05-06")));
        assert!(rows.iter().all(|l| l.as_str() != "atest" && l.as_str() != "btest"));
    }

    fn mkc(name: &str, comment: &str) -> crate::password::PasswordRef {
        let pwd = mk(name, 2022, 1, 2);
        pwd.lock().borrow_mut().comment = Some(comment.to_string());
        pwd
    }

    #[test]
    fn ls_scope_test() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        for pwd in [
            mk("sshkeys", 2022, 1, 2),        // name starts with ssh
            mk("myssh", 2022, 1, 2),          // name contains ssh
            mkc("gitlab", "ssh access here"), // comment starts with ssh
            mkc("mail", "ok@example.com"),    // comment starts with ok@
            mkc("other", "write to ok@x"),    // comment contains ok@
            mk("microsoft-account", 2022, 1, 2),
        ] {
            LKEval::news(Command::Add(pwd), lk.clone()).eval();
        }
        let ls = |scope, re: &str| {
            let pr = LKEval::news(Command::Ls(scope, re.to_string()), lk.clone()).with_capture(true).eval();
            let rows = pr.out.out.as_ref().unwrap().lock().clone();
            rows
        };

        // Default scope is the trimmed descriptor line, so `^` anchors at the
        // name — neither the mid-name nor the comment-start hit comes along.
        assert_eq!(ls(LsScope::Line, "^ssh"), vec!["sshkeys".to_string()]);
        // Unanchored still sees the whole line, comment included.
        assert_eq!(ls(LsScope::Line, "ssh"), vec!["gitlab", "myssh", "sshkeys"]);
        // -n anchors both ends at the name; -c does the same for the comment.
        assert_eq!(ls(LsScope::Name, "^ssh"), vec!["sshkeys".to_string()]);
        assert_eq!(ls(LsScope::Name, "^microsoft.*t$"), vec!["microsoft-account".to_string()]);
        assert_eq!(ls(LsScope::Comment, "^ok@"), vec!["mail".to_string()]);
        assert_eq!(ls(LsScope::Comment, "ssh"), vec!["gitlab".to_string()]);
        // -a is the union: a name start OR a comment start.
        assert_eq!(ls(LsScope::Any, "^ssh"), vec!["gitlab", "sshkeys"]);
        // A pattern that does not compile is reported, not silently ignored.
        let pr = LKEval::news(Command::Ls(LsScope::Line, "^(".to_string()), lk.clone()).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock().len(), 0);
        assert!(pr.out.err.as_ref().unwrap().lock()[0].contains("failed to parse re"));
    }

    #[test]
    fn help_test() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        // overview
        let pr = LKEval::news(Command::Help(None), lk.clone()).eval();
        assert!(pr.out.out.as_ref().unwrap().lock()[0].contains("ENTRIES"));
        // per-topic detail
        let pr = LKEval::news(Command::Help(Some("enc".to_string())), lk.clone()).eval();
        assert!(pr.out.out.as_ref().unwrap().lock()[0].contains("enc ld <re>"));
        // alias resolves to the same topic
        let pr = LKEval::news(Command::Help(Some("descriptor".to_string())), lk.clone()).eval();
        assert!(pr.out.out.as_ref().unwrap().lock()[0].contains("[prefix] <name>"));
        // unknown topic -> stderr error, empty stdout
        let pr = LKEval::news(Command::Help(Some("bogus".to_string())), lk.clone()).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock().len(), 0);
        assert!(pr.out.err.as_ref().unwrap().lock()[0].contains("no help for bogus"));
    }

    #[test]
    fn enc_consumer_test() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        LKEval::news(Command::Add(mk("microexa1", 2024, 1, 10)), lk.clone()).eval();
        LKEval::news(Command::Add(mk("microexa2", 2025, 9, 1)), lk.clone()).eval();
        LKEval::news(Command::Add(mk("microexaadmin", 2026, 3, 4)), lk.clone()).eval();
        LKEval::news(Command::Add(mk("other", 2023, 1, 1)), lk.clone()).eval();
        let rp = |p: String| -> std::io::Result<String> {
            if p == "/" { Ok("a".to_string()) } else { Ok("".to_string()) }
        };

        // enc ld <re>: 3 matches -> encode the newest (microexaadmin); note on stderr.
        let pr = LKEval::newd(command_parser::cmd("enc ld micro.*exa").unwrap(), lk.clone(), rp).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock().len(), 1);
        let pass_newest = pr.out.out.as_ref().unwrap().lock()[0].clone();
        assert!(pr.out.err.as_ref().unwrap().lock().iter().any(|l| l == "note: 3 names matched; encoding last: microexaadmin"));

        // Same password as encoding the newest entry by name directly.
        lk.lock().borrow_mut().secrets.clear();
        let pr2 = LKEval::newd(command_parser::cmd("enc microexaadmin").unwrap(), lk.clone(), rp).eval();
        assert_eq!(pr2.out.out.as_ref().unwrap().lock()[0].clone(), pass_newest);

        // 0 matches -> error, empty stdout (so a wrapping `pb` copies nothing).
        let pr = LKEval::newd(command_parser::cmd("enc ld nomatch").unwrap(), lk.clone(), rp).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock().len(), 0);
        assert!(pr.out.err.as_ref().unwrap().lock().iter().any(|l| l.contains("no entry matches")));

        // strict: >1 match errors, nothing encoded.
        crate::structs::config_set("hel_enc_strict", "1");
        let pr = LKEval::newd(command_parser::cmd("enc ld micro.*exa").unwrap(), lk.clone(), rp).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock().len(), 0);
        assert!(pr.out.err.as_ref().unwrap().lock().iter().any(|l| l.contains("hel_enc_strict")));
        crate::structs::config_set("hel_enc_strict", "0");

        // literal-first: an entry named like a command keyword still encodes that
        // entry (not the listing) and emits no "names matched" note.
        LKEval::news(Command::Add(mk("ld", 2020, 1, 1)), lk.clone()).eval();
        lk.lock().borrow_mut().secrets.clear();
        let pr = LKEval::newd(command_parser::cmd("enc ld").unwrap(), lk.clone(), rp).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock().len(), 1);
        assert!(!pr.out.err.as_ref().unwrap().lock().iter().any(|l| l.contains("names matched")));
    }

    #[test]
    fn gen_capture_and_enc_test() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let rp = |p: String| -> std::io::Result<String> {
            if p == "/" { Ok("a".to_string()) } else { Ok("".to_string()) }
        };
        // Captured `gen` -> bare variant names (no header, no password columns),
        // so it composes with pb/enc like ls/ld.
        let pr = LKEval::newd(command_parser::cmd("gen testG").unwrap(), lk.clone(), rp)
            .with_capture(true)
            .eval();
        let names = pr.out.out.as_ref().unwrap().lock();
        assert!(!names.is_empty());
        assert!(names.iter().all(|l| l.starts_with("test") && !l.contains(' ')));
        assert!(!names.iter().any(|l| l.contains("Password")));
        drop(names);

        // `enc gen` runs gen and encodes one variant — proves enc accepts any
        // command, not only ls/ld. `testX` yields a single random variant.
        let pr = LKEval::newd(command_parser::cmd("enc gen testX").unwrap(), lk.clone(), rp).eval();
        assert_eq!(pr.out.out.as_ref().unwrap().lock().len(), 1);
        assert!(pr.out.out.as_ref().unwrap().lock()[0].contains(' ')); // six S/KEY words, not a name
    }

    #[test]
    fn save_diff_always_complete_test() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        let tmp = std::env::temp_dir().join(format!("hel_save_diff_{}", std::process::id()));
        let target = tmp.to_str().unwrap().to_string();

        // No baseline yet: the first save lists the whole catalog as added.
        LKEval::news(command_parser::cmd("add t1").unwrap(), lk.clone()).eval();
        LKEval::news(command_parser::cmd("add t2").unwrap(), lk.clone()).eval();
        let pr = LKEval::news(Command::Dump(Some(target.clone())), lk.clone()).eval();
        let out = pr.out.out.as_ref().unwrap().lock().clone();
        assert_eq!(out.iter().filter(|l| l.starts_with("> add")).count(), 2);

        // Clean save: an explicit marker instead of silence.
        let pr = LKEval::news(Command::Dump(Some(target.clone())), lk.clone()).eval();
        let out = pr.out.out.as_ref().unwrap().lock().clone();
        assert!(out.iter().any(|l| l == "no changes since last load/save"));
        assert!(!out.iter().any(|l| l.starts_with("< ") || l.starts_with("> ")));

        // A later `source` merges as unsaved changes, so its adds appear in the
        // diff alongside other edits (the baseline only moves on load/save).
        let src = std::env::temp_dir().join(format!("hel_save_diff_src_{}", std::process::id()));
        std::fs::write(&src, "add t3\n").unwrap();
        LKEval::news(Command::Source(false, src.to_str().unwrap().to_string()), lk.clone()).eval();
        LKEval::news(command_parser::cmd("rm t2").unwrap(), lk.clone()).eval();
        let pr = LKEval::news(Command::Dump(Some(target.clone())), lk.clone()).eval();
        let out = pr.out.out.as_ref().unwrap().lock().clone();
        assert_eq!(out.iter().filter(|l| l.starts_with("> add") && l.contains(" t3 ")).count(), 1);
        assert_eq!(out.iter().filter(|l| l.starts_with("< add") && l.contains(" t2 ")).count(), 1);

        std::fs::remove_file(&tmp).ok();
        std::fs::remove_file(&src).ok();
    }
}

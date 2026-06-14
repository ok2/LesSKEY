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

    pub fn read(&mut self) -> LKEval {
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
                self.rl.lock().add_history_entry(&self.cmd);
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
            Command::Ls(filter) => {
                self.cmd_ls(&out, filter.to_string(), |a, b| a.lock().borrow().name.cmp(&b.lock().borrow().name))
            }
            Command::Ld(filter) => {
                self.cmd_ls(&out, filter.to_string(), |a, b| a.lock().borrow().date.cmp(&b.lock().borrow().date))
            }
            Command::Add(name) => self.cmd_add(&out, &name),
            Command::Keep(name) => self.cmd_keep(&out, &name),
            Command::Comment(name, comment) => self.cmd_comment(&out, &name, &comment),
            Command::Rm(name) => match self.get_password(name) {
                Some(pwd) => {
                    self.state.lock().borrow_mut().db.remove(&pwd.lock().borrow().name);
                    out.o(format!("removed {}", pwd.lock().borrow().name));
                }
                None => out.e(format!("error: password {} not found", name)),
            },
            Command::Enc(arg) => {
                self.cmd_enc_arg(&out, arg);
            }
            Command::Gen(num, name) => self.cmd_gen(&out, &num, &name),
            Command::PasteBuffer(command) => self.cmd_pb(&out, command),
            Command::Source(script) => {
                quit = self.cmd_source(&out, script);
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
            self.rl.lock().add_history_entry(self.cmd.to_string().as_str());
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
    use crate::structs::Mode;
    use crate::utils::date::Date;
    use parking_lot::ReentrantMutex;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn exec_cmds_basic() {
        let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
        assert_eq!(
            LKEval::news(Command::Ls(".".to_string()), lk.clone()).eval(),
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
            LKEval::news(Command::Ls(".".to_string()), lk.clone()).eval(),
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
            LKEval::news(Command::Ls(".".to_string()), lk.clone()).eval(),
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
            LKEval::news(Command::Ls(".".to_string()), lk.clone()).eval(),
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
        let pr = LKEval::news(Command::Ls(".".to_string()), lk.clone()).with_capture(true).eval();
        assert_eq!(pr.out, LKOut::from_vecs(vec!["atest".to_string(), "btest".to_string()], vec![]));

        // Captured ld -> bare names, sorted by date ascending (newest last).
        let pr = LKEval::news(Command::Ld(".".to_string()), lk.clone()).with_capture(true).eval();
        assert_eq!(pr.out, LKOut::from_vecs(vec!["btest".to_string(), "atest".to_string()], vec![]));

        // Interactive ls keeps the rich rows (key + mode + date), not bare names.
        let pr = LKEval::news(Command::Ls(".".to_string()), lk.clone()).eval();
        let rows = pr.out.out.as_ref().unwrap().lock();
        assert!(rows.iter().any(|l| l.contains("atest R 99 2024-05-06")));
        assert!(rows.iter().all(|l| l.as_str() != "atest" && l.as_str() != "btest"));
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
}

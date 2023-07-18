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
        }
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
            Command::Enc(name) => {
                self.cmd_enc(&out, name);
            }
            Command::Gen(num, name) => self.cmd_gen(&out, &num, &name),
            Command::PasteBuffer(command) => self.cmd_pb(&out, command),
            Command::Source(script) => {
                quit = self.cmd_source(&out, script);
            }
            Command::Dump(script) => self.cmd_dump(&out, script),
            Command::Pass(name, None) => self.cmd_pass(&out, &name, &None),
            Command::Pass(name, pass) => { to_history = false; self.cmd_pass(&out, &name, &pass); },
            Command::UnPass(name) => match self.state.lock().borrow_mut().secrets.remove(name) {
                Some(_) => out.o(format!("Removed saved password for {}", name)),
                None => out.e(format!("error: saved password for {} not found", name)),
            },
            Command::Correct(name) => self.cmd_correct(&out, name, true, None),
            Command::Uncorrect(name) => self.cmd_correct(&out, name, false, None),
            Command::Noop => { to_history = false; },
            Command::Help => {
                out.o("HELP".to_string());
            }
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
}

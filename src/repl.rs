use home::home_dir;
use rpassword::prompt_password;
use rustyline::Editor;
use std::{cell::RefCell, rc::Rc};

use crate::lk::LK;
use crate::parser::command_parser;
use crate::password::{fix_password_recursion, PasswordRef};
use crate::structs::{Command, LKErr, Radix};

#[derive(Debug)]
pub struct LKRead {
    rl: Editor<()>,
    prompt: String,
    state: Rc<RefCell<LK>>,
    cmd: String,
}

#[derive(Debug)]
pub struct LKEval<'a> {
    cmd: Command<'a>,
    state: Rc<RefCell<LK>>,
}

#[derive(Debug, PartialEq)]
pub struct LKPrint {
    out: Vec<String>,
    quit: bool,
    state: Rc<RefCell<LK>>,
}

impl LKRead {
    pub fn new(rl: Editor<()>, prompt: String, state: Rc<RefCell<LK>>) -> Self {
        Self {
            rl,
            prompt,
            state,
            cmd: "".to_string(),
        }
    }

    pub fn read(&mut self) -> LKEval {
        let history_file_path = home_dir().unwrap().join(".lesskey_history");
        let history_file = history_file_path.as_path().to_str().unwrap();
        self.rl.clear_history();
        match self.rl.load_history(&history_file) {
            Ok(_) => (),
            Err(_) => {
                self.rl.add_history_entry("ls");
                ()
            }
        }
        self.cmd = match self.rl.readline(&*self.prompt) {
            Ok(str) => str,
            Err(err) => return LKEval::new(Command::Error(LKErr::ReadError(err.to_string())), self.state.clone()),
        };
        self.rl.add_history_entry(self.cmd.as_str());
        match self.rl.save_history(&history_file) {
            Ok(_) => (),
            Err(_) => (),
        }
        match command_parser::cmd(self.cmd.as_str()) {
            Ok(cmd) => LKEval::new(cmd, self.state.clone()),
            Err(err) => LKEval::new(Command::Error(LKErr::ParseError(err)), self.state.clone()),
        }
    }

    pub fn refresh(&mut self) {}

    pub fn quit(&mut self) {}
}

impl<'a> LKEval<'a> {
    pub fn new(cmd: Command<'a>, state: Rc<RefCell<LK>>) -> Self {
        Self { cmd, state }
    }

    fn get_password(&self, name: &String) -> Option<PasswordRef> {
        match self.state.borrow().db.get(name) {
            Some(pwd) => Some(pwd.clone()),
            None => match self.state.borrow().ls.get(name) {
                Some(pwd) => Some(pwd.clone()),
                None => None,
            },
        }
    }

    fn read_master(&self, pwd: PasswordRef) -> String {
        let parent = match &pwd.borrow().parent {
            Some(p) => p.borrow().name.clone(),
            None => Rc::new("/".to_string()),
        };
        let secret = match self.state.borrow().secrets.get(&parent) {
            Some(p) => Some(p.clone()),
            None => None,
        };
        match (pwd.borrow().parent.clone(), secret) {
            (_, Some(s)) => s.to_string(),
            (None, None) => {
                let password = prompt_password("Master: ").unwrap();
                self.state.borrow_mut().secrets.insert(Rc::new("/".to_string()), password.clone());
                password
            }
            (Some(pn), None) => {
                let password = prompt_password(format!("Password for {}: ", pn.borrow().name)).unwrap();
                if password.len() > 0 {
                    self.state.borrow_mut().secrets.insert(pn.borrow().name.clone(), password.clone());
                    password
                } else {
                    let master = self.read_master(pn.clone());
                    let password = pn.borrow().encode(master.as_str());
                    self.state.borrow_mut().secrets.insert(pn.borrow().name.clone(), password.clone());
                    password
                }
            }
        }
    }

    fn cmd_enc(&self, out: &mut Vec<String>, name: &String) {
        let root_folder = Rc::new("/".to_string());
        if name == "/" && self.state.borrow().secrets.contains_key(&root_folder) {
            out.push(self.state.borrow().secrets.get(&root_folder).unwrap().to_string());
            return;
        }
        let pwd = match self.get_password(name) {
            Some(p) => p.clone(),
            None => {
                out.push(format!("error: name {} not found", name));
                return;
            }
        };
        let name = pwd.borrow().name.clone();
        if self.state.borrow().secrets.contains_key(&name) {
            out.push(self.state.borrow().secrets.get(&name).unwrap().to_string());
            return;
        }
        let sec = self.read_master(pwd.clone());
        out.push(pwd.borrow().encode(sec.as_str()));
    }

    fn cmd_ls(&self, out: &mut Vec<String>) {
        let mut tmp: Vec<PasswordRef> = vec![];
        for (_, name) in &self.state.borrow().db {
            tmp.push(name.clone());
        }
        tmp.sort_by(|a, b| a.borrow().name.cmp(&b.borrow().name));
        self.state.borrow_mut().ls.clear();
        let mut counter = 1;
        for pwd in tmp {
            let key = Radix::new(counter, 36).unwrap().to_string();
            counter += 1;
            self.state.borrow_mut().ls.insert(key.clone(), pwd.clone());
            out.push(format!("{:>3} {}", key, pwd.borrow().to_string()));
        }
    }

    pub fn eval(&self) -> LKPrint {
        let mut out: Vec<String> = vec![];
        let mut quit: bool = false;

        match &self.cmd {
            Command::Quit => {
                out.push("Bye!".to_string());
                quit = true;
            }
            Command::Ls => self.cmd_ls(&mut out),
            Command::Add(name) => {
                if self.state.borrow().db.get(&name.borrow().name).is_some() {
                    out.push("error: password already exist".to_string());
                } else {
                    self.state.borrow_mut().db.insert(name.borrow().name.clone(), name.clone());
                    self.state.borrow().fix_hierarchy();
                }
            }
            Command::Comment(name, comment) => match self.get_password(name) {
                Some(pwd) => {
                    pwd.borrow_mut().comment = match comment {
                        Some(c) => Some(c.to_string()),
                        None => None,
                    }
                }
                None => out.push("error: password not found".to_string()),
            },
            Command::Rm(name) => match self.get_password(name) {
                Some(pwd) => {
                    self.state.borrow_mut().db.remove(&pwd.borrow().name);
                    out.push(format!("removed {}", pwd.borrow().name));
                }
                None => out.push("error: password not found".to_string()),
            },
            Command::Enc(name) => self.cmd_enc(&mut out, name),
            Command::Pass(name) => match self.get_password(name) {
                Some(p) => {
                    self.state.borrow_mut().secrets.insert(p.borrow().name.clone(), prompt_password(format!("Password for {}: ", p.borrow().name)).unwrap());
                }
                None => {
                    if name == "/" {
                        self.state.borrow_mut().secrets.insert(Rc::new("/".to_string()), prompt_password("Master: ").unwrap());
                    } else {
                        out.push(format!("error: password with name {} not found", name));
                    }
                }
            },
            Command::Help => {
                out.push("HELP".to_string());
            }
            Command::Mv(name, folder) => match self.get_password(name) {
                Some(pwd) => {
                    if folder == "/" {
                        pwd.borrow_mut().parent = None
                    } else {
                        match self.get_password(folder) {
                            Some(fld) => {
                                pwd.borrow_mut().parent = Some(fld.clone());
                                fix_password_recursion(pwd.clone());
                            }
                            None => out.push(format!("error: folder {} not found", folder)),
                        }
                    }
                }
                None => out.push(format!("error: password with name {} not found", name)),
            },
            Command::Error(err) => match err {
                LKErr::ParseError(e) => out.push(e.to_string()),
                LKErr::ReadError(e) => out.push(e.to_string()),
                LKErr::Error(e) => out.push(format!("error: {}", e.to_string())),
            },
        }

        LKPrint::new(out, quit, self.state.clone())
    }
}

impl LKPrint {
    pub fn new(out: Vec<String>, quit: bool, state: Rc<RefCell<LK>>) -> Self {
        Self { out, quit, state }
    }

    pub fn print(&mut self) -> bool {
        for line in &self.out {
            println!("{}", line);
        }
        return !self.quit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::Password;
    use crate::structs::Mode;
    use chrono::naive::NaiveDate;
    use std::collections::HashMap;

    #[test]
    fn exec_cmds_basic() {
        let lk = Rc::new(RefCell::new(LK::new()));
        assert_eq!(LKEval::new(Command::Ls, lk.clone()).eval(), LKPrint::new(vec![], false, lk.clone()));
        let pwd1 = Rc::new(RefCell::new(Password {
            name: Rc::new("t1".to_string()),
            prefix: None,
            length: None,
            mode: Mode::Regular,
            seq: 99,
            date: NaiveDate::from_ymd_opt(2022, 12, 30).unwrap(),
            comment: Some("comment".to_string()),
            parent: None,
        }));
        assert_eq!(LKEval::new(Command::Add(pwd1.clone()), lk.clone()).eval().state.borrow().db, {
            let mut db = HashMap::new();
            db.insert(pwd1.borrow().name.clone(), pwd1.clone());
            db
        });
        assert_eq!(LKEval::new(Command::Ls, lk.clone()).eval(), LKPrint::new(vec!["  1 t1 R 99 2022-12-30 comment".to_string()], false, lk.clone()));
        assert_eq!(LKEval::new(Command::Quit, lk.clone()).eval(), LKPrint::new(vec!["Bye!".to_string()], true, lk.clone()));
        let pwd2 = Rc::new(RefCell::new(Password {
            name: Rc::new("t2".to_string()),
            prefix: None,
            length: None,
            mode: Mode::Regular,
            seq: 99,
            date: NaiveDate::from_ymd_opt(2022, 12, 31).unwrap(),
            comment: Some("bli blup".to_string()),
            parent: None,
        }));
        assert_eq!(LKEval::new(Command::Add(pwd2.clone()), lk.clone()).eval().state.borrow().db, {
            let mut db = HashMap::new();
            db.insert(pwd1.borrow().name.clone(), pwd1.clone());
            db.insert(pwd2.borrow().name.clone(), pwd2.clone());
            db
        });
        assert_eq!(
            LKEval::new(Command::Ls, lk.clone()).eval(),
            LKPrint::new(vec!["  1 t1 R 99 2022-12-30 comment".to_string(), "  2 t2 R 99 2022-12-31 bli blup".to_string()], false, lk.clone())
        );
        assert_eq!(LKEval::new(Command::Rm("2".to_string()), lk.clone()).eval(), LKPrint::new(vec!["removed t2".to_string()], false, lk.clone()));
        assert_eq!(LKEval::new(Command::Ls, lk.clone()).eval(), LKPrint::new(vec!["  1 t1 R 99 2022-12-30 comment".to_string()], false, lk.clone()));
    }
}

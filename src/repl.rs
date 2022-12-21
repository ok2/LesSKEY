use regex::Regex;
use rpassword::prompt_password;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::io::{BufWriter, Write};
use std::{cell::RefCell, rc::Rc};

use crate::lk::LK;
use crate::parser::command_parser;
use crate::password::{fix_password_recursion, Name, PasswordRef};
use crate::structs::{Command, LKErr, LKOut, Radix, CORRECT_FILE, DUMP_FILE, HISTORY_FILE};
use crate::utils::{call_cmd_with_input, get_cmd_args_from_command, get_copy_command_from_env};

#[derive(Debug)]
pub struct LKRead {
    pub rl: Editor<()>,
    pub prompt: String,
    pub state: Rc<RefCell<LK>>,
    pub cmd: String,
    pub read_password: fn(String) -> std::io::Result<String>,
}

#[derive(Debug)]
pub struct LKEval<'a> {
    pub cmd: Command<'a>,
    pub state: Rc<RefCell<LK>>,
    pub read_password: fn(String) -> std::io::Result<String>,
}

#[derive(Debug, PartialEq)]
pub struct LKPrint {
    pub out: LKOut,
    pub quit: bool,
    pub state: Rc<RefCell<LK>>,
}

impl LKRead {
    pub fn new(rl: Editor<()>, prompt: String, state: Rc<RefCell<LK>>) -> Self {
        Self {
            rl,
            prompt,
            state,
            cmd: "".to_string(),
            read_password: prompt_password,
        }
    }

    pub fn read(&mut self) -> LKEval {
        let history_file = HISTORY_FILE.to_str().unwrap();
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
            Err(ReadlineError::Eof | ReadlineError::Interrupted) => "quit".to_string(),
            Err(err) => {
                return LKEval::new(
                    Command::Error(LKErr::ReadError(err.to_string())),
                    self.state.clone(),
                    self.read_password,
                )
            }
        };
        self.rl.add_history_entry(self.cmd.as_str());
        match self.rl.save_history(&history_file) {
            Ok(_) => (),
            Err(_) => (),
        }
        match command_parser::cmd(self.cmd.as_str()) {
            Ok(cmd) => LKEval::new(cmd, self.state.clone(), self.read_password),
            Err(err) => LKEval::new(Command::Error(LKErr::ParseError(err)), self.state.clone(), self.read_password),
        }
    }

    pub fn refresh(&mut self) {}

    pub fn quit(&mut self) {}
}

impl<'a> LKEval<'a> {
    pub fn new(cmd: Command<'a>, state: Rc<RefCell<LK>>, read_password: fn(String) -> std::io::Result<String>) -> Self {
        Self {
            cmd,
            state,
            read_password,
        }
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

    fn read_master(&self, out: &LKOut, pwd: PasswordRef, read: bool) -> Option<String> {
        if read {
            match self.read_master(&out, pwd.clone(), false) {
                Some(p) => {
                    return Some(p);
                }
                None => (),
            }
        }
        let parent = match &pwd.borrow().parent {
            Some(p) => p.borrow().name.to_string(),
            None => "/".to_string(),
        };
        let secret = match self.state.borrow().secrets.get(&parent) {
            Some(p) => Some(p.clone()),
            None => None,
        };
        match (pwd.borrow().parent.clone(), secret) {
            (_, Some(s)) => Some(s.to_string()),
            (None, None) => {
                if read {
                    match (self.read_password)("Master: ".to_string()) {
                        Ok(password) => {
                            let name = "/".to_string();
                            self.cmd_correct(&out, &name, true, Some(password.clone()));
                            self.state.borrow_mut().secrets.insert(name, password.clone());
                            Some(password)
                        }
                        Err(_) => None,
                    }
                } else {
                    None
                }
            }
            (Some(pn), None) => {
                let password = if read {
                    (self.read_password)(format!("Password for {}: ", pn.borrow().name)).ok()
                } else {
                    None
                };
                if password.is_some() && password.as_ref().unwrap().len() > 0 {
                    let name = pn.borrow().name.to_string();
                    self.cmd_correct(&out, &name, true, Some(password.as_ref().unwrap().clone()));
                    self.state.borrow_mut().secrets.insert(name, password.as_ref().unwrap().clone());
                    password
                } else {
                    match self.read_master(&out, pn.clone(), read) {
                        Some(master) => {
                            let password = pn.borrow().encode(master.as_str());
                            let name = pn.borrow().name.to_string();
                            self.cmd_correct(&out, &name, true, Some(master));
                            self.state.borrow_mut().secrets.insert(name, password.clone());
                            Some(password)
                        }
                        None => None,
                    }
                }
            }
        }
    }

    fn cmd_enc(&self, out: &LKOut, name: &String) -> Option<(String, String)> {
        let root_folder = "/".to_string();
        let (name, pass) = if name == "/" && self.state.borrow().secrets.contains_key(&root_folder) {
            (root_folder.to_string(), self.state.borrow().secrets.get(&root_folder).unwrap().to_string())
        } else {
            let pwd = match self.get_password(name) {
                Some(p) => p.clone(),
                None => {
                    out.e(format!("error: name {} not found", name));
                    return None;
                }
            };
            let name = pwd.borrow().name.to_string();
            if self.state.borrow().secrets.contains_key(&name) {
                (name.clone(), self.state.borrow().secrets.get(&name).unwrap().to_string())
            } else {
                match self.read_master(&out, pwd.clone(), true) {
                    Some(sec) => (name.clone(), pwd.borrow().encode(sec.as_str())),
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

    fn cmd_pb(&self, out: &LKOut, command: &String) {
        match command_parser::cmd(command) {
            Ok(cmd) => {
                let print = LKEval::new(cmd, self.state.clone(), self.read_password).eval();
                let data = print.out.data();
                print.out.copy_err(&out);
                if data.len() > 0 {
                    let (copy_command, copy_cmd_args) = get_copy_command_from_env();
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
            }
            Err(e) => out.e(format!("error: faild to parse command {}: {}", command, e.to_string())),
        };
    }

    fn cmd_source(&self, out: &LKOut, source: &String) {
        let script = if source.trim().ends_with("|") {
            let (cmd, args) = match get_cmd_args_from_command(source.trim().trim_end_matches('|')) {
                Ok(c) => c,
                Err(e) => {
                    out.e(format!("error: failed to parse command {:?}: {}", source, e.to_string()));
                    return;
                }
            };
            match call_cmd_with_input(&cmd, &args, "") {
                Ok(o) => o,
                Err(e) => {
                    out.e(format!("error: failed to execute command {}: {}", cmd, e.to_string()));
                    return;
                }
            }
        } else {
            let script = shellexpand::full(source).unwrap().into_owned();
            match std::fs::read_to_string(script) {
                Ok(script) => script,
                Err(e) => {
                    out.e(format!("error: failed to read file {}: {}", source, e.to_string()));
                    return;
                }
            }
        };
        match command_parser::script(&script) {
            Ok(cmd_list) => {
                for cmd in cmd_list {
                    let print = LKEval::new(cmd, self.state.clone(), prompt_password).eval();
                    print.out.copy(&out);
                }
            }
            Err(e) => {
                out.e(format!("error: {}", e.to_string()));
                return;
            }
        };
    }

    fn cmd_dump(&self, out: &LKOut, script: &Option<String>) {
        let script = match script {
            Some(p) => p,
            None => DUMP_FILE.to_str().unwrap(),
        };
        let script = shellexpand::full(script).unwrap().into_owned();
        fn save_dump(data: &HashMap<Name, PasswordRef>, script: &String) -> std::io::Result<()> {
            let file = fs::File::create(script)?;
            let mut writer = BufWriter::new(file);
            let mut vals = data.values().map(|v| v.clone()).collect::<Vec<PasswordRef>>();
            vals.sort_by(|a, b| a.borrow().name.cmp(&b.borrow().name));
            for pwd in vals {
                writeln!(writer, "add {}", pwd.borrow().to_string())?
            }
            Ok(())
        }
        if script.trim().starts_with("|") {
            let (cmd, args) = match get_cmd_args_from_command(script.trim().trim_start_matches('|')) {
                Ok(c) => c,
                Err(e) => {
                    out.e(format!("error: failed to parse command {:?}: {}", script, e.to_string()));
                    return;
                }
            };
            let data = self
                .state
                .borrow()
                .db
                .values()
                .map(|v| format!("add {}", v.borrow().to_string()))
                .collect::<Vec<String>>()
                .join("\n");
            let output = match call_cmd_with_input(&cmd, &args, data.as_str()) {
                Ok(o) => o,
                Err(e) => {
                    out.e(format!("error: failed to execute command {}: {}", cmd, e.to_string()));
                    return;
                }
            };
            if output.len() > 0 {
                out.e(format!("Passwords dumped to command {} and got following output:", cmd));
                out.o(output);
            } else {
                out.o(format!("Passwords dumped to command {}", cmd));
            }
        } else {
            match save_dump(&self.state.borrow().db, &script) {
                Ok(()) => out.o(format!("Passwords dumped to {}", script)),
                Err(e) => out.e(format!("error: failed to dump passswords to {}: {}", script, e.to_string())),
            };
        }
    }

    fn cmd_ls(&self, out: &LKOut, filter: String) {
        let re = match Regex::new(&filter) {
            Ok(re) => re,
            Err(e) => {
                out.e(format!("error: failed to parse re: {:?}", e));
                return;
            }
        };
        let mut tmp: Vec<PasswordRef> = vec![];
        for (_, name) in &self.state.borrow().db {
            if re.find(&name.borrow().to_string()).is_some() {
                tmp.push(name.clone());
            } else if re.find(&name.borrow().name).is_some() {
                tmp.push(name.clone());
            } else if name.borrow().comment.is_some() && re.find(&name.borrow().comment.as_ref().unwrap()).is_some() {
                tmp.push(name.clone());
            }
        }
        tmp.sort_by(|a, b| a.borrow().name.cmp(&b.borrow().name));
        self.state.borrow_mut().ls.clear();
        let mut counter = 1;
        for pwd in tmp {
            let key = Radix::new(counter, 36).unwrap().to_string();
            counter += 1;
            self.state.borrow_mut().ls.insert(key.clone(), pwd.clone());
            out.o(format!("{:>3} {}", key, pwd.borrow().to_string()));
        }
    }

    fn cmd_correct(&self, out: &LKOut, name: &String, correct: bool, check: Option<String>) {
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
            let file = fs::File::open(CORRECT_FILE.to_str().unwrap())?;
            let reader = BufReader::new(file);
            let mut lines = HashSet::new();
            for line in reader.lines() {
                lines.insert(line?.trim().to_owned());
            }
            Ok(lines)
        }
        let mut data = match load_lines() {
            Ok(d) => d,
            Err(_) => HashSet::new(),
        };
        let mut sha1 = Sha1::new();
        sha1.update(name.to_string());
        sha1.update(pwd);
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
            let file = fs::File::create(CORRECT_FILE.to_str().unwrap())?;
            let mut writer = BufWriter::new(file);
            for entry in data {
                writeln!(writer, "{}", entry)?;
            }
            Ok(())
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

    pub fn eval(&self) -> LKPrint {
        let out = LKOut::new();
        let mut quit: bool = false;

        match &self.cmd {
            Command::Quit => {
                out.e("Bye!".to_string());
                quit = true;
            }
            Command::Ls(filter) => self.cmd_ls(&out, filter.to_string()),
            Command::Add(name) => {
                let state = &mut self.state.borrow_mut();
                let mut fix = false;
                {
                    let db = &mut state.db;
                    let pwname = &name.borrow().name.to_string();
                    if db.get(pwname).is_some() {
                        out.e(format!("error: password {} already exist", pwname));
                    } else {
                        db.insert(pwname.to_string(), name.clone());
                        fix = true;
                    }
                }
                if fix {
                    state.fix_hierarchy();
                }
            }
            Command::Comment(name, comment) => match self.get_password(name) {
                Some(pwd) => {
                    pwd.borrow_mut().comment = match comment {
                        Some(c) => Some(c.to_string()),
                        None => None,
                    }
                }
                None => out.e("error: password not found".to_string()),
            },
            Command::Rm(name) => match self.get_password(name) {
                Some(pwd) => {
                    self.state.borrow_mut().db.remove(pwd.borrow().name.as_ref());
                    out.o(format!("removed {}", pwd.borrow().name));
                }
                None => out.e(format!("error: password {} not found", name)),
            },
            Command::Enc(name) => {
                self.cmd_enc(&out, name);
            }
            Command::PasteBuffer(command) => self.cmd_pb(&out, command),
            Command::Source(script) => self.cmd_source(&out, script),
            Command::Dump(script) => self.cmd_dump(&out, script),
            Command::Pass(name) => match self.get_password(name) {
                Some(p) => {
                    let pwd = (self.read_password)(format!("Password for {}: ", p.borrow().name)).unwrap();
                    self.cmd_correct(&out, &p.borrow().name.as_ref(), true, Some(pwd.clone()));
                    self.state.borrow_mut().secrets.insert(p.borrow().name.to_string(), pwd);
                }
                None => {
                    if name == "/" {
                        let pwd = (self.read_password)("Master: ".to_string()).unwrap();
                        self.cmd_correct(&out, &"/".to_string(), true, Some(pwd.clone()));
                        self.state
                            .borrow_mut()
                            .secrets
                            .insert("/".to_string(), (self.read_password)("Master: ".to_string()).unwrap());
                    } else {
                        out.e(format!("error: password with name {} not found", name));
                    }
                }
            },
            Command::UnPass(name) => match self.state.borrow_mut().secrets.remove(name) {
                Some(_) => out.o(format!("Removed saved password for {}", name)),
                None => out.e(format!("error: saved password for {} not found", name)),
            },
            Command::Correct(name) => self.cmd_correct(&out, name, true, None),
            Command::Uncorrect(name) => self.cmd_correct(&out, name, false, None),
            Command::Noop => (),
            Command::Help => {
                out.o("HELP".to_string());
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
                            None => out.e(format!("error: folder {} not found", folder)),
                        }
                    }
                }
                None => out.e(format!("error: password with name {} not found", name)),
            },
            Command::Error(error) => match error {
                LKErr::ParseError(e) => out.e(e.to_string()),
                LKErr::ReadError(e) => out.e(e.to_string()),
                LKErr::Error(e) => out.e(format!("error: {}", e.to_string())),
            },
        }

        LKPrint::new(out, quit, self.state.clone())
    }
}

impl LKPrint {
    pub fn new(out: LKOut, quit: bool, state: Rc<RefCell<LK>>) -> Self {
        Self { out, quit, state }
    }

    pub fn print(&mut self) -> bool {
        self.out.print_err();
        self.out.print_out();
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

    impl<'a> LKEval<'a> {
        pub fn news(cmd: Command<'a>, state: Rc<RefCell<LK>>) -> Self {
            Self {
                cmd,
                state,
                read_password: |_| {
                    Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "could not read password"))
                },
            }
        }
    }

    #[test]
    fn exec_cmds_basic() {
        let lk = Rc::new(RefCell::new(LK::new()));
        assert_eq!(
            LKEval::news(Command::Ls(".".to_string()), lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec![], vec![]), false, lk.clone())
        );
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
        assert_eq!(LKEval::news(Command::Add(pwd1.clone()), lk.clone()).eval().state.borrow().db, {
            let mut db = HashMap::new();
            db.insert(pwd1.borrow().name.to_string(), pwd1.clone());
            db
        });
        assert_eq!(
            LKEval::news(Command::Ls(".".to_string()), lk.clone()).eval(),
            LKPrint::new(
                LKOut::from_vecs(vec!["  1 t1 R 99 2022-12-30 comment".to_string()], vec![]),
                false,
                lk.clone()
            )
        );
        assert_eq!(
            LKEval::news(Command::Quit, lk.clone()).eval(),
            LKPrint::new(LKOut::from_vecs(vec![], vec!["Bye!".to_string()]), true, lk.clone())
        );
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
        assert_eq!(LKEval::news(Command::Add(pwd2.clone()), lk.clone()).eval().state.borrow().db, {
            let mut db = HashMap::new();
            db.insert(pwd1.borrow().name.to_string(), pwd1.clone());
            db.insert(pwd2.borrow().name.to_string(), pwd2.clone());
            db
        });
        assert_eq!(
            LKEval::news(Command::Ls(".".to_string()), lk.clone()).eval(),
            LKPrint::new(
                LKOut::from_vecs(
                    vec!["  1 t1 R 99 2022-12-30 comment".to_string(), "  2 t2 R 99 2022-12-31 bli blup".to_string()],
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
                LKOut::from_vecs(vec!["  1 t1 R 99 2022-12-30 comment".to_string()], vec![]),
                false,
                lk.clone()
            )
        );
    }

    #[test]
    fn read_pwd_test() {
        let lk = Rc::new(RefCell::new(LK::new()));
        let t1 = Rc::new(RefCell::new(Password::new(
            None,
            "t1".to_string(),
            None,
            Mode::Regular,
            99,
            NaiveDate::from_ymd_opt(2022, 12, 30).unwrap(),
            None,
        )));
        let t2 = Rc::new(RefCell::new(Password::new(
            None,
            "t2".to_string(),
            None,
            Mode::Regular,
            99,
            NaiveDate::from_ymd_opt(2022, 12, 30).unwrap(),
            None,
        )));
        let t3 = Rc::new(RefCell::new(Password::new(
            None,
            "t3".to_string(),
            None,
            Mode::Regular,
            99,
            NaiveDate::from_ymd_opt(2022, 12, 30).unwrap(),
            None,
        )));
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
            LKEval::new(Command::Enc("t3".to_string()), lk.clone(), |p| if p == "NULL" {
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
            LKEval::new(Command::Enc("t3".to_string()), lk.clone(), |p| if p == "Master: " {
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
            LKEval::new(Command::Enc("t2".to_string()), lk.clone(), |p| if p == "NULL" {
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
            LKEval::new(Command::Enc("t1".to_string()), lk.clone(), |p| if p == "NULL" {
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
}

use regex::Regex;
use sha1::{Digest, Sha1};
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::io::{BufWriter, Write};

use crate::parser::command_parser;
use crate::password::fix_password_recursion;
use crate::password::{Name, Password, PasswordRef};
use crate::repl::LKEval;
use crate::structs::{LKOut, Radix, CORRECT_FILE, DUMP_FILE};
use crate::utils::editor::password;
use crate::utils::{call_cmd_with_input, get_cmd_args_from_command, get_copy_command_from_env, rnd};

impl<'a> LKEval<'a> {
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

    pub fn cmd_pb(&self, out: &LKOut, command: &String) {
        match command_parser::cmd(command) {
            Ok(cmd) => {
                let print = LKEval::new(self.rl.clone(), cmd, self.state.clone(), self.read_password).eval();
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

    pub fn cmd_source(&self, out: &LKOut, source: &String) -> bool {
        let script = if source.trim().ends_with("|") {
            let (cmd, args) = match get_cmd_args_from_command(source.trim().trim_end_matches('|')) {
                Ok(c) => c,
                Err(e) => {
                    out.e(format!("error: failed to parse command {:?}: {}", source, e.to_string()));
                    return false;
                }
            };
            match call_cmd_with_input(&cmd, &args, "") {
                Ok(o) => o,
                Err(e) => {
                    out.e(format!("error: failed to execute command {}: {}", cmd, e.to_string()));
                    return false;
                }
            }
        } else {
            let script = shellexpand::full(source).unwrap().into_owned();
            match std::fs::read_to_string(script) {
                Ok(script) => script,
                Err(e) => {
                    out.e(format!("error: failed to read file {}: {}", source, e.to_string()));
                    return false;
                }
            }
        };
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
        false
    }

    pub fn cmd_dump(&self, out: &LKOut, script: &Option<String>) {
        let script = match script {
            Some(p) => p,
            None => DUMP_FILE.to_str().unwrap(),
        };
        let script = shellexpand::full(script).unwrap().into_owned();
        fn save_dump(data: &HashMap<Name, PasswordRef>, script: &String) -> std::io::Result<()> {
            let file = fs::File::create(script)?;
            let mut writer = BufWriter::new(file);
            let mut vals = data.values().map(|v| v.clone()).collect::<Vec<PasswordRef>>();
            vals.sort_by(|a, b| a.lock().borrow().name.cmp(&b.lock().borrow().name));
            for pwd in vals {
                writeln!(writer, "add {}", pwd.lock().borrow().to_string())?
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
                .lock()
                .borrow()
                .db
                .values()
                .map(|v| format!("add {}", v.lock().borrow().to_string()))
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
                out.e(format!("Passwords saved to command {} and got following output:", cmd));
                out.o(output);
            } else {
                out.o(format!("Passwords saved to command {}", cmd));
            }
        } else if script.trim() == "-" {
            let mut vals = (&self.state.lock().borrow().db).values().map(|v| v.clone()).collect::<Vec<PasswordRef>>();
            vals.sort_by(|a, b| a.lock().borrow().name.cmp(&b.lock().borrow().name));
            for pwd in vals {
                out.o(format!("add {}", pwd.lock().borrow().to_string()))
            }
        } else {
            match save_dump(&self.state.lock().borrow().db, &script) {
                Ok(()) => out.o(format!("Passwords saved to file {}", script)),
                Err(e) => out.e(format!("error: failed to dump passswords to {}: {}", script, e.to_string())),
            };
        }
    }

    pub fn cmd_ls<F>(&self, out: &LKOut, filter: String, sort_by: F)
    where
        F: Fn(&PasswordRef, &PasswordRef) -> std::cmp::Ordering,
    {
        let re = match Regex::new(&filter) {
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
            out.o(format!("{:>3} {}", key, pwd.lock().borrow().to_string()));
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

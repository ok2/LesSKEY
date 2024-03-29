use crate::password::{Comment, Name, PasswordRef};
use num_integer::Integer;
use parking_lot::Mutex;
use parking_lot::ReentrantMutex;
use std::cell::RefCell;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use crate::lk::LK;
use crate::parser::command_parser;
use crate::repl::{LKEval, LKRead};
use crate::utils::editor::{password, Editor};
use crate::utils::home;

lazy_static! {
    pub static ref HISTORY_FILE: Box<Path> = {
        match std::env::var("HEL_HISTORY") {
            Ok(v) => Path::new(shellexpand::full(&v).unwrap().into_owned().as_str()).to_path_buf().into_boxed_path(),
            _ => home::dir().join(".hel_history").into_boxed_path(),
        }
    };
    pub static ref PROMPT_SETTING: String = {
        match std::env::var("HEL_PROMPT") {
            Ok(v) => v,
            _ => "> ".to_string(),
        }
    };
    pub static ref INIT_FILE: Box<Path> = {
        match std::env::var("HEL_INIT") {
            Ok(v) => Path::new(shellexpand::full(&v).unwrap().into_owned().as_str()).to_path_buf().into_boxed_path(),
            _ => home::dir().join(".helrc").into_boxed_path(),
        }
    };
    pub static ref CORRECT_FILE: Box<Path> = {
        match std::env::var("HEL_CORRECT") {
            Ok(v) => Path::new(shellexpand::full(&v).unwrap().into_owned().as_str()).to_path_buf().into_boxed_path(),
            _ => home::dir().join(".hel_correct").into_boxed_path(),
        }
    };
    pub static ref DUMP_FILE: Box<Path> = {
        match std::env::var("HEL_DUMP") {
            Ok(v) => Path::new(shellexpand::full(&v).unwrap().into_owned().as_str()).to_path_buf().into_boxed_path(),
            _ => home::dir().join(".hel_dump").into_boxed_path(),
        }
    };
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum LKErr<'a> {
    #[error("Error: {0}")]
    Error(&'a str),
    #[error("Error: end of file")]
    EOF,
    #[error("Failed to read the line: {0}")]
    ReadError(String),
    #[error("Failed to parse: {0}")]
    ParseError(peg::error::ParseError<peg::str::LineCol>),
}

#[derive(Debug)]
pub enum Command<'a> {
    Add(PasswordRef),
    Keep(Name),
    Ls(String),
    Ld(String),
    Mv(Name, Name),
    Rm(Name),
    Enc(Name),
    Gen(u32, PasswordRef),
    Pass(Name, Option<String>),
    UnPass(Name),
    Correct(Name),
    Uncorrect(Name),
    PasteBuffer(String),
    Source(String),
    Dump(Option<String>),
    Comment(Name, Comment),
    Error(LKErr<'a>),
    Noop,
    Help,
    Quit,
}

impl<'a> PartialEq for Command<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Command::Add(s), Command::Add(o)) => *s.lock() == *o.lock(),
            (Command::Keep(s), Command::Keep(o)) => s == o,
            (Command::Ls(s), Command::Ls(o)) => s == o,
            (Command::Ld(s), Command::Ld(o)) => s == o,
            (Command::Mv(a, b), Command::Mv(x, y)) => a == x && b == y,
            (Command::Rm(s), Command::Rm(o)) => s == o,
            (Command::Enc(s), Command::Enc(o)) => s == o,
            (Command::Gen(a, b), Command::Gen(x, y)) => a == x && *b.lock() == *y.lock(),
            (Command::Pass(a, b), Command::Pass(x, y)) => a == x && b == y,
            (Command::UnPass(s), Command::UnPass(o)) => s == o,
            (Command::Correct(s), Command::Correct(o)) => s == o,
            (Command::Uncorrect(s), Command::Uncorrect(o)) => s == o,
            (Command::PasteBuffer(s), Command::PasteBuffer(o)) => s == o,
            (Command::Source(s), Command::Source(o)) => s == o,
            (Command::Dump(s), Command::Dump(o)) => s == o,
            (Command::Comment(a, b), Command::Comment(x, y)) => a == x && b == y,
            (Command::Error(s), Command::Error(o)) => s == o,
            (Command::Noop, Command::Noop) => true,
            (Command::Help, Command::Help) => true,
            (Command::Quit, Command::Quit) => true,
            _ => false,
        }
    }
}

impl<'a> std::fmt::Display for Command<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Add(s) => write!(f, "add {}", s.lock().borrow().to_string().trim()),
            Command::Keep(s) => write!(f, "keep {}", s),
            Command::Ls(s) => write!(f, "ls {}", s),
            Command::Ld(s) => write!(f, "ld {}", s),
            Command::Mv(a, b) => write!(f, "mv {} {}", a, b),
            Command::Rm(s) => write!(f, "rm {}", s),
            Command::Enc(s) => write!(f, "enc {}", s),
            Command::Gen(a, b) => write!(f, "gen{} {}", a, b.lock().borrow().to_string().trim()),
            Command::Pass(a, None) => write!(f, "pass {}", a),
            Command::Pass(a, Some(b)) => write!(f, "pass {} {}", a, b),
            Command::UnPass(s) => write!(f, "unpass {}", s),
            Command::Correct(s) => write!(f, "correct {}", s),
            Command::Uncorrect(s) => write!(f, "uncorrect {}", s),
            Command::PasteBuffer(s) => write!(f, "pb {}", s),
            Command::Source(s) => write!(f, "source {}", s),
            Command::Dump(None) => write!(f, "dump"),
            Command::Dump(Some(s)) => write!(f, "dump {}", s),
            Command::Comment(a, None) => write!(f, "comment {}", a),
            Command::Comment(a, Some(b)) => write!(f, "comment {} {}", a, b),
            Command::Error(s) => write!(f, "error {}", s),
            Command::Noop => write!(f, "noop"),
            Command::Help => write!(f, "help"),
            Command::Quit => write!(f, "quit"),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum Mode {
    Regular,
    RegularUpcase,
    NoSpace,
    NoSpaceUpcase,
    NoSpaceCamel,
    Hex,
    HexUpcase,
    Base64,
    Base64Upcase,
    Decimal,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Mode::Regular => "R",
                Mode::RegularUpcase => "UR",
                Mode::NoSpace => "N",
                Mode::NoSpaceUpcase => "UN",
                Mode::NoSpaceCamel => "C",
                Mode::Hex => "H",
                Mode::HexUpcase => "UH",
                Mode::Base64 => "B",
                Mode::Base64Upcase => "UB",
                Mode::Decimal => "D",
            }
            .to_string()
        )
    }
}

#[derive(Debug)]
pub struct LKOut {
    pub out: Option<Arc<Mutex<Vec<String>>>>,
    pub err: Option<Arc<Mutex<Vec<String>>>>,
}

impl LKOut {
    pub fn new() -> Self {
        Self {
            out: Some(Arc::new(Mutex::new(vec![]))),
            err: Some(Arc::new(Mutex::new(vec![]))),
        }
    }

    pub fn from_lkout(out: Option<Arc<Mutex<Vec<String>>>>, err: Option<Arc<Mutex<Vec<String>>>>) -> Self {
        let o = match out {
            Some(v) => Some(v.clone()),
            None => None,
        };
        let e = match err {
            Some(v) => Some(v.clone()),
            None => None,
        };
        Self { out: o, err: e }
    }

    #[allow(dead_code)]
    pub fn from_vecs(out: Vec<String>, err: Vec<String>) -> Self {
        Self {
            out: Some(Arc::new(Mutex::new(out))),
            err: Some(Arc::new(Mutex::new(err))),
        }
    }

    pub fn copy_out(&self, out: &LKOut) {
        if !self.out.is_some() {
            return;
        }
        for line in self.out.as_ref().unwrap().lock().iter() {
            out.o(line.to_string())
        }
    }

    pub fn copy_err(&self, out: &LKOut) {
        if !self.err.is_some() {
            return;
        }
        for line in self.err.as_ref().unwrap().lock().iter() {
            out.e(line.to_string())
        }
    }

    pub fn print_out(&self) {
        if !self.out.is_some() {
            return;
        }
        for line in self.out.as_ref().unwrap().lock().iter() {
            println!("{}", line);
        }
    }

    pub fn print_err(&self) {
        if !self.err.is_some() {
            return;
        }
        for line in self.err.as_ref().unwrap().lock().iter() {
            eprintln!("{}", line);
        }
    }

    pub fn copy(&self, out: &LKOut) {
        self.copy_err(&out);
        self.copy_out(&out);
    }

    pub fn data(&self) -> String {
        if self.out.is_some() {
            self.out.as_ref().unwrap().lock().join("\n")
        } else {
            "".to_string()
        }
    }

    pub fn output(&self) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        match &self.err {
            Some(o) => {
                for l in &*o.lock() {
                    out.push(l.to_string());
                }
            }
            _ => (),
        }
        match &self.out {
            Some(o) => {
                for l in &*o.lock() {
                    out.push(l.to_string());
                }
            }
            _ => (),
        }
        out
    }

    pub fn active(&self) -> bool {
        self.out.is_some()
    }
    pub fn o(&self, line: String) {
        if self.out.is_some() {
            self.out.as_ref().unwrap().lock().push(line);
        }
    }
    pub fn e(&self, line: String) {
        if self.err.is_some() {
            self.err.as_ref().unwrap().lock().push(line);
        }
    }
}

impl PartialEq for LKOut {
    fn eq(&self, other: &Self) -> bool {
        (match (&self.out, &other.out) {
            (Some(a), Some(b)) => *a.lock() == *b.lock(),
            (None, None) => true,
            _ => false,
        } && match (&self.err, &other.err) {
            (Some(a), Some(b)) => *a.lock() == *b.lock(),
            (None, None) => true,
            _ => false,
        })
    }
}

pub struct Radix {
    x: i32,
    radix: u32,
}

impl Radix {
    pub fn new(x: i32, radix: u32) -> Result<Self, &'static str> {
        if radix < 2 || radix > 36 {
            Err("Unnsupported radix")
        } else {
            Ok(Self { x, radix })
        }
    }
}

impl fmt::Display for Radix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (mut x, negative): (u32, bool) = if self.x < 0 {
            ((self.x * -1).try_into().unwrap(), true)
        } else {
            ((self.x).try_into().unwrap(), false)
        };
        let mut result = Vec::new();

        while x != 0 {
            let (n, m) = x.div_rem(&self.radix);
            result.push(std::char::from_digit(m as u32, self.radix).unwrap());
            x = n;
        }

        if negative {
            write!(f, "-")?;
        }

        for c in result.iter().rev() {
            write!(f, "{}", c)?;
        }
        Ok(())
    }
}

pub fn init() -> Option<LKRead> {
    let lk = Arc::new(ReentrantMutex::new(RefCell::new(LK::new())));
    let editor = Editor::new();

    match std::fs::read_to_string(INIT_FILE.to_str().unwrap()) {
        Ok(script) => match command_parser::script(&script) {
            Ok(cmd_list) => {
                for cmd in cmd_list {
                    if !LKEval::new(editor.clone(), cmd, lk.clone(), password).eval().print() {
                        return None;
                    }
                }
            }
            Err(err) => {
                LKEval::new(editor.clone(), Command::Error(LKErr::ParseError(err)), lk.clone(), password)
                    .eval()
                    .print();
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
        Err(err) => {
            LKEval::new(
                editor.clone(),
                Command::Error(LKErr::Error(
                    format!("Failed to read init file {:?}: {}", INIT_FILE.to_str(), err).as_str(),
                )),
                lk.clone(),
                password,
            )
            .eval()
            .print();
        }
    }
    Some(LKRead::new(editor.clone(), PROMPT_SETTING.to_string(), lk.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::Password;
    use crate::utils::date::Date;
    use std::io::{BufWriter, Write};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_env() {
        std::env::set_var("HEL_HISTORY", "./test_history");
        std::env::set_var("HEL_INIT", "./test_init");
        std::env::set_var("HEL_DUMP", "./test_dump");
        std::env::set_var("HEL_CORRECT", "./test_correct");
        std::env::set_var("HEL_PB", "./test_pb");
        std::env::set_var("HEL_PROMPT", "test> ");

        fn create_init() {
            let file = std::fs::File::create("test_init").unwrap();
            let mut writer = BufWriter::new(file);
            writeln!(writer, "add t1 r 99 2022-10-10").expect("write");
            writeln!(writer, "add t2 r 99 2022-10-10 test ^t1").expect("write");
            writeln!(writer, "add t3 r 99 2022-10-10 ^t2 aoeu").expect("write");
        }

        fn create_pb() {
            let file = std::fs::File::create("test_pb").unwrap();
            let mut writer = BufWriter::new(file);
            let metadata = std::fs::metadata("test_pb").expect("unable to get file metadata");
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o755); // set executable flag
            std::fs::set_permissions("test_pb", permissions).expect("unable to set file permissions");
            writeln!(writer, "#!/bin/sh\ncat >test_pb_out").expect("write");
        }

        fn clear_test_files() {
            #[allow(unused_must_use)]
            {
                std::fs::remove_file("test_history");
                std::fs::remove_file("test_init");
                std::fs::remove_file("test_dump");
                std::fs::remove_file("test_correct");
                std::fs::remove_file("test_pb");
                std::fs::remove_file("test_pb_out");
            }
        }

        defer! {
            clear_test_files();
        }

        clear_test_files();
        create_init();
        create_pb();

        let lkread = init().unwrap();
        assert_eq!(lkread.prompt, "test> ");
        assert_eq!(lkread.state.lock().borrow().db.contains_key("t1"), true);

        let t1 = Password::from_password(Password::new(
            None,
            "t1".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 10, 10),
            None,
        ));
        let t2 = Password::from_password(Password::new(
            None,
            "t2".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 10, 10),
            Some("test".to_string()),
        ));
        t2.lock().borrow_mut().parent = Some(t1.clone());
        let t3 = Password::from_password(Password::new(
            None,
            "t3".to_string(),
            None,
            Mode::Regular,
            99,
            Date::new(2022, 10, 10),
            Some("aoeu".to_string()),
        ));
        t3.lock().borrow_mut().parent = Some(t2.clone());
        assert_eq!(*lkread.state.lock().borrow().db.get("t1").unwrap().lock(), *t1.lock());
        assert_eq!(*lkread.state.lock().borrow().db.get("t2").unwrap().lock(), *t2.lock());
        assert_eq!(*lkread.state.lock().borrow().db.get("t3").unwrap().lock(), *t3.lock());

        LKEval::newd(command_parser::cmd("save").unwrap(), lkread.state.clone(), password).eval().print();
        assert_eq!(
            std::fs::read_to_string("test_dump").expect("read"),
            "add       t1 R 99 2022-10-10\nadd       t2 R 99 2022-10-10 test ^t1\nadd       t3 R 99 2022-10-10 aoeu ^t2\n".to_string()
        );

        let pr = LKEval::newd(command_parser::cmd("enc t3").unwrap(), lkread.state.clone(), |v| {
            if v == "/" {
                Ok("a".to_string())
            } else {
                Ok("".to_string())
            }
        })
        .eval();
        assert_eq!(
            pr.out,
            LKOut::from_vecs(
                vec!["san bud most noon jaw cash".to_string()],
                vec![
                    "warning: password / is not marked as correct".to_string(),
                    "warning: password t1 is not marked as correct".to_string(),
                    "warning: password t2 is not marked as correct".to_string(),
                    "warning: password t3 is not marked as correct".to_string(),
                ]
            )
        );
        lkread.state.lock().borrow_mut().secrets.clear();
        let pr = LKEval::newd(command_parser::cmd("pb enc t3").unwrap(), lkread.state.clone(), |v| {
            if v == "/" {
                Ok("a".to_string())
            } else {
                Ok("".to_string())
            }
        })
        .eval();
        assert_eq!(
            pr.out,
            LKOut::from_vecs(
                vec!["Copied output with command ./test_pb".to_string()],
                vec![
                    "warning: password / is not marked as correct".to_string(),
                    "warning: password t1 is not marked as correct".to_string(),
                    "warning: password t2 is not marked as correct".to_string(),
                    "warning: password t3 is not marked as correct".to_string(),
                ]
            )
        );
        assert_eq!(std::fs::read_to_string("test_pb_out").expect("read"), "san bud most noon jaw cash");
    }
}

use crate::password::{Comment, Name, PasswordRef};
use home::home_dir;
use std::cell::RefCell;
use std::fmt;
use std::path::Path;
use std::rc::Rc;

lazy_static! {
    pub static ref HISTORY_FILE: Box<Path> = {
        match std::env::var("LESSKEY_HISTORY") {
            Ok(v) => Path::new(shellexpand::full(&v).unwrap().into_owned().as_str()).to_path_buf().into_boxed_path(),
            _ => home_dir().unwrap().join(".lesskey_history").into_boxed_path(),
        }
    };
    pub static ref INIT_FILE: Box<Path> = {
        match std::env::var("LESSKEY_INIT") {
            Ok(v) => Path::new(shellexpand::full(&v).unwrap().into_owned().as_str()).to_path_buf().into_boxed_path(),
            _ => home_dir().unwrap().join(".lesskeyrc").into_boxed_path(),
        }
    };
    pub static ref CORRECT_FILE: Box<Path> = {
        match std::env::var("LESSKEY_CORRECT") {
            Ok(v) => Path::new(shellexpand::full(&v).unwrap().into_owned().as_str()).to_path_buf().into_boxed_path(),
            _ => home_dir().unwrap().join(".lesskey_correct").into_boxed_path(),
        }
    };
    pub static ref DUMP_FILE: Box<Path> = {
        match std::env::var("LESSKEY_DUMP") {
            Ok(v) => Path::new(shellexpand::full(&v).unwrap().into_owned().as_str()).to_path_buf().into_boxed_path(),
            _ => home_dir().unwrap().join(".lesskey_dump").into_boxed_path(),
        }
    };
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum LKErr<'a> {
    #[error("Error: {0}")]
    Error(&'a str),
    #[error("Failed to read the line: {0}")]
    ReadError(String),
    #[error("Failed to parse: {0}")]
    ParseError(peg::error::ParseError<peg::str::LineCol>),
}

#[derive(PartialEq, Debug)]
pub enum Command<'a> {
    Add(PasswordRef),
    Ls(String),
    Mv(Name, Name),
    Rm(Name),
    Enc(Name),
    Pass(Name),
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

#[derive(PartialEq, Debug)]
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

#[derive(PartialEq, Debug)]
pub struct LKOut {
    pub out: Option<Rc<RefCell<Vec<String>>>>,
    pub err: Option<Rc<RefCell<Vec<String>>>>,
}

impl LKOut {
    pub fn new() -> Self {
        Self {
            out: Some(Rc::new(RefCell::new(vec![]))),
            err: Some(Rc::new(RefCell::new(vec![]))),
        }
    }

    pub fn from_lkout(out: Option<Rc<RefCell<Vec<String>>>>, err: Option<Rc<RefCell<Vec<String>>>>) -> Self {
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

    pub fn from_vecs(out: Vec<String>, err: Vec<String>) -> Self {
        Self {
            out: Some(Rc::new(RefCell::new(out))),
            err: Some(Rc::new(RefCell::new(err))),
        }
    }

    pub fn copy_out(&self, out: &LKOut) {
        if !self.out.is_some() {
            return;
        }
        for line in self.out.as_ref().unwrap().borrow().iter() {
            out.o(line.to_string())
        }
    }

    pub fn copy_err(&self, out: &LKOut) {
        if !self.err.is_some() {
            return;
        }
        for line in self.err.as_ref().unwrap().borrow().iter() {
            out.e(line.to_string())
        }
    }

    pub fn print_out(&self) {
        if !self.out.is_some() {
            return;
        }
        for line in self.out.as_ref().unwrap().borrow().iter() {
            println!("{}", line);
        }
    }

    pub fn print_err(&self) {
        if !self.err.is_some() {
            return;
        }
        for line in self.err.as_ref().unwrap().borrow().iter() {
            eprintln!("{}", line);
        }
    }

    pub fn copy(&self, out: &LKOut) {
        self.copy_err(&out);
        self.copy_out(&out);
    }

    pub fn data(&self) -> String {
        if self.out.is_some() {
            self.out.as_ref().unwrap().borrow().join("\n")
        } else {
            "".to_string()
        }
    }

    pub fn active(&self) -> bool {
        self.out.is_some()
    }
    pub fn o(&self, line: String) {
        if self.out.is_some() {
            self.out.as_ref().unwrap().borrow_mut().push(line);
        }
    }
    pub fn e(&self, line: String) {
        if self.err.is_some() {
            self.err.as_ref().unwrap().borrow_mut().push(line);
        }
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
        let mut x = self.x;
        // Good for binary formatting of `u128`s
        let mut result = ['\0'; 128];
        let mut used = 0;
        let negative = x < 0;
        if negative {
            x *= -1;
        }
        let mut x = x as u32;
        loop {
            let m = x % self.radix;
            x /= self.radix;

            result[used] = std::char::from_digit(m, self.radix).unwrap();
            used += 1;

            if x == 0 {
                break;
            }
        }

        if negative {
            write!(f, "-")?;
        }

        for c in result[..used].iter().rev() {
            write!(f, "{}", c)?;
        }

        Ok(())
    }
}

/*
impl fmt::Display for Radix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sign = if self.x < 0 { '-' } else { ' ' };
        let mut x: u32 = self.x.abs() as u32;
        write!(f, "{}{}", sign, (0..).map(|_| {
                    let m = x % self.radix;
                    x /= self.radix;
                    (x, std::char::from_digit(m, self.radix).unwrap())
                })
                .take_while(|a| a.0 > 0).map(|b| b.1).collect::<String>()
                .chars().rev().collect::<String>()
        )?;
        Ok(())
    }
}
*/

use crate::password::{Comment, Name, PasswordRef};
use home::home_dir;
use std::fmt;
use std::path::Path;

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
    PasteBuffer(String),
    Source(String),
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

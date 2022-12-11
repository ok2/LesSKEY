use crate::password::{Comment, Name, PasswordRef};
use std::fmt;

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
    Ls,
    Mv(Name, Name),
    Rm(Name),
    Comment(Name, Comment),
    Error(LKErr<'a>),
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
            x*=-1;
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

use crate::password::{Comment, Name, PasswordRef};

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

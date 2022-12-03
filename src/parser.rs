extern crate peg;

use crate::password::Password;
use crate::structs::{Command, LKErr, Mode};
use chrono::naive::NaiveDate;
use std::{cell::RefCell, rc::Rc};

peg::parser! {
    pub grammar command_parser() for str {
        pub rule cmd() -> Command<'input> = c:(
            help_cmd()
            / add_cmd()
            / quit_cmd()
            / error_cmd()
            / ls_cmd()
            / mv_cmd()
            / comment_cmd()
        ) { c }
        pub rule name() -> Password = name:(jname() / pname() / mname() / sname()) { name }

        rule _() -> &'input str = s:$((" " / "\t" / "\r" / "\n")+) { s }
        rule comment() -> String = _ c:$([' '..='~']+) { c.to_string() }
        rule word() -> String = n:$(['!'..='~']+) { n.to_string() }
        rule num() -> u32 = n:$(['0'..='9']+) {? n.parse().or(Err("not a number")) }

        rule pname() -> Password = &(word() _ word() _ num()? mode() _ num() _ date()) pr:word() _ pn:word() _ pl:num()? pm:mode() _ ps:num() _ pd:date() pc:comment()?
        { Password::new(Some(pr), pn, pl, pm, ps, pd, pc) }
        rule jname() -> Password = &(word() _ num()? mode() _ num() _ date()) pn:word() _ pl:num()? pm:mode() _ ps:num() _ pd:date() pc:comment()?
        { Password::new(None, pn, pl, pm, ps, pd, pc) }
        rule mname() -> Password = &(word() _ word() _ num()? mode() _ date()) pr:word() _ pn:word() _ pl:num()? pm:mode() _ pd:date() pc:comment()?
        { Password::new(Some(pr), pn, pl, pm, 99, pd, pc) }
        rule sname() -> Password = &(word() _ num()? mode() _ date()) pn:word() _ pl:num()? pm:mode() _ pd:date() pc:comment()?
        { Password::new(None, pn, pl, pm, 99, pd, pc) }

        rule date() -> NaiveDate = y:$("-"? ['0'..='9']*<1,4>) "-" m:$(['0'..='9']*<1,2>) "-" d:$(['0'..='9']*<1,2>) {?
            let year:  i32 = match y.parse() { Ok(n) => n, Err(_) => return Err("year") };
            let month: u32 = match m.parse() { Ok(n) => n, Err(_) => return Err("month") };
            let day:   u32 = match d.parse() { Ok(n) => n, Err(_) => return Err("day") };
            NaiveDate::from_ymd_opt(year, month, day).ok_or("date")
        }
        rule umode() -> Mode = ("U" / "u") m:$("R" / "r" / "N" / "n" / "H" / "h" / "B" / "b") {?
            match m.to_uppercase().as_str() {
                "R" => Ok(Mode::RegularUpcase),
                "N" => Ok(Mode::NoSpaceUpcase),
                "H" => Ok(Mode::HexUpcase),
                "B" => Ok(Mode::Base64Upcase),
                _ => Err("unknown mode"),
            }
        }
        rule rmode() -> Mode = m:$("R" / "r" / "U" / "u" / "N" / "n" / "H" / "h" / "B" / "b" / "D" / "d") {?
            match m.to_uppercase().as_str() {
                "R" => Ok(Mode::Regular),
                "N" => Ok(Mode::NoSpace),
                "U" => Ok(Mode::RegularUpcase),
                "H" => Ok(Mode::Hex),
                "B" => Ok(Mode::Base64),
                "D" => Ok(Mode::Decimal),
                _ => Err("unknown mode"),
            }
        }
        rule mode() -> Mode = m:(umode() / rmode()) { m }
        rule help_cmd() -> Command<'input> = "help" { Command::Help }
        rule quit_cmd() -> Command<'input> = "quit" { Command::Quit }
        rule ls_cmd() -> Command<'input> = "ls" { Command::Ls }
        rule add_cmd() -> Command<'input> = "add" _ name:name() { Command::Add(Rc::new(RefCell::new(name))) }
        rule error_cmd() -> Command<'input> = "error" _ e:$(([' '..='~'])+) { Command::Error(LKErr::Error(e)) }
        rule mv_cmd() -> Command<'input> = "mv" _ name:word() _ folder:word() { Command::Mv(name, folder) }
        rule comment_cmd() -> Command<'input> = "comment" _ name:word() c:comment()? { Command::Comment(name, c) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_password_test() {
        assert_eq!(
            command_parser::name(
                "ableton89 R 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"
            ),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: None,
                mode: Mode::Regular,
                length: None,
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("xx.ableton@domain.info https://www.ableton.com".to_string())
            })
        );
        assert_eq!(
            command_parser::name(
                "ableton89 U 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"
            ),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: None,
                mode: Mode::RegularUpcase,
                length: None,
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("xx.ableton@domain.info https://www.ableton.com".to_string())
            })
        );
        assert_eq!(
            command_parser::name("ableton89 U 2020-12-09"),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: None,
                mode: Mode::RegularUpcase,
                length: None,
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: None
            })
        );
        assert_eq!(
            command_parser::name(
                "#W9 ableton89 R 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"
            ),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: Some("#W9".to_string()),
                mode: Mode::Regular,
                length: None,
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("xx.ableton@domain.info https://www.ableton.com".to_string())
            })
        );
        assert_eq!(
            command_parser::name(
                "#W9 ableton89 N 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"
            ),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: Some("#W9".to_string()),
                mode: Mode::NoSpace,
                length: None,
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("xx.ableton@domain.info https://www.ableton.com".to_string())
            })
        );
        assert_eq!(
            command_parser::name(
                "#W9 ableton89 UN 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"
            ),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: Some("#W9".to_string()),
                mode: Mode::NoSpaceUpcase,
                length: None,
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("xx.ableton@domain.info https://www.ableton.com".to_string())
            })
        );
        assert_eq!(
            command_parser::name("#W9 ableton89 20R 99 2020-12-09 a b c"),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: Some("#W9".to_string()),
                mode: Mode::Regular,
                length: Some(20),
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("a b c".to_string())
            })
        );
        assert_eq!(
            command_parser::name("#W9 ableton89 20UR 99 2020-12-09 a b c"),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: Some("#W9".to_string()),
                mode: Mode::RegularUpcase,
                length: Some(20),
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("a b c".to_string())
            })
        );
        assert_eq!(
            command_parser::name("#W9 ableton89 20UH 99 2020-12-09 a b c"),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: Some("#W9".to_string()),
                mode: Mode::HexUpcase,
                length: Some(20),
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("a b c".to_string())
            })
        );
        assert_eq!(
            command_parser::name("#W9 ableton89 20UB 99 2020-12-09 a b c"),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: Some("#W9".to_string()),
                mode: Mode::Base64Upcase,
                length: Some(20),
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("a b c".to_string())
            })
        );
        assert_eq!(
            command_parser::name("#W9 ableton89 20D 99 2020-12-09 a b c"),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: Some("#W9".to_string()),
                mode: Mode::Decimal,
                length: Some(20),
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("a b c".to_string())
            })
        );
        assert_eq!(
            command_parser::name("ableton89 20D 98 2020-12-09 a b c"),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: None,
                mode: Mode::Decimal,
                length: Some(20),
                seq: 98,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("a b c".to_string())
            })
        );
        assert_eq!(
            command_parser::name("ableton89 20D 2020-12-09 a b c"),
            Ok(Password {
                name: Rc::new("ableton89".to_string()),
                parent: None,
                prefix: None,
                mode: Mode::Decimal,
                length: Some(20),
                seq: 99,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("a b c".to_string())
            })
        );
    }
}

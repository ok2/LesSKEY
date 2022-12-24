extern crate peg;

use crate::password::Password;
use crate::structs::{Command, LKErr, Mode};
use chrono::naive::NaiveDate;
use chrono::Local;
use std::{cell::RefCell, rc::Rc};

peg::parser! {
    pub grammar command_parser() for str {
        pub rule cmd() -> Command<'input> = c:(info_cmd_list() / mod_cmd_list() / enc_cmd_list() / asides_cmd_list()) { c }
        pub rule info_cmd_list() -> Command<'input> = (" " / "\t" / "\r" / "\n")* c:(ls_cmd() / ld_cmd() / pb_cmd() / dump_cmd() / dump_def_cmd()) { c }
        pub rule mod_cmd_list() -> Command<'input> = (" " / "\t" / "\r" / "\n")* c:(add_cmd() / leave_cmd() / mv_cmd() / rm_cmd() / comment_cmd ()) { c }
        pub rule asides_cmd_list() -> Command<'input> = (" " / "\t" / "\r" / "\n")* c:(help_cmd() / source_cmd() / quit_cmd() / noop_cmd() / error_cmd()) { c }
        pub rule enc_cmd_list() -> Command<'input> = (" " / "\t" / "\r" / "\n")* c:(enc_cmd() / gen_cmd() / pass_cmd() / unpass_cmd() / correct_cmd() / uncorrect_cmd()) { c }
        pub rule script() -> Vec<Command<'input>> = c:(info_cmd_list() / mod_cmd_list() / enc_cmd_list() / asides_cmd_list()) ++ "\n" { c }

        rule _() -> &'input str = s:$((" " / "\t" / "\r")+) { s }
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
        rule nname() -> Password = &(word() _ num()? mode()) pn:word() _ pl:num()? pm:mode()
        { Password::new(None, pn, pl, pm, 99, Local::now().naive_local().date(), None) }
        rule qname() -> Password = &(word()) pn:word()
        { Password::new(None, pn, None, Mode::NoSpaceCamel, 99, Local::now().naive_local().date(), None) }
        pub rule name() -> Password = name:(jname() / pname() / mname() / sname() / nname() / qname())? {?
            match name { Some(n) => Ok(n), None => Err("failed to parse password description") }
        }

        rule ndate() -> NaiveDate = y:$("-"? ['0'..='9']*<1,4>) "-" m:$(['0'..='9']*<1,2>) "-" d:$(['0'..='9']*<1,2>) {?
            let year:  i32 = match y.parse() { Ok(n) => n, Err(_) => return Err("year") };
            let month: u32 = match m.parse() { Ok(n) => n, Err(_) => return Err("month") };
            let day:   u32 = match d.parse() { Ok(n) => n, Err(_) => return Err("day") };
            NaiveDate::from_ymd_opt(year, month, day).ok_or("date")
        }
        rule cdate() -> NaiveDate = "now" { Local::now().naive_local().date() }
        rule date() -> NaiveDate = d:(ndate() / cdate()) { d }
        rule umode() -> Mode = ("U" / "u") m:$("R" / "r" / "N" / "n" / "H" / "h" / "B" / "b") {?
            match m.to_uppercase().as_str() {
                "R" => Ok(Mode::RegularUpcase),
                "N" => Ok(Mode::NoSpaceUpcase),
                "H" => Ok(Mode::HexUpcase),
                "B" => Ok(Mode::Base64Upcase),
                _ => Err("unknown mode"),
            }
        }
        rule rmode() -> Mode = m:$("R" / "r" / "U" / "u" / "N" / "n" / "C" / "c" / "H" / "h" / "B" / "b" / "D" / "d") {?
            match m.to_uppercase().as_str() {
                "R" => Ok(Mode::Regular),
                "N" => Ok(Mode::NoSpace),
                "C" => Ok(Mode::NoSpaceCamel),
                "U" => Ok(Mode::RegularUpcase),
                "H" => Ok(Mode::Hex),
                "B" => Ok(Mode::Base64),
                "D" => Ok(Mode::Decimal),
                _ => Err("unknown mode"),
            }
        }
        rule mode() -> Mode = m:(umode() / rmode()) { m }

        rule noop_cmd() -> Command<'input> = ("#" [' '..='~']*)? { Command::Noop }
        rule help_cmd() -> Command<'input> = "help" { Command::Help }
        rule quit_cmd() -> Command<'input> = "quit" { Command::Quit }
        rule pb_cmd() -> Command<'input> = "pb" _ e:$(([' '..='~'])+) { Command::PasteBuffer(e.to_string()) }
        rule dump_cmd() -> Command<'input> = "dump" _ s:$(([' '..='~'])+) { Command::Dump(Some(s.to_string())) }
        rule dump_def_cmd() -> Command<'input> = "dump" { Command::Dump(None) }
        rule source_cmd() -> Command<'input> = "source" _ s:$(([' '..='~'])+) { Command::Source(s.to_string()) }
        rule ls_cmd() -> Command<'input> = "ls" f:comment()? { Command::Ls(f.unwrap_or(".".to_string())) }
        rule ld_cmd() -> Command<'input> = "ld" f:comment()? { Command::Ld(f.unwrap_or(".".to_string())) }
        rule add_cmd() -> Command<'input> = "add" _ name:name() { Command::Add(Rc::new(RefCell::new(name))) }
        rule leave_cmd() -> Command<'input> = "leave" _ name:word() { Command::Leave(name.to_string()) }
        rule gen_cmd() -> Command<'input> = "gen" n:num()? _ name:name() {
            Command::Gen(match n { Some(n) => n, None => 10_u32 }, Rc::new(RefCell::new(name)))
        }
        rule error_cmd() -> Command<'input> = "error" _ e:$(([' '..='~'])+) { Command::Error(LKErr::Error(e)) }
        rule mv_cmd() -> Command<'input> = "mv" _ name:word() _ folder:word() { Command::Mv(name, folder) }
        rule pass_cmd() -> Command<'input> = "pass" _ name:word() { Command::Pass(name) }
        rule correct_cmd() -> Command<'input> = "correct" _ name:word() { Command::Correct(name) }
        rule uncorrect_cmd() -> Command<'input> = "uncorrect" _ name:word() { Command::Uncorrect(name) }
        rule unpass_cmd() -> Command<'input> = "unpass" _ name:word() { Command::UnPass(name) }
        rule enc_cmd() -> Command<'input> = "enc" _ name:word() { Command::Enc(name) }
        rule rm_cmd() -> Command<'input> = "rm" _ name:word() { Command::Rm(name) }
        rule comment_cmd() -> Command<'input> = "comment" _ name:word() c:comment()? { Command::Comment(name, c) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_script_test() {
        assert_eq!(
            command_parser::script(
                r###"add t1 C 99 2022-12-14
add t2 C 99 2022-12-14
add t3 C 99 2022-12-14"###
            ),
            Ok(vec![
                Command::Add(Rc::new(RefCell::new(Password {
                    parent: None,
                    prefix: None,
                    name: "t1".to_string(),
                    length: None,
                    mode: Mode::NoSpaceCamel,
                    seq: 99,
                    date: NaiveDate::from_ymd_opt(2022, 12, 14).unwrap(),
                    comment: None
                }))),
                Command::Add(Rc::new(RefCell::new(Password {
                    parent: None,
                    prefix: None,
                    name: "t2".to_string(),
                    length: None,
                    mode: Mode::NoSpaceCamel,
                    seq: 99,
                    date: NaiveDate::from_ymd_opt(2022, 12, 14).unwrap(),
                    comment: None
                }))),
                Command::Add(Rc::new(RefCell::new(Password {
                    parent: None,
                    prefix: None,
                    name: "t3".to_string(),
                    length: None,
                    mode: Mode::NoSpaceCamel,
                    seq: 99,
                    date: NaiveDate::from_ymd_opt(2022, 12, 14).unwrap(),
                    comment: None
                })))
            ])
        );
        assert_eq!(
            command_parser::script(
                r###"add t1 C 99 2022-12-14
add t2 C 99 2022-12-14
add t3 C 99 2022-12-14
"###
            ),
            Ok(vec![
                Command::Add(Rc::new(RefCell::new(Password {
                    parent: None,
                    prefix: None,
                    name: "t1".to_string(),
                    length: None,
                    mode: Mode::NoSpaceCamel,
                    seq: 99,
                    date: NaiveDate::from_ymd_opt(2022, 12, 14).unwrap(),
                    comment: None
                }))),
                Command::Add(Rc::new(RefCell::new(Password {
                    parent: None,
                    prefix: None,
                    name: "t2".to_string(),
                    length: None,
                    mode: Mode::NoSpaceCamel,
                    seq: 99,
                    date: NaiveDate::from_ymd_opt(2022, 12, 14).unwrap(),
                    comment: None
                }))),
                Command::Add(Rc::new(RefCell::new(Password {
                    parent: None,
                    prefix: None,
                    name: "t3".to_string(),
                    length: None,
                    mode: Mode::NoSpaceCamel,
                    seq: 99,
                    date: NaiveDate::from_ymd_opt(2022, 12, 14).unwrap(),
                    comment: None
                }))),
                Command::Noop
            ])
        );
        assert_eq!(
            command_parser::script(
                r###"add t1 C 99 2022-12-14
add t2 C 99 2022-12-14
add t3 C 99 2022-12-14
  # some comment
"###
            ),
            Ok(vec![
                Command::Add(Rc::new(RefCell::new(Password {
                    parent: None,
                    prefix: None,
                    name: "t1".to_string(),
                    length: None,
                    mode: Mode::NoSpaceCamel,
                    seq: 99,
                    date: NaiveDate::from_ymd_opt(2022, 12, 14).unwrap(),
                    comment: None
                }))),
                Command::Add(Rc::new(RefCell::new(Password {
                    parent: None,
                    prefix: None,
                    name: "t2".to_string(),
                    length: None,
                    mode: Mode::NoSpaceCamel,
                    seq: 99,
                    date: NaiveDate::from_ymd_opt(2022, 12, 14).unwrap(),
                    comment: None
                }))),
                Command::Add(Rc::new(RefCell::new(Password {
                    parent: None,
                    prefix: None,
                    name: "t3".to_string(),
                    length: None,
                    mode: Mode::NoSpaceCamel,
                    seq: 99,
                    date: NaiveDate::from_ymd_opt(2022, 12, 14).unwrap(),
                    comment: None
                }))),
                Command::Noop,
                Command::Noop
            ])
        );
    }

    #[test]
    fn parse_password_test() {
        assert_eq!(
            command_parser::name("ableton89 R 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"),
            Ok(Password {
                name: "ableton89".to_string(),
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
            command_parser::name("ableton89 U 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"),
            Ok(Password {
                name: "ableton89".to_string(),
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
                name: "ableton89".to_string(),
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
            command_parser::name("#W9 ableton89 R 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"),
            Ok(Password {
                name: "ableton89".to_string(),
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
            command_parser::name("#W9 ableton89 N 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"),
            Ok(Password {
                name: "ableton89".to_string(),
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
            command_parser::name("#W9 ableton89 UN 99 2020-12-09 xx.ableton@domain.info https://www.ableton.com"),
            Ok(Password {
                name: "ableton89".to_string(),
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
                name: "ableton89".to_string(),
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
                name: "ableton89".to_string(),
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
                name: "ableton89".to_string(),
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
                name: "ableton89".to_string(),
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
                name: "ableton89".to_string(),
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
                name: "ableton89".to_string(),
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
            command_parser::name("ableton89 20C 98 2020-12-09 a b c"),
            Ok(Password {
                name: "ableton89".to_string(),
                parent: None,
                prefix: None,
                mode: Mode::NoSpaceCamel,
                length: Some(20),
                seq: 98,
                date: NaiveDate::from_ymd_opt(2020, 12, 09).unwrap(),
                comment: Some("a b c".to_string())
            })
        );
        assert_eq!(
            command_parser::name("ableton89 20D 2020-12-09 a b c"),
            Ok(Password {
                name: "ableton89".to_string(),
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

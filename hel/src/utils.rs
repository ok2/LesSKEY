use shlex::split;
use std::env;
use std::ffi::OsString;
use std::io;
use std::io::Write;
use std::process::{Command, Stdio};

pub mod date {
    use chrono::naive::NaiveDate;
    use chrono::Local;

    #[derive(PartialEq, Debug, Clone, Copy)]
    pub struct Date {
        date: NaiveDate,
    }

    impl Date {
        pub fn new(year: i32, month: u32, day: u32) -> Self {
            Self {
                date: NaiveDate::from_ymd_opt(year, month, day).unwrap(),
            }
        }

        pub fn try_new(year: i32, month: u32, day: u32) -> Result<Self, &'static str> {
            match NaiveDate::from_ymd_opt(year, month, day) {
                Some(d) => Ok(Self { date: d }),
                None => Err("error: failed to parse the date"),
            }
        }

        pub fn now() -> Self {
            Self {
                date: Local::now().naive_local().date(),
            }
        }

        pub fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            self.date.cmp(&other.date)
        }
    }

    impl std::fmt::Display for Date {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.date.to_string())
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub mod rnd {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = hel_rnd_range)]
        fn extern_rnd_range(start: u32, end: u32) -> u32;
    }

    pub fn range(start: u32, end: u32) -> u32 {
        extern_rnd_range(start, end)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub mod rnd {
    use rand::{thread_rng, Rng};

    pub fn range(start: u32, end: u32) -> u32 {
        thread_rng().gen_range(start..end)
    }
}

#[cfg(target_arch = "wasm32")]
pub mod home {
    pub fn dir() -> std::path::PathBuf {
        std::path::PathBuf::new()
    }
}

#[cfg(unix)]
pub mod home {
    use home::home_dir;
    use std::path::PathBuf;

    pub fn dir() -> PathBuf {
        home_dir().unwrap()
    }
}

#[cfg(unix)]
pub mod editor {
    use crate::structs::LKErr;
    use rustyline::error::ReadlineError;
    use rustyline::config::Configurer;
    use std::sync::Arc;
    use parking_lot::Mutex;

    pub type EditorRef = Arc<Mutex<Editor>>;

    #[derive(Debug)]
    pub struct Editor {
        editor: rustyline::Editor<()>,
    }

    impl Editor {
        pub fn new() -> EditorRef {
            let mut editor = rustyline::Editor::<()>::new().unwrap();
            editor.set_max_history_size(10000);
            Arc::new(Mutex::new(Self {
                editor: editor,
            }))
        }

        pub fn clear_history(&mut self) {
            self.editor.clear_history();
        }

        pub fn add_history_entry(&mut self, entry: &str) {
            self.editor.add_history_entry(entry);
        }

        pub fn load_history<'a>(&mut self, fname: &str) -> Result<(), LKErr<'a>> {
            match self.editor.load_history(&fname) {
                Ok(_) => Ok(()),
                Err(_) => Err(LKErr::Error("failed to read history file")),
            }
        }

        pub fn save_history<'a>(&mut self, fname: &str) -> Result<(), LKErr<'a>> {
            match self.editor.save_history(&fname) {
                Ok(_) => Ok(()),
                Err(ReadlineError::Eof | ReadlineError::Interrupted) => Err(LKErr::EOF),
                Err(_) => Err(LKErr::Error("failed to write history file")),
            }
        }

        pub fn readline<'a>(&mut self, prompt: &str) -> Result<String, LKErr<'a>> {
            match self.editor.readline(&prompt) {
                Ok(line) => Ok(line),
                Err(_) => Err(LKErr::Error("failed to read from input")),
            }
        }
    }

    pub fn password(pwname: String) -> std::io::Result<String> {
        rpassword::prompt_password(format!("Password for {}: ", pwname))
    }
}

#[cfg(target_arch = "wasm32")]
pub mod editor {
    use crate::structs::LKErr;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = hel_read_password)]
        fn extern_read_password(prompt: &str);

        #[wasm_bindgen(js_name = hel_current_password)]
        fn extern_current_password() -> Option<String>;
    }

    #[derive(Debug)]
    pub struct Editor {
        history: Vec<String>,
    }

    impl Editor {
        pub fn new() -> Self {
            Self { history: vec![] }
        }

        pub fn clear_history(&mut self) {
            self.history.clear();
        }

        pub fn add_history_entry(&mut self, entry: &str) {
            self.history.push(entry.to_string());
        }

        pub fn load_history<'a>(&mut self, _fname: &str) -> Result<(), LKErr<'a>> {
            Ok(())
        }

        pub fn save_history<'a>(&mut self, _fname: &str) -> Result<(), LKErr<'a>> {
            Ok(())
        }

        pub fn readline<'a>(&mut self, _prompt: &str) -> Result<String, LKErr<'a>> {
            Ok("".to_string())
        }
    }

    pub fn password(prompt: String) -> std::io::Result<String> {
        extern_read_password(&prompt);
        loop {
            match extern_current_password() {
                Some(p) => return Ok(p),
                None => std::thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
    }
}

pub fn call_cmd_with_input(cmd: &str, args: &Vec<String>, input: &str) -> io::Result<String> {
    let mut cmd = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    {
        let stdin = cmd.stdin.as_mut().unwrap();
        stdin
            .write_all(input.as_bytes())
            .expect("Failed to write input to stdin");
    }

    let output = cmd.wait_with_output()?;

    match String::from_utf8(output.stdout) {
        Ok(x) => Ok(x),
        Err(err) => Err(io::Error::new(io::ErrorKind::InvalidData, err.utf8_error())),
    }
}

pub fn get_cmd_args_from_command(command: &str) -> io::Result<(String, Vec<String>)> {
    let args = match split(command) {
        Some(c) => c,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse the command: {:?}", command),
            ))
        }
    };
    Ok((shellexpand::full(&args[0]).unwrap().into_owned(), args[1..].to_vec()))
}

pub fn get_copy_command_from_env() -> (String, Vec<String>) {
    let cmd_os_str = env::var_os("HEL_PB").unwrap_or_else(|| match env::consts::OS {
        _ if env::var("TMUX").is_ok() => OsString::from("tmux load-buffer -"),
        "macos" => OsString::from("pbcopy"),
        "linux" => OsString::from("xclip"),
        _ => OsString::from("cat"),
    });
    get_cmd_args_from_command(&cmd_os_str.to_string_lossy()).unwrap_or_else(|_| ("cat".to_string(), vec![]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_exec_test() {
        assert_eq!(call_cmd_with_input("true", &vec![], "").unwrap(), "".to_string());
        assert_eq!(call_cmd_with_input("cat", &vec![], "ok").unwrap(), "ok".to_string());
        assert_eq!(
            call_cmd_with_input(
                "cat",
                &vec![],
                r###"line 1
line 2
line 3
line 4"###
            )
            .unwrap(),
            "line 1\nline 2\nline 3\nline 4".to_string()
        );
        assert_ne!(call_cmd_with_input("cat", &vec![], "notok").unwrap(), "ok".to_string());
        assert_eq!(
            call_cmd_with_input("echo", &vec!["-n".to_string(), "test is ok".to_string()], "").unwrap(),
            "test is ok".to_string()
        );
    }

    #[test]
    fn check_correct_stdin() {
        let cmd = "cat";
        let args = vec![];
        let input = "Hello World!";
        let output = call_cmd_with_input(cmd, &args, input).unwrap();
        assert_eq!(output, "Hello World!");
    }
}

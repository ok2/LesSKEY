use shlex::split;
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
    use rand::prelude::*;

    pub fn range(start: u32, end: u32) -> u32 {
        rand::rng().random_range(start..end)
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
        editor: rustyline::DefaultEditor,
    }

    impl Editor {
        pub fn new() -> EditorRef {
            let mut editor = rustyline::DefaultEditor::new().unwrap();
            // These return Result in rustyline 11+; a full history is best-effort.
            let _ = editor.set_max_history_size(10000);
            Arc::new(Mutex::new(Self { editor }))
        }

        pub fn clear_history(&mut self) {
            let _ = self.editor.clear_history();
        }

        pub fn add_history_entry(&mut self, entry: &str) {
            let _ = self.editor.add_history_entry(entry);
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

        /// A handle that prints from another thread without garbling a
        /// half-typed line — rustyline redraws the prompt around the message.
        /// `None` when the terminal cannot provide one (not a tty, piped input).
        pub fn external_printer(&mut self) -> Option<impl rustyline::ExternalPrinter + Send> {
            self.editor.create_external_printer().ok()
        }

        pub fn readline<'a>(&mut self, prompt: &str) -> Result<String, LKErr<'a>> {
            match self.editor.readline(prompt) {
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
    use parking_lot::Mutex;
    use std::sync::Arc;
    use wasm_bindgen::prelude::*;

    // Mirror the unix editor's contract so repl.rs (which holds an `EditorRef`
    // and calls `.lock()`) compiles unchanged under wasm.
    pub type EditorRef = Arc<Mutex<Editor>>;

    #[wasm_bindgen]
    extern "C" {
        // Synchronous: the host page returns the current master-password value.
        // (The old read/poll pair used thread::sleep, which deadlocks the single
        // browser thread — never use blocking polling under wasm.)
        #[wasm_bindgen(js_name = hel_get_password)]
        fn extern_get_password(prompt: &str) -> String;
    }

    #[derive(Debug)]
    pub struct Editor {
        #[allow(dead_code)]
        history: Vec<String>,
    }

    impl Editor {
        pub fn new() -> EditorRef {
            Arc::new(Mutex::new(Self { history: vec![] }))
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
        Ok(extern_get_password(&prompt))
    }
}

pub fn call_cmd_with_input(cmd: &str, args: &Vec<String>, input: &str) -> io::Result<String> {
    let mut cmd = Command::new(cmd)
        .args(args)
        // Export runtime `set …` config (uppercased) into the child, so e.g.
        // `set hel_notion_token …` reaches a spawned `hel store`/`hel load`.
        .envs(crate::structs::config_envs())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    // The child may exit before draining stdin (e.g. `hel store` with a bad
    // target): EPIPE here is the child's failure, reported via its exit status
    // below — so hold the write error instead of panicking on it.
    let write_res = cmd.stdin.as_mut().unwrap().write_all(input.as_bytes());

    let output = cmd.wait_with_output()?;
    if !output.status.success() {
        // The child's stderr is inherited (already on the terminal); the caller
        // must NOT report success or advance its saved-state on this.
        return Err(io::Error::new(io::ErrorKind::Other, format!("command failed ({})", output.status)));
    }
    write_res?; // exited 0 without taking all input -> still a failed hand-off

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

/// Outcome of a built-in fan-out copy: which sinks accepted the data and which
/// failed (best-effort, like the reference shell script's `2>/dev/null`).
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Default, PartialEq)]
pub struct CopyReport {
    pub ok: Vec<String>,
    pub err: Vec<(String, String)>,
}

/// True if `bin` is an existing file on any `$PATH` directory.
#[cfg(not(target_arch = "wasm32"))]
pub fn bin_on_path(bin: &str) -> bool {
    match std::env::var_os("PATH") {
        Some(paths) => std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()),
        None => false,
    }
}

/// Built-in, zero-config clipboard copy: pipe `data` into **every** clipboard
/// sink present on `$PATH`, so a single `pb` works across macOS, Wayland, X11
/// and (inside a session) tmux without any `HEL_PB` script. Used only when no
/// explicit override (`set hel_pb` / `HEL_PB`) is set. The sink set + flags
/// mirror the reference script, with two fixes: `xclip -selection clipboard`
/// (the script's bare `xclip` filled the X11 *primary*, so Ctrl/Cmd-V missed
/// it) and `xsel -ib` (input-to-clipboard; the script's `-ob` is the *output*
/// direction). `wl-copy` is added for Wayland.
#[cfg(not(target_arch = "wasm32"))]
pub fn copy_to_clipboards(data: &str) -> CopyReport {
    let mut sinks: Vec<(&str, Vec<&str>)> = Vec::new();
    if bin_on_path("pbcopy") {
        sinks.push(("pbcopy", vec![]));
    }
    if bin_on_path("wl-copy") {
        sinks.push(("wl-copy", vec![]));
    }
    if bin_on_path("xclip") {
        sinks.push(("xclip", vec!["-selection", "clipboard"]));
    }
    if bin_on_path("xsel") {
        sinks.push(("xsel", vec!["-ib"]));
    }
    if std::env::var("TMUX").is_ok() && bin_on_path("tmux") {
        sinks.push(("tmux", vec!["load-buffer", "-"]));
    }

    let mut report = CopyReport::default();
    for (bin, args) in sinks {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        match call_cmd_with_input(bin, &args, data) {
            Ok(_) => report.ok.push(bin.to_string()),
            Err(e) => report.err.push((bin.to_string(), e.to_string())),
        }
    }
    report
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
        // A failing child is an Err — `save |cmd` must never report success on
        // it (the Notion 504 regression: `hel store` exits 1, save said saved).
        assert!(call_cmd_with_input("false", &vec![], "").is_err());
        // A child that exits before draining a large stdin must not panic the
        // caller (EPIPE) — it surfaces as the child's failure or a write error.
        let big = "x".repeat(1 << 20);
        assert!(call_cmd_with_input("false", &vec![], &big).is_err());
        assert_eq!(
            call_cmd_with_input("echo", &vec!["-n".to_string(), "test is ok".to_string()], "").unwrap(),
            "test is ok".to_string()
        );
    }

    #[test]
    fn bin_on_path_test() {
        // `sh` is on PATH on every unix; a nonsense name is not.
        assert!(bin_on_path("sh"));
        assert!(!bin_on_path("definitely-not-a-real-binary-xyzzy-42"));
    }

    #[test]
    fn copy_report_default_test() {
        let r = CopyReport::default();
        assert!(r.ok.is_empty() && r.err.is_empty());
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

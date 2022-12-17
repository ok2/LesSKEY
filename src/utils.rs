use std::env;
use std::io;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use shlex::split;
use std::ffi::OsString;

pub fn call_cmd_with_input(cmd: &str, args: &Vec<String>, input: &str) -> io::Result<String> {
    let mut cmd = Command::new(cmd).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let mut stdin = cmd.stdin.take().unwrap();
    let stdout = cmd.stdout.as_mut().unwrap();
    let in_data = input.to_string();
    let write_handle = std::thread::spawn(move || stdin.write_all(in_data.as_bytes()));
    let mut output = Vec::new();
    stdout.read_to_end(&mut output)?;
    match write_handle.join() {
        Ok(_) => (),
        Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Failed to run command")),
    }
    match String::from_utf8(output) {
        Ok(x) => Ok(x),
        Err(err) => Err(io::Error::new(io::ErrorKind::InvalidData, err.utf8_error())),
    }
}

pub fn get_copy_command_from_env() -> (String, Vec<String>) {
    let cmd_os_str = env::var_os("LESSKEY_PB").unwrap_or_else(|| match env::consts::OS {
        _ if env::var("TMUX").is_ok() => OsString::from("tmux load-buffer -"),
        "macos" => OsString::from("pbcopy"),
        "linux" => OsString::from("xclip"),
        _ => OsString::from("cat"),
    });
    let args = split(&cmd_os_str.to_string_lossy()).unwrap_or_else(|| vec!["cat".to_string()]);
    (args[0].clone(), args[1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_exec_test() {
        assert_eq!(call_cmd_with_input("true", &vec![], "").unwrap(), "".to_string());
        assert_eq!(call_cmd_with_input("cat", &vec![], "ok").unwrap(), "ok".to_string());
        assert_eq!(call_cmd_with_input("cat", &vec![], r###"line 1
line 2
line 3
line 4"###).unwrap(), "line 1\nline 2\nline 3\nline 4".to_string());
        assert_ne!(call_cmd_with_input("cat", &vec![], "notok").unwrap(), "ok".to_string());
        assert_eq!(call_cmd_with_input("echo", &vec!["-n".to_string(), "test is ok".to_string()], "").unwrap(), "test is ok".to_string());
    }
}

use std::io;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

pub fn call_cmd_with_input(cmd: &str, args: Vec<&str>, input: &str) -> io::Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_exec_test() {
        assert_eq!(call_cmd_with_input("true", vec![], "").unwrap(), "".to_string());
        assert_eq!(call_cmd_with_input("cat", vec![], "ok").unwrap(), "ok".to_string());
        assert_ne!(call_cmd_with_input("cat", vec![], "notok").unwrap(), "ok".to_string());
        assert_eq!(call_cmd_with_input("echo", vec!["-n", "test is ok"], "").unwrap(), "test is ok".to_string());
    }
}

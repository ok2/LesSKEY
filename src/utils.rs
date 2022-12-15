use std::io;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

pub fn call_cmd_with_input(cmd: &str, args: Vec<&str>, input: &str) -> io::Result<String> {
    let mut cmd = Command::new(cmd).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let stdin = cmd.stdin.as_mut().unwrap();
    stdin.write_all(input.as_bytes())?;
    let stdout = cmd.stdout.as_mut().unwrap();
    let mut output = Vec::new();
    stdout.read_to_end(&mut output)?;
    match String::from_utf8(output) {
        Ok(x) => Ok(x),
        Err(err) => Err(io::Error::new(io::ErrorKind::InvalidData, err.utf8_error())),
    }
}

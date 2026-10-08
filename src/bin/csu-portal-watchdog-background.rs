//! Windowless task entry point; the CLI keeps its normal console behavior.
#![cfg(windows)]
#![windows_subsystem = "windows"]

use std::{
    os::windows::process::CommandExt,
    process::{Command, Stdio},
};

fn main() {
    let result = std::env::current_exe().and_then(|exe| {
        Command::new(exe.with_file_name("csu-portal-watchdog.exe"))
            .args(std::env::args_os().skip(1))
            .creation_flags(0x08000000) // CREATE_NO_WINDOW: no console is created.
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    });
    std::process::exit(result.ok().and_then(|status| status.code()).unwrap_or(2));
}

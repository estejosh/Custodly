//! Dev helper: make an empty KeePass database whose password lives in the OS keystore under
//! `<keyring-name>`, for tests that must not touch the real vault.
//! cargo run -p custodly-vault --example make_test_vault -- <db-path> <keyring-name>
use std::io::Write;
use std::process::{Command, Stdio};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (db, name) = (&a[1], &a[2]);
    let pw = custodly_vault::password::get_or_create(name).expect("keystore");
    let mut c = Command::new(r"C:\Program Files\KeePassXC\keepassxc-cli.exe")
        .args(["db-create", "-q", "-p", db])
        .stdin(Stdio::piped())
        .spawn()
        .expect("keepassxc-cli");
    let mut i = c.stdin.take().expect("stdin");
    writeln!(i, "{pw}").expect("write");
    writeln!(i, "{pw}").expect("write");
    drop(i);
    println!("db-create: {}", c.wait().expect("wait"));
}
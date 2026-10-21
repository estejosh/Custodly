//! Dev helper: print one entry from a throwaway test vault (value included -- test vaults only).
//! cargo run -p custodly-vault --example show_test_entry -- <db-path> <keyring-name> <project> <label>
use custodly_core::SecretQuery;
use custodly_vault::Vault;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let vault = Vault::new(r"C:\Program Files\KeePassXC\keepassxc-cli.exe", &a[1], a[2].clone());
    let e = vault.get(&SecretQuery::new(a[3].clone(), a[4].clone())).expect("entry");
    println!("group_path = {}", e.group_path);
    println!("secret     = {}", e.secret);
    println!("{:#?}", e.metadata);
}
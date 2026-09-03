fn main() {
    if let Err(error) = reforge_desktop_lib::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

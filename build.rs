fn main() {
    // TODO wrap in env var condition
    println!("cargo:rustc-link-search=/usr/local/ssl/lib");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
}

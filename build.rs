fn main() {
    // TODO wrap in env var condition
    println!("cargo:rustc-link-search=/usr/lib");
    println!("cargo:rustc-link-search=/usr/local/ssl/lib");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=cryptsetup");
    println!("cargo:rustc-link-lib=static=devmapper");
    println!("cargo:rustc-link-lib=static=json-c");
    println!("cargo:rustc-link-lib=static=ssl");
    //println!("cargo:rustc-link-lib=static=tss2-esys");
    //println!("cargo:rustc-link-lib=static=tss2-mu");
    //println!("cargo:rustc-link-lib=static=tss2-rc");
    //println!("cargo:rustc-link-lib=static=tss2-sys");
    //println!("cargo:rustc-link-lib=static=tss2-tctildr");
}

fn main() {
    if let Some(build_static) = option_env!("TPM_LUKS_BUILD_STATIC") {
        if matches!(
            build_static.to_lowercase().as_ref(),
            "1" | "y" | "yes" | "true"
        ) {
            println!("cargo:rustc-link-arg=-l:libc.a");
            println!("cargo:rustc-link-arg=-l:libtss2-tcti-device.a");
            //println!("cargo:rustc-link-arg=-l:libtss2-tcti-mssim.a");
            //println!("cargo:rustc-link-arg=-l:libtss2-tcti-swtpm.a");
            println!("cargo:rustc-link-lib=static=crypto");
            println!("cargo:rustc-link-lib=static=cryptsetup");
            println!("cargo:rustc-link-lib=static=devmapper");
            println!("cargo:rustc-link-lib=static=json-c");
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=tss2-esys");
            println!("cargo:rustc-link-lib=static=tss2-mu");
            println!("cargo:rustc-link-lib=static=tss2-sys");
            //println!("cargo:rustc-link-lib=static=tss2-tcti-device");
            //println!("cargo:rustc-link-lib=static=tss2-tcti-mssim");
            //println!("cargo:rustc-link-lib=static=tss2-tcti-swtpm");
            //println!("cargo:rustc-link-lib=static=tss2-tctildr");
            println!("cargo:rustc-link-lib=static=uuid");
            println!("cargo:rustc-link-search=/usr/lib");
            println!("cargo:rustc-link-search=/usr/local/ssl/lib");
        }
    }
}

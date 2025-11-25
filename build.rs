fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() != "windows" {
        println!("cargo:rustc-link-search=native={}", "preloader");
        println!("cargo:rustc-link-lib=preloader");
    }
}
#[cfg(not(target_os = "windows"))]
mod fullbright;
#[cfg(not(target_os = "windows"))]
mod preloader;
#[cfg(target_os = "windows")]
mod windows;

#[ctor::ctor]
fn safe_setup() {
    std::panic::set_hook(Box::new(move |_panic_info| {}));
    main();
}

fn main() {
    #[cfg(not(target_os = "windows"))]
    let _ = fullbright::patch_gfx_gamma();
}
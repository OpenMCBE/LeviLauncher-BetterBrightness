use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows::Win32::Foundation::{BOOL, HMODULE};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use minhook_sys::*;

static ORIGINAL_GET_GAMMA: AtomicUsize = AtomicUsize::new(0);

const GET_GAMMA_SIG: &[u8] = &[
    0x48, 0x83, 0xEC, 0x00,
    0x48, 0x8B, 0x01,
    0x48, 0x8D, 0x54, 0x00, 0x00,
    0x41, 0xB8, 0x34, 0x00, 0x00, 0x00
];

const GET_GAMMA_MASK: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0x00,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
];

unsafe extern "C" fn detour_get_gamma(options: *mut c_void, a2: *mut c_void) -> f32 {
    let original_addr = ORIGINAL_GET_GAMMA.load(Ordering::Relaxed);
    if original_addr != 0 {
        let original: extern "C" fn(*mut c_void, *mut c_void) -> f32 = std::mem::transmute(original_addr);
        let val = original(options, a2);
        return val * 10.0;
    }
    0.0
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(
    dll_module: HMODULE,
    call_reason: u32,
    reserved: *mut c_void,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            std::thread::spawn(|| {
                unsafe { initialize(); }
            });
        }
        DLL_PROCESS_DETACH => {}
        _ => {}
    }
    BOOL::from(true)
}

unsafe fn initialize() {
    let base = windows::Win32::System::LibraryLoader::GetModuleHandleA(None).unwrap();
    
    let dos_header = base.0 as *const windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
    let nt_headers = (base.0 as usize + (*dos_header).e_lfanew as usize) as *const windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    let size_of_image = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    
    let memory_slice = std::slice::from_raw_parts(base.0 as *const u8, size_of_image);
    
    if let Some(offset) = find_pattern(memory_slice, GET_GAMMA_SIG, GET_GAMMA_MASK) {
        let target_addr = (base.0 as usize + offset) as *mut c_void;
        
        if MH_Initialize() != MH_OK {
            return;
        }
        
        let mut original: *mut c_void = std::ptr::null_mut();
        if MH_CreateHook(target_addr, detour_get_gamma as *mut c_void, &mut original) == MH_OK {
            ORIGINAL_GET_GAMMA.store(original as usize, Ordering::Relaxed);
            MH_EnableHook(target_addr);
        }
    }
}

fn find_pattern(data: &[u8], pattern: &[u8], mask: &[u8]) -> Option<usize> {
    if pattern.len() != mask.len() {
        return None;
    }
    
    for i in 0..data.len() - pattern.len() {
        let mut found = true;
        for j in 0..pattern.len() {
            if mask[j] == 0xFF && data[i + j] != pattern[j] {
                found = false;
                break;
            }
        }
        if found {
            return Some(i);
        }
    }
    None
}

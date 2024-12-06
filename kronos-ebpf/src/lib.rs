#![no_std]
use aya_ebpf::helpers;
use aya_log_ebpf::info;
pub mod vmlinux;
// This function returns the bytes of the dname of the file struct
pub unsafe fn getnamehashfromfilestruct(
    file: *const vmlinux::file,
    printfilename: bool,
) -> Option<u32> {
    let mut path_ptr = unsafe { &(*file).f_path as *const vmlinux::path };

    let d_name = unsafe { (*(*path_ptr).dentry).d_name };

    let mut path_buf: [u8; 256] = [0; 256];
    let res = helpers::bpf_probe_read_kernel_str_bytes(d_name.name, &mut path_buf);

    match res.ok() {
        Some(bytes) => {
            let my_str = core::str::from_utf8_unchecked(bytes);
            let hash = djb2_hash(bytes);
            Some(hash)
        }
        None => None,
    }
}

pub fn djb2_hash(input: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in input.iter().take(64) {
        if byte == 0 {
            break;
        }
        hash = (hash.wrapping_shl(5))
            .wrapping_add(hash)
            .wrapping_add(byte as u32); // hash = hash * 33 + byte
    }

    hash
}

pub fn djb2_hash_from_str(input: &str) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in input.as_bytes().iter().take(64) {
        if byte == 0 {
            break;
        }
        hash = (hash.wrapping_shl(5))
            .wrapping_add(hash)
            .wrapping_add(byte as u32); // hash = hash * 33 + byte
    }
    hash
}
pub fn djb2_hash_dns(input: &[u8]) -> u32 {
    let mut hash: u32 = 5381;

    let domain_len = if input.len() < 64 { input.len() } else { 63 };
    for i in 1..domain_len {
        let mut byte = input[i];
        if byte == 0 {
            break;
        }
        if byte < 10 && byte != 0 {
            byte = 46;
        }
        hash = (hash.wrapping_shl(5))
            .wrapping_add(hash)
            .wrapping_add(byte as u32);
        // info!(&ctx, "byte{}, hash:{}", byte, hash);
    }
    hash
}

use log::info;

pub mod k8s_helpers;
pub mod system;

pub fn djb2_hash(input: &str) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in input.as_bytes().iter().take(64) {
        if byte == 0 {
            break;
        }
        hash = (hash.wrapping_shl(5))
            .wrapping_add(hash)
            .wrapping_add(byte as u32); // hash = hash * 33 + byte
                                        // info!("byte:{},hash:{}", byte, hash);
    }
    hash
}

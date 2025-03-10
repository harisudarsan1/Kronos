use helpers::system::kernel;

/// checks the environment for the bpf features and BPF-LSM as kronos is mainly
/// dependent on BPF LSM for enforcement. kernel version is also checked and used internally
pub fn check_environment() {
    match kernel::is_bpflsm_enabled().ok() {
        Some(_) => {
            println!("bpf lsm enabled kronos can be used with BPFLSM");
        }
        None => {
            println!("bpf lsm is not enabled");
        }
    }
}

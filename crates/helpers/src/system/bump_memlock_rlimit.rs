use anyhow::{bail, Ok, Result};
use log::debug;

pub fn bump_memlock_rlimit() -> Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    if ret != 0 {
        bail!("remove limit on locked memory failed, ret is: {}", ret);
    }

    debug!("Memory limits adjusted successfully.");
    Ok(())
}

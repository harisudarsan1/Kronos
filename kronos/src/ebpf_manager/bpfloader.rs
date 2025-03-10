use anyhow::{Context, Result};
use aya::{include_bytes_aligned, Bpf};
use aya::{
    programs::{CgroupSkb, CgroupSkbAttachType, Lsm},
    Btf,
};
use aya_log::BpfLogger;
use log::{debug, info, warn};
use tokio::signal;

pub async fn load_bpf_programs() -> Result<Bpf> {
    // env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/kronos-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/kronos-ebpf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("lsm_file_open").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    if program.attach().is_err() {
        panic!("cannot load lsm file open");
    }

    let cgroup_path = String::from("/sys/fs/cgroup/kubepods.slice");
    let cgroup = std::fs::File::open(&cgroup_path).with_context(|| format!("{}", cgroup_path))?;
    let program: &mut CgroupSkb = bpf.program_mut("cskb").unwrap().try_into()?;
    program.load()?;
    if program.attach(cgroup, CgroupSkbAttachType::Egress).is_err() {
        panic!("cannot load cgroup program");
    }

    Ok(bpf)
}

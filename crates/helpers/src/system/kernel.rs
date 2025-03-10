use anyhow::{bail, Context, Ok, Result};
use log::{error, info};
use regex::Regex;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

use crate::k8s_helpers::kubernetes::{self, K8sCluster};
use std::os::unix::ffi::OsStrExt;
use std::{
    ffi::{CString, OsStr},
    mem, ptr, slice,
};

pub const CGROUPFS_PATH: &str = "/sys/fs/cgroup";
/// get_kernel_version retrieves the kernel version from the /proc/version file
/// and parses it to the kernel version
pub fn get_kernel_version() -> Result<String> {
    todo!()
}

pub enum CgroupDriver {
    SystemdUnified,
    SystemdLegacy,
    SystemdHybrid,
    CgroupFS,
    Unknown,
}
pub enum SystemdCgroupMode {
    Unified,
    Legacy,
    Hybrid,
    Undefined,
}
pub enum ContainerRuntime {
    Docker,
    Containerd,
    CriO,
}

pub fn is_bpflsm_enabled() -> Result<bool> {
    let lsms = fs::read_to_string("/sys/kernel/security/lsm");
    let lsms = lsms.ok();
    match lsms {
        Some(x) => {
            if x.contains("bpf") {
                return Ok(true);
            }
        }
        None => {
            bail!("error reading /sys/kernel/security/lsm")
        }
    }

    Ok(false)
}

pub fn check_btf_support() -> Result<bool> {
    todo!()
}

// TODO: This is temporary need to get the cgroup driver and determine the cgroup path based on the
// cgroup driver and the container configuration
// pub fn get_container_cgroup_path(
//     pod_id: &str,
//     qos_class: &str,
//     container_id: &str,
//     cluster: K8sCluster,
// ) -> String {
//     match cluster {
//         K8sCluster::K3s => {
//             format!(
//                 "/sys/fs/cgroup/kubepods.slice/kubepods-{}.slice/kubepods-{}-pod{}.slice/cri-containerd-{}.scope",
//                 qos_class,qos_class, pod_id, container_id
//             )
//         }
//         K8sCluster::Minikube => {
//             format!(
//                 "/sys/fs/cgroup/kubepods/{}/pod{}/{}",
//                 qos_class, pod_id, container_id
//             )
//         }
//         K8sCluster::KubeAdm => {
//             format!(
//                 "/sys/fs/cgroup/kubepods.slice/{}pod{}/{}",
//                 qos_class, pod_id, container_id
//             )
//         }
//         K8sCluster::Microk8s => {
//             format!(
//                 "/sys/fs/cgroup/kubepods/{}/pod{}/{}",
//                 qos_class, pod_id, container_id
//             )
//         }
//         K8sCluster::Kind => {
//             format!("")
//         }
//     }
// }

pub fn get_container_cgroup_path(
    pod_id: &str,
    qos_class: &str,
    container_id: &str,
    container_runtime: &str,
    cg_driver: &CgroupDriver,
) -> String {
    match cg_driver {
        CgroupDriver::CgroupFS => {
            format!(
                "{}/kubepods/{}/pod{}/{}",
                CGROUPFS_PATH, qos_class, pod_id, container_id
            )
        }
        CgroupDriver::SystemdUnified => {
            format!(
                "{}/unified/kubepods.slice/kubepods-{}.slice/kubepods-{}-pod{}.slice/cri-{}-{}.scope",
                CGROUPFS_PATH, qos_class, qos_class, pod_id, container_runtime, container_id
            )
        }
        CgroupDriver::SystemdHybrid => {
            format!(
                "{}/kubepods.slice/kubepods-{}.slice/kubepods-{}-pod{}.slice/cri-{}-{}.scope",
                CGROUPFS_PATH, qos_class, qos_class, pod_id, container_runtime, container_id
            )
        }
        _ => {
            format!("")
        }
    }
}

pub fn get_pod_cgroup_path(pod_id: &str, qos_class: &str, cg_driver: &CgroupDriver) -> String {
    match cg_driver {
        CgroupDriver::CgroupFS => {
            format!("{}/kubepods/{}/pod{}", CGROUPFS_PATH, qos_class, pod_id)
        }
        CgroupDriver::SystemdUnified => {
            format!(
                "{}/unified/kubepods.slice/kubepods-{}.slice/kubepods-{}-pod{}.slice",
                CGROUPFS_PATH, qos_class, qos_class, pod_id
            )
        }
        CgroupDriver::SystemdHybrid => {
            format!(
                "{}/kubepods.slice/kubepods-{}.slice/kubepods-{}-pod{}.slice",
                CGROUPFS_PATH, qos_class, qos_class, pod_id
            )
        }
        _ => {
            format!("")
        }
    }
}

pub fn get_cg_path(pod_id: &str, qos_class: &str, cluster: K8sCluster) -> String {
    todo!()
}

fn get_kubelet_cgroup_driver() -> Option<CgroupDriver> {
    let path = "/var/lib/kubelet/config.yaml";

    // Read file line by line
    let file = fs::File::open(path).unwrap();
    let reader = io::BufReader::new(file);

    // Define regex to match `cgroupDriver`
    let re = Regex::new(r"cgroupDriver:\s*(\S+)").unwrap();
    for line in reader.lines() {
        let line = line.unwrap();
        if let Some(caps) = re.captures(&line) {
            println!("Found cgroup driver: {}", &caps[1]);
            return None;
        }
    }
    return None;
}

pub fn get_cgroup_driver(path: String, is_unified: bool) -> Result<CgroupDriver> {
    let path = Path::new(&path);
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if dir_name.starts_with("kubepods") {
                    println!("Processing directory (starts with kubepods): {:?}", path);
                    if is_unified {
                        println!("systemdunified driver");
                        return Ok(CgroupDriver::SystemdUnified);
                    }
                    if dir_name.ends_with("slice") {
                        println!("systemdhybrid driver");
                        return Ok(CgroupDriver::SystemdHybrid);
                    } else {
                        println!("cgroupfs driver");
                        return Ok(CgroupDriver::CgroupFS);
                    }
                } else if dir_name == "unified" {
                    println!("Processing directory (named unified): {:?}", path);
                    let new_path = format!("{}/unified", CGROUPFS_PATH);
                    get_cgroup_driver(new_path, true)?;
                }
            }
        }
    }
    Ok(CgroupDriver::Unknown)
}

//TODO: modify this function in Rust way
pub unsafe fn get_cgroup_id(cgroup_path: String) -> u64 {
    info!("received cgroup path:{}", cgroup_path);
    #[repr(C)]
    struct file_handle {
        handle_bytes: u32,
        handle_type: i32,
        f_handle: [u8; 0], // This is a flexible array member, meaning the size is dynamic
    }

    // Manually declare the system call
    extern "C" {
        pub fn name_to_handle_at(
            dirfd: libc::c_int,
            pathname: *const libc::c_char,
            handle: *mut file_handle,
            mount_id: *mut libc::c_int,
            flags: libc::c_int,
        ) -> libc::c_int;
    }
    let flags = 0;

    let pathname = &cgroup_path;
    // let path_str = CString::new(cgroup_path).unwrap();

    let c_path = CString::new(OsStr::new(pathname).as_bytes()).unwrap();

    let mut mount_id: i32 = 0;

    let mut fhsize = mem::size_of::<file_handle>() as i32;

    //
    let fhp = libc::malloc(fhsize as usize) as *mut file_handle;
    if fhp.is_null() {
        eprintln!("Error allocating memory");
        std::process::exit(1);
    }

    (*fhp).handle_bytes = 0;

    // First call to determine the size of the file handle
    if name_to_handle_at(libc::AT_FDCWD, c_path.as_ptr(), fhp, &mut mount_id, flags) != -1
        || *libc::__errno_location() != libc::EOVERFLOW
    {
        error!("Unexpected result from name_to_handle_at()");
        libc::free(fhp as *mut libc::c_void);
        std::process::exit(1);
    }

    // Reallocate file_handle with the correct size
    fhsize = mem::size_of::<file_handle>() as i32 + (*fhp).handle_bytes as i32;
    let fhp = libc::realloc(fhp as *mut libc::c_void, fhsize as usize) as *mut file_handle;
    if fhp.is_null() {
        eprintln!("Error reallocating memory");
        std::process::exit(1);
    }

    // Second call to get the file handle
    if name_to_handle_at(libc::AT_FDCWD, c_path.as_ptr(), fhp, &mut mount_id, flags) == -1 {
        error!("Error calling name_to_handle_at");
        libc::free(fhp as *mut libc::c_void);
        std::process::exit(1);
    }

    let handle_bytes =
        slice::from_raw_parts((*fhp).f_handle.as_ptr(), (*fhp).handle_bytes as usize);

    if (*fhp).handle_bytes == 8 {
        let mut cgroup_id: u64 = 0;
        ptr::copy_nonoverlapping(
            handle_bytes.as_ptr(),
            &mut cgroup_id as *mut u64 as *mut u8,
            8,
        );
        println!("Cgroup ID: {}", cgroup_id);
        return cgroup_id;
    } else {
        println!("Invalid handle size, cannot interpret as cgroup ID");
    }

    libc::free(fhp as *mut libc::c_void);

    return 0;
}

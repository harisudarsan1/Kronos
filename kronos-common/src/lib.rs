#![no_std]

pub struct Event {
    command: [u8; 16],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct PodBpfMap {
    pub target: u8, //
    // if the the first bit exists or 1 then a file target exists similarly for second bit binary
    // target exists for third bit network and for the fourth bit Capability
    pub namespace_hash: u32,
    // Namespace hash will be used to retrieve value from File and other maps.
    // Namespace level uniqueness is created by doing operation with namespace hash
    // pub onlyallow: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PodBpfMap {}

// pub struct FilemapValue {
//     is_source: bool,
//     source: u32, // list of sources of that file stored in an array
//     severity: u8,
//     is_owner: bool,
//     is_dir: bool,
//     recursive: bool,
// }
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct FileMap {
    // 0 if no rule exist for file
    // 1 bit if only file without source exist
    // 2 bit if only file+source exists
    pub is_file: u8,
    // 1 for block , 0 for auditd
    pub file_action: u8,
    pub label_namespace_hash: u32,
    //allow only if set to 1 this operation will be rejected if the is_file value
    //is 2 or 3 and source+file doesn't exists. else it will be passed
    //
    //If the allow only set to 0 it doesn't matter
    pub only_allow: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileMap {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct BinaryMap {
    // 1 for block , 0 for auditd
    pub binary_action: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BinaryMap {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SourceMap {
    is_source: bool,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SourceMap {}

// #[derive(Copy, Clone, Debug)]
// #[repr(C)]
// pub struct NetworkRule {
//     pub dns: NRule,
//     pub udp: NRule,
//     pub tcp: NRule,
// }

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct NetworkRule {
    pub dns: NRule,
    pub udp: NRule,
    pub tcp: NRule,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkRule {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct NRule {
    pub direction: i8,
    pub max_req: Option<u32>,

    pub num_of_request: u32,
    pub action: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NRule {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub enum NetworkAllowValue {
    LNValue {
        dns: Allowrule,
        udp: Allowrule,
        tcp: Allowrule,
    },
    Rule(NRule),
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkAllowValue {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub enum BinaryAllowMap {
    // This LNvalue is used only for label_namespace_hash in onlyallow maps
    LNvalue(Allowrule),
    Null,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BinaryAllowMap {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Allowrule {
    pub count: u32,
    pub action: u8,
}

pub struct FileAlert {
    time_stamp: u64,
    command: [u8; 16],
    full_binary_path: [u8; 256],
    file_name: [u8; 256],
    host_pid: u32,
    host_ppid: u32,
    cgroup_id: u64,
    // parent_process_name: [u8; 256],
    uid: u32,

    action: u8,
}

pub struct BinaryAlert {
    time_stamp: u64,
    full_binary_path: [u8; 256],

    cgroup_id: u64,
    host_pid: u32,
    host_ppid: u32,
    // parent_process_name: [u8; 256],
    uid: u32,
    action: u8,
}

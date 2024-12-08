use aya::maps::lpm_trie::Key;
use aya::maps::LpmTrie;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::u64;
use CRD::{KronosSecurityPolicy, NetworkTarget};

use aya::{
    maps::{HashMap as ayaHash, MapData},
    // Ebpf,
};

use kronos_common::{
    BinaryAllowMap, DNSAllowMap, DNSRule, FileAlert, FileMap, NRule, NetworkAllowValue,
    NetworkRule, PodBpfMap, SourceMap, TCPAllowMap, TCPRule, UDPAllowMap, UDPRule,
};

pub mod CRD;
pub mod errors;

#[derive(Debug, Clone)]
pub struct PodInfo {
    pub poduid: Arc<str>,
    pub qos_class: Arc<str>,
    pub podname: Arc<str>,
    pub namespace: Arc<str>,
    pub labels: HashSet<Arc<str>>,
    pub container_map: Vec<ContainerInfo>,
}
pub struct KronosPodContainerInfo {
    pub poduid: Arc<str>,
    pub qos_class: Arc<str>,
    pub podname: Arc<str>,
    pub label: Arc<str>,
    pub namespace: Arc<str>,
    pub label_namespace: Arc<str>,
    pub container_map: Vec<ContainerInfo>,
}

#[derive(Debug, Clone)]
pub struct KronosPod {
    pub poduid: Arc<str>,
    // pub pod_cgroup_path: Arc<str>,
    // pub pod_cgroup_id: HashSet<u64>,
    pub qos_class: Arc<str>,
    pub podname: Arc<str>,
    pub label_namespace: Arc<str>,
    pub namespace: Arc<str>,
    pub label_namespace_hash: u32,
    // targets as bitmask for file 0x1,for binary 0x2, for network 0x8, for capability 0x16
    // pub rules: u8,
    // pub container_map: HashMap<Arc<str>, ContainerInfo>,
}

// #[derive(Debug)]
// pub struct RuleEventInfo {
//     pub poduid: Arc<str>,
//     pub container_id: Arc<str>,
//     pub container_image: Arc<str>,
//     pub rule: Arc<str>,
// }

#[derive(Debug, Clone)]
pub struct PodFilterValue {
    // pub namespace: HashSet<Arc<str>>,
    pub crd_ref_count: i32,
    pub kronos_policies: HashSet<Arc<str>>,
}

// #[derive(Debug, Hash, Eq, PartialEq, PartialOrd)]
// pub struct NamespaceSet {
//     pub namespace: Arc<str>,
//     pub crd_ref_count: u32,
// }

#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub container_id: Arc<str>,
    pub container_name: Arc<str>,
    pub container_image: Arc<str>,
    pub image_id: Arc<str>,
}

pub enum PodEvent {
    Add(PodInfo),
    Delete(Arc<str>),
}

pub enum KronosEvent {
    Add(KronosSecurityPolicy),
    Delete(KronosSecurityPolicy),
}

pub struct CgroupPodContainerInfo {
    // pod info
    pub poduid: Arc<str>,
    pub podname: Arc<str>,
    pub namespace: Arc<str>,
    // pub label: Arc<str>,

    // container info
    pub container_id: Arc<str>,
    pub container_name: Arc<str>,
    pub container_image: Arc<str>,
}

// pub struct

pub enum RuleType {
    File {
        is_owner: bool,
        filenames: Vec<Arc<str>>,
        sources: Option<Vec<Arc<str>>>,
    },
    Binary(Vec<Arc<str>>),
    Network(NetworkTarget),
    Capability(Vec<Arc<str>>),
}
pub enum PolicyEbpfOperation {
    Add,
    Remove,
}

pub struct PolicyEbpfAdd {
    // pub cgroup_id: u64,
    pub policy_uid: Arc<str>,
    pub rule: RuleType,
    // pub operation: PolicyEbpfOperation,
    pub action: u8,
    pub onlyallow: u8,
    pub label_namespace_hash: u32,
}
pub struct policyEbpfRemove {
    pub policy_id: Arc<str>,
    pub onlyallow: bool,
    pub label_namespace_hash_vec: Vec<u32>,
}

pub enum PolicyBpfEvent {
    Add(PolicyEbpfAdd),
    Delete(policyEbpfRemove),
}

pub enum PodEbpfEvent {
    Add {
        poduid: Arc<str>,
        pod_cid: u64,
        namespace_hash: u32,
        target: u8,
    },
    Delete {
        poduid: Arc<str>,
        target: u8,
    },
}

pub struct KronosPolicyEbpfMaps {
    pub kronos_file_map: ayaHash<MapData, u64, FileMap>,
    pub kronos_sourcefile_map: ayaHash<MapData, u64, u32>,
    pub kronos_binary_map: ayaHash<MapData, u64, u8>,
    pub kronos_binary_allow_map: ayaHash<MapData, u64, BinaryAllowMap>,

    pub kronos_network_map: ayaHash<MapData, u64, NRule>,
    pub kronos_network_allow_map: ayaHash<MapData, u64, NetworkAllowValue>,
}

pub struct KronosPodEbpfMaps {
    pub kronos_pod_map: ayaHash<MapData, u64, PodBpfMap>,
}

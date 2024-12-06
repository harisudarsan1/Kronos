use std::{
    collections::{self, HashMap, HashSet},
    sync::Arc,
};

use log::info;
use tokio::sync::{mpsc, oneshot};
use types::{CgroupPodContainerInfo, KronosPod};

pub enum CacheMapOperation<K, V> {
    Add {
        key: K,
        value: V,
    },
    Remove {
        key: K,
        sender: Option<oneshot::Sender<Option<V>>>,
    },
    Get {
        key: K,
        sender: oneshot::Sender<Option<V>>,
    },
}

pub enum CacheSetOperations<K, V> {
    Add { map_key: K, set_value: V },
    Remove { map_key: K, set_value: V },
}

pub struct ContainerActor {
    // This cgroup_id should be of the container and can be used to map the cgroupid with
    // containerinfo for telemetry events
    pub container_info_map: HashMap<u64, Arc<CgroupPodContainerInfo>>,

    // This is necessary for cleaning up containerinfo when pod is deleted
    pub pod_to_cid_map: HashMap<Arc<str>, Arc<Vec<u64>>>,

    receiver: mpsc::Receiver<ContainerCache>,
}
pub enum ContainerCache {
    ContainerInfo(CacheMapOperation<u64, Arc<CgroupPodContainerInfo>>),
    PodToCid(CacheMapOperation<Arc<str>, Arc<Vec<u64>>>),
}
impl ContainerActor {
    pub fn new(rx: mpsc::Receiver<ContainerCache>) -> Self {
        let container_actor = ContainerActor {
            container_info_map: HashMap::new(),
            pod_to_cid_map: HashMap::new(),
            receiver: rx,
        };
        container_actor
    }

    fn handle_container_info(
        &mut self,
        request: CacheMapOperation<u64, Arc<CgroupPodContainerInfo>>,
    ) {
        match request {
            CacheMapOperation::Add { key, value } => {
                self.container_info_map.insert(key, value);
            }
            CacheMapOperation::Remove { key, sender } => {
                if let Some(containerInfo) = self.container_info_map.remove(&key) {
                    match sender {
                        Some(sender) => {
                            sender.send(Some(containerInfo));
                        }
                        None => {}
                    }
                }
            }
            CacheMapOperation::Get { key, sender } => match self.container_info_map.get(&key) {
                Some(containerInfo) => {
                    let containerInfo = containerInfo.clone();
                    sender.send(Some(containerInfo));
                }
                None => {
                    sender.send(None);
                }
            },
        }
    }
    fn handle_pod_cid_map(&mut self, request: CacheMapOperation<Arc<str>, Arc<Vec<u64>>>) {
        match request {
            CacheMapOperation::Add { key, value } => {
                self.pod_to_cid_map.insert(key, value);
            }
            CacheMapOperation::Get { key, sender } => match self.pod_to_cid_map.get(&key) {
                Some(container_cgroupids) => {
                    let container_cgroupids = container_cgroupids.clone();
                    sender.send(Some(container_cgroupids));
                }
                None => {
                    sender.send(None);
                }
            },
            CacheMapOperation::Remove { key, sender } => {
                if let Some(containerInfo) = self.pod_to_cid_map.remove(&key) {
                    match sender {
                        Some(sender) => {
                            sender.send(Some(containerInfo));
                        }
                        None => {}
                    }
                }
            }
        }
    }
}
pub async fn container_actor_handle(mut container_actor: ContainerActor) {
    while let Some(container_cache) = container_actor.receiver.recv().await {
        match container_cache {
            ContainerCache::ContainerInfo(container_info_request) => {
                container_actor.handle_container_info(container_info_request);
            }
            ContainerCache::PodToCid(pod_to_cid_request) => {
                container_actor.handle_pod_cid_map(pod_to_cid_request);
            }
        }
    }
}

pub struct PodActor {
    // NOTE: podmap is the map between label+namespace to the pod ids. We are using this hash for
    // policy deletion events
    podmap: HashMap<u32, HashSet<Arc<str>>>,

    receiver: mpsc::Receiver<PodCache>,
}
pub enum PodCache {
    PodMap(CacheMapOperation<u32, HashSet<Arc<str>>>),
    PodId(CacheSetOperations<u32, Arc<str>>),
}

impl PodActor {
    pub fn new(rx: mpsc::Receiver<PodCache>) -> Self {
        let pod_actor = PodActor {
            podmap: HashMap::new(),
            receiver: rx,
        };
        pod_actor
    }
    fn handle_pod_map(&mut self, request: CacheMapOperation<u32, HashSet<Arc<str>>>) {
        match request {
            CacheMapOperation::Add { key, value } => {
                self.podmap.insert(key, value);
            }
            CacheMapOperation::Get { key, sender } => {
                if let Some(pod_set) = self.podmap.get(&key) {
                    let podset = pod_set.clone();
                    sender.send(Some(podset));
                } else {
                    sender.send(None);
                }
            }
            CacheMapOperation::Remove { key, sender } => match sender {
                Some(sender) => {
                    if let Some(pod_set) = self.podmap.remove(&key) {
                        sender.send(Some(pod_set));
                    } else {
                        sender.send(None);
                    }
                }
                None => {}
            },
        }
    }
    fn handle_pod_set(&mut self, request: CacheSetOperations<u32, Arc<str>>) {
        match request {
            CacheSetOperations::Add { map_key, set_value } => {
                if let Some(podset) = self.podmap.get_mut(&map_key) {
                    podset.insert(set_value);
                }
            }
            CacheSetOperations::Remove { map_key, set_value } => {
                if let Some(podset) = self.podmap.get_mut(&map_key) {
                    podset.remove(&set_value);
                }
            }
        }
    }
}

pub async fn manage_pod_actor(mut pod_actor: PodActor) {
    while let Some(pod_request) = pod_actor.receiver.recv().await {
        match pod_request {
            PodCache::PodId(pod_set_request) => {
                pod_actor.handle_pod_set(pod_set_request);
            }
            PodCache::PodMap(pod_map_request) => {
                pod_actor.handle_pod_map(pod_map_request);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct PolicyInfo {
    pub onlyallow: bool,
    pub label_namespace_hash_vec: Vec<u32>,
}
pub struct PolicyActor {
    policy_info_map: HashMap<Arc<str>, PolicyInfo>,
    receiver: mpsc::Receiver<PolicyCache>,
}
pub enum PolicyCache {
    PolicyMap(CacheMapOperation<Arc<str>, PolicyInfo>),
}

impl PolicyActor {
    pub fn new(rx: mpsc::Receiver<PolicyCache>) -> Self {
        let policy_actor = PolicyActor {
            policy_info_map: HashMap::new(),
            receiver: rx,
        };
        policy_actor
    }
    fn handle_policy_request(&mut self, request: CacheMapOperation<Arc<str>, PolicyInfo>) {
        match request {
            CacheMapOperation::Add { key, value } => {
                self.policy_info_map.insert(key, value);
            }
            CacheMapOperation::Get { key, sender } => {
                if let Some(policy_info) = self.policy_info_map.get(&key) {
                    let policy_info = policy_info.clone();
                    sender.send(Some(policy_info));
                } else {
                    sender.send(None);
                }
            }
            CacheMapOperation::Remove { key, sender } => match sender {
                Some(sender) => {
                    if let Some(policy_info) = self.policy_info_map.remove(&key) {
                        sender.send(Some(policy_info));
                    } else {
                        sender.send(None);
                    }
                }
                None => {}
            },
        }
    }
}
pub async fn manage_policy_actor(mut policy_actor: PolicyActor) {
    while let Some(policy_request) = policy_actor.receiver.recv().await {
        match policy_request {
            PolicyCache::PolicyMap(policy_request) => {
                policy_actor.handle_policy_request(policy_request);
            }
        }
    }
}

pub struct TargetRefCount {
    pub file_count: u32,
    pub binary_count: u32,
    pub capability_count: u32,
    pub network_count: u32,
}

pub enum TargetCache {
    PolicyTarget(CacheMapOperation<u32, u8>),
    // GetTarget should be used to get the target for a pod based on the target ref counts
    GetTarget {
        key: u32,
        sender: oneshot::Sender<u8>,
    },
}

// NOTE: These targets and reference counts are just used as bloom filters to reduce the lookups in
// ebpf part. Otherwise these are unneccesary.
pub struct TargetCacheActor {
    policy_target: HashMap<u32, u8>,
    target_ref_count: HashMap<u32, TargetRefCount>,
    // The purpose of this previous_target is to send the pod_target only when
    // there is a change in previous target and the current target other wise there will be update
    // requests for each pod in the ebpf pods map which is very expensive
    previous_target: HashMap<u32, u8>,
    receiver: mpsc::Receiver<TargetCache>,
}
impl TargetCacheActor {
    pub fn new(rx: mpsc::Receiver<TargetCache>) -> Self {
        let target_actor = TargetCacheActor {
            policy_target: HashMap::new(),
            target_ref_count: HashMap::new(),
            previous_target: HashMap::new(),
            receiver: rx,
        };
        target_actor
    }

    fn handle_policy_target_operation(&mut self, request: CacheMapOperation<u32, u8>) {
        match request {
            CacheMapOperation::Add { key, value } => {
                info!(
                    "policy target for the policy:{}, is {} in cache manager",
                    key.clone(),
                    value
                );
                self.policy_target.insert(key, value);

                let ref_count = self.target_ref_count.get_mut(&key);

                let mut file_count = 0;
                let mut binary_count = 0;
                let mut network_count = 0;
                let mut capability_count = 0;
                if (value & 1) != 0 {
                    file_count = 1;
                }
                if (value & 2) != 0 {
                    binary_count = 1;
                }
                if (value & 3) != 0 {
                    network_count = 1;
                }
                if (value & 4) != 0 {
                    capability_count = 1;
                }
                match ref_count {
                    Some(target_ref_count) => {
                        target_ref_count.file_count += file_count;
                        target_ref_count.binary_count += binary_count;
                        target_ref_count.network_count += network_count;
                        target_ref_count.capability_count += capability_count;
                    }
                    None => {
                        self.target_ref_count.insert(
                            key,
                            TargetRefCount {
                                file_count,
                                binary_count,
                                network_count,
                                capability_count,
                            },
                        );
                    }
                }
            }
            CacheMapOperation::Remove { key, sender } => {
                if let Some(target) = self.policy_target.remove(&key) {
                    let mut file_count = 0;
                    let mut binary_count = 0;
                    let mut network_count = 0;
                    let mut capability_count = 0;
                    if (target & 1) != 0 {
                        file_count = 1;
                    }
                    if (target & 2) != 0 {
                        binary_count = 1;
                    }
                    if (target & 3) != 0 {
                        network_count = 1;
                    }
                    if (target & 4) != 0 {
                        capability_count = 1;
                    }
                    if let Some(target_ref_count) = self.target_ref_count.get_mut(&key) {
                        target_ref_count.file_count -= file_count;
                        target_ref_count.binary_count -= binary_count;
                        target_ref_count.network_count -= network_count;
                        target_ref_count.capability_count -= capability_count;
                        let file_remove_condition = target_ref_count.file_count == 0;
                        let binary_remove_condition = target_ref_count.binary_count == 0;
                        let network_remove_condition = target_ref_count.network_count == 0;
                        let capability_remove_condition = target_ref_count.capability_count == 0;
                        let mut pod_target = 0;

                        if file_remove_condition {
                            pod_target |= 1;
                        }
                        if binary_remove_condition {
                            pod_target |= 2;
                        }
                        if network_remove_condition {
                            pod_target |= 4;
                        }
                        if capability_remove_condition {
                            pod_target |= 8;
                        }

                        let mask = 0b0000_1111; // Example mask to flip only the last 4 bits
                        let pod_target = pod_target ^ mask;
                        let mut target_already_exists = false;
                        if let Some(prev_target) = self.previous_target.get(&key) {
                            if *prev_target == pod_target {
                                target_already_exists = true;
                            }
                        }
                        match sender {
                            Some(sender) => {
                                if !target_already_exists {
                                    sender.send(Some(pod_target));
                                } else {
                                    sender.send(None);
                                }

                                // after using this pod target and label+namespace the handle
                                // policy remove function can send request to ebpf manager to
                                // remove the pods with in this label+namespace
                            }
                            None => {}
                        }

                        self.previous_target.insert(key.clone(), pod_target);
                        let remove_condition = file_remove_condition
                            && binary_remove_condition
                            && capability_remove_condition
                            && network_remove_condition;
                        if remove_condition {
                            self.target_ref_count.remove(&key);
                        }
                    }
                }
            }
            // NOTE: This sends the target based on the ref_count for the usage of pods
            // This Get method doesn't send the policy target as policy target is not rew
            CacheMapOperation::Get { key, sender } => {
                if let Some(x) = self.policy_target.get(&key) {
                    sender.send(Some(x.clone()));
                } else {
                    sender.send(None);
                }
            }
        }
    }
    fn get_target_from_ref_count(&self, key: u32, sender: oneshot::Sender<u8>) {
        let mut target = 0;
        if let Some(target_ref_count) = self.target_ref_count.get(&key) {
            if target_ref_count.file_count > 0 {
                info!("file count > 0");
                target |= 1;
            }
            if target_ref_count.binary_count > 0 {
                target |= 2;
            }
            if target_ref_count.network_count > 0 {
                target |= 4;
            }
            if target_ref_count.capability_count > 0 {
                target |= 8;
            }
        }
        sender.send(target);
    }
}
pub async fn manage_target_cache_actor(mut target_cache_actor: TargetCacheActor) {
    while let Some(target_cache_request) = target_cache_actor.receiver.recv().await {
        info!("target cache initiated");
        match target_cache_request {
            TargetCache::PolicyTarget(x) => {
                target_cache_actor.handle_policy_target_operation(x);
            }
            TargetCache::GetTarget { key, sender } => {
                target_cache_actor.get_target_from_ref_count(key, sender);
            }
        }
    }
}

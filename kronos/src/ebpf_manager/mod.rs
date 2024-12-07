// use crate::bpfloader::load_bpf_programs;
mod bpfloader;
use aya::{maps::HashMap as ayaHash, Bpf};
use bpfloader::load_bpf_programs;
use dashmap::DashMap;
use futures::future::join;
use helpers::djb2_hash;
use kronos_common::{
    Allowrule, BinaryAllowMap, DNSAllowMap, DNSRule, FileAlert, FileMap, NRule, NetworkAllowValue,
    NetworkRule, PodBpfMap, SourceMap, TCPAllowMap, TCPRule, UDPAllowMap, UDPRule,
};

use log::info;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;
use types::{
    KronosPodEbpfMaps, KronosPolicyEbpfMaps, PodEbpfEvent, PolicyBpfEvent, RuleType, CRD::Direction,
};

use anyhow::{Context, Result};

pub struct EbpfManager {}
impl EbpfManager {
    pub fn new() -> Self {
        let ebpf_manager = EbpfManager {};
        ebpf_manager
    }

    pub async fn ebpf_manager(
        self: Arc<Self>,
        ebpf_policy_rx: mpsc::Receiver<PolicyBpfEvent>,
        ebpf_pod_rx: mpsc::Receiver<PodEbpfEvent>,
    ) {
        let mut ebpf: Bpf = load_bpf_programs().await.unwrap();

        let kronos_file_map: ayaHash<_, u64, FileMap> =
            ayaHash::try_from(ebpf.take_map("KRONOS_FILE_MAP").unwrap()).unwrap();

        let kronos_sourcefile_map: ayaHash<_, u64, u32> =
            ayaHash::try_from(ebpf.take_map("KRONOS_SOURCE_MAP").unwrap()).unwrap();

        let kronos_binary_map: ayaHash<_, u64, u8> =
            ayaHash::try_from(ebpf.take_map("KRONOS_BINARY_MAP").unwrap()).unwrap();

        let kronos_binary_allow_map: ayaHash<_, u64, BinaryAllowMap> =
            ayaHash::try_from(ebpf.take_map("KRONOS_ALLOW_BINARY_MAP").unwrap()).unwrap();

        let kronos_network_map: ayaHash<_, u64, NRule> =
            ayaHash::try_from(ebpf.take_map("KRONOS_NETWORK_MAP").unwrap()).unwrap();

        let kronos_network_allow_map: ayaHash<_, u64, NetworkAllowValue> =
            ayaHash::try_from(ebpf.take_map("KRONOS_ALLOW_NETWORK_MAP").unwrap()).unwrap();

        let  kronos_pod_map: ayaHash<_, u64, PodBpfMap> =
        // KRONOS_PODS Map will contain the cgroup_id to podebpfinfo map
            ayaHash::try_from(ebpf.take_map("KRONOS_PODS").unwrap()).unwrap();

        let pod_ebpf_maps = KronosPodEbpfMaps { kronos_pod_map };
        let policy_ebpf_maps = KronosPolicyEbpfMaps {
            kronos_file_map,
            kronos_sourcefile_map,
            kronos_binary_map,
            kronos_binary_allow_map,
            kronos_network_map,
            kronos_network_allow_map,
        };
        let ebpf_manager_clone = self.clone();

        let pod_handle = ebpf_manager_clone.pod_ebpf_manager(ebpf_pod_rx, pod_ebpf_maps);
        let policy_handle = self.policy_ebpf_manager(ebpf_policy_rx, policy_ebpf_maps);

        let _ = join(pod_handle, policy_handle).await;
    }

    async fn policy_ebpf_manager(
        &self,
        mut policy_rx: mpsc::Receiver<PolicyBpfEvent>,
        ebpf_maps: KronosPolicyEbpfMaps,
    ) -> Result<()> {
        info!("policy_ebpf_manager is called");
        struct EbpfManager {
            policy_filehash_map: HashMap<Arc<str>, Vec<u64>>,
            policy_sourcehash_map: HashMap<Arc<str>, Vec<u64>>,
            policy_binaryhash_map: HashMap<Arc<str>, Vec<u64>>,
            policy_network_map: HashMap<Arc<str>, Vec<u64>>,
            policy_net: HashMap<Arc<str>, u8>,
        }

        let mut ebpf_cache = EbpfManager {
            policy_filehash_map: HashMap::new(),
            policy_sourcehash_map: HashMap::new(),
            policy_binaryhash_map: HashMap::new(),
            policy_network_map: HashMap::new(),
            policy_net: HashMap::new(),
        };

        // if the value is 1 source exists which means only the allowed binaries should need to be
        // executed hence the ebpf program computes the hash of file+binary and compares it with
        // the filemap
        let mut kronos_file_map = ebpf_maps.kronos_file_map;
        let mut kronos_sourcefile_map = ebpf_maps.kronos_sourcefile_map;
        let mut kronos_binary_map = ebpf_maps.kronos_binary_map;
        let mut kronos_binary_allow_map = ebpf_maps.kronos_binary_allow_map;

        let mut kronos_network_map = ebpf_maps.kronos_network_map;
        let mut kronos_network_allow_map = ebpf_maps.kronos_network_allow_map;

        // Take ownership of the receiver if it exists
        while let Some(policy_event) = policy_rx.recv().await {
            // Perform eBPF operation based on the message
            //
            match policy_event {
                PolicyBpfEvent::Add(policy_ebpf) => {
                    info!(
                        "received a policy event in policy_ebpf_manager with policyid: {}",
                        policy_ebpf.policy_uid
                    );
                    match policy_ebpf.rule {
                        RuleType::File {
                            is_owner,
                            filenames,
                            sources,
                        } => {
                            // let is_source_exist = if sources.len() > 0 { true } else { false };
                            let mut file_hash_vec: Vec<u64> = vec![];
                            let mut source_hash_vec: Vec<u64> = vec![];

                            let is_file = 0;
                            match sources {
                                Some(sources) => {
                                    let is_file = 1;

                                    for file in filenames.iter() {
                                        info!("file name:{file}");
                                        let file_hash = djb2_hash(file);

                                        let file_namespace_hash: u64 = (file_hash as u64)
                                            ^ (policy_ebpf.label_namespace_hash as u64);
                                        for source in sources.iter() {
                                            // let input = format!("{}{}", file, source);
                                            let source_hash = djb2_hash(source) as u64;

                                            info!("source {} : hash:{}", source, source_hash);
                                            let file_source_hash: u64 =
                                                file_namespace_hash ^ source_hash;
                                            kronos_sourcefile_map
                                                .insert(file_source_hash, 1, 0)
                                                .context("Error while inserting sourcefile map")?;
                                            source_hash_vec.push(file_source_hash);
                                        }
                                        // Handle file hashes as well
                                        file_hash_vec.push(file_namespace_hash);
                                        let file_map = FileMap {
                                            is_file,
                                            only_allow: policy_ebpf.onlyallow,
                                            file_action: policy_ebpf.action,
                                            label_namespace_hash: policy_ebpf.label_namespace_hash,
                                        };
                                        kronos_file_map.insert(file_namespace_hash, file_map, 0)?;
                                    }
                                }
                                None => {
                                    // send the files without sources in ebpf map
                                    for file in filenames.iter() {
                                        println!("file name:{file}");
                                        let hash = djb2_hash(file);
                                        let final_hash: u64 = (hash as u64)
                                            ^ (policy_ebpf.label_namespace_hash as u64);
                                        file_hash_vec.push(final_hash);
                                        let file_map = FileMap {
                                            is_file,
                                            only_allow: policy_ebpf.onlyallow,
                                            file_action: policy_ebpf.action,
                                            label_namespace_hash: policy_ebpf.label_namespace_hash,
                                        };

                                        kronos_file_map.insert(final_hash, file_map, 0)?;
                                    }
                                }
                            }

                            ebpf_cache
                                .policy_filehash_map
                                .insert(policy_ebpf.policy_uid.clone(), file_hash_vec);
                            ebpf_cache
                                .policy_sourcehash_map
                                .insert(policy_ebpf.policy_uid, source_hash_vec);
                        }
                        RuleType::Binary(binaries) => {
                            let mut binary_hash_vec: Vec<u64> = Vec::new();

                            for binary_name in binaries.iter() {
                                let hash = djb2_hash(&binary_name);

                                let final_hash: u64 =
                                    (hash as u64) ^ (policy_ebpf.label_namespace_hash as u64);

                                if policy_ebpf.onlyallow == 1 {
                                    kronos_binary_allow_map.insert(
                                        final_hash,
                                        BinaryAllowMap::Null,
                                        0,
                                    )?;
                                } else {
                                    kronos_binary_map.insert(final_hash, 0, 0)?;
                                }
                                binary_hash_vec.push(final_hash);
                            }

                            if policy_ebpf.onlyallow == 1 {
                                let label_namespace_hash = policy_ebpf.label_namespace_hash as u64;
                                match kronos_binary_allow_map.get(&label_namespace_hash, 0).ok() {
                                    Some(v) => {
                                        if let BinaryAllowMap::LNvalue(mut rule) = v {
                                            let mut rule = rule;

                                            rule.count += 1;
                                            kronos_binary_allow_map.insert(
                                                label_namespace_hash,
                                                BinaryAllowMap::LNvalue(rule),
                                                0,
                                            )?;
                                        }
                                    }
                                    None => {
                                        let rule = Allowrule {
                                            count: 1,
                                            action: policy_ebpf.action,
                                        };
                                        kronos_binary_allow_map.insert(
                                            label_namespace_hash,
                                            BinaryAllowMap::LNvalue(rule),
                                            0,
                                        )?;
                                    }
                                }
                            }

                            ebpf_cache
                                .policy_binaryhash_map
                                .insert(policy_ebpf.policy_uid, binary_hash_vec);
                        }
                        RuleType::Network(network_target) => {
                            let mut network_hash_vec: Vec<u64> = Vec::new();
                            let mut net = 0;
                            let initial_allow_rule = Allowrule {
                                count: 0,
                                action: 2,
                            };

                            let mut dns_allow_rule = initial_allow_rule;
                            let mut tcp_allow_rule = initial_allow_rule;
                            let mut udp_allow_rule = initial_allow_rule;

                            if let Some(dns) = network_target.dns {
                                net = net | 4;
                                info!("received dns target");

                                for domain_name in dns.domain_names.iter() {
                                    let hash = djb2_hash(&domain_name);
                                    let final_hash = hash ^ policy_ebpf.label_namespace_hash;
                                    let final_hash = final_hash as u64;

                                    let rule = NRule {
                                        direction: 1,
                                        max_req: dns.maxreq,
                                        action: policy_ebpf.action,
                                        num_of_request: 0,
                                    };
                                    if policy_ebpf.onlyallow == 1 {
                                        dns_allow_rule.count = 1;
                                        dns_allow_rule.action = policy_ebpf.action;
                                        kronos_network_allow_map.insert(
                                            final_hash,
                                            NetworkAllowValue::Rule(rule),
                                            0,
                                        )?;
                                    } else {
                                        kronos_network_map.insert(final_hash, rule, 0);
                                    }

                                    network_hash_vec.push(final_hash);
                                }
                            }

                            if let Some(tcp) = network_target.tcp {
                                net = net | 2;
                                let direction = match tcp.direction {
                                    Direction::Ingress => -1,
                                    Direction::Egress => 1,
                                    Direction::Both => 0,
                                };

                                let rule = NRule {
                                    direction: direction,
                                    max_req: tcp.maxreq,
                                    action: policy_ebpf.action,
                                    num_of_request: 0,
                                };

                                for port in tcp.ports.iter() {
                                    // let hash = djb2_hash(domain_name);
                                    let final_hash =
                                        port.clone() as u32 ^ policy_ebpf.label_namespace_hash;
                                    let final_hash = final_hash as u64;
                                    if policy_ebpf.onlyallow == 1 {
                                        tcp_allow_rule.count = 1;
                                        tcp_allow_rule.action = policy_ebpf.action;
                                        kronos_network_allow_map.insert(
                                            final_hash,
                                            NetworkAllowValue::Rule(rule),
                                            0,
                                        )?;
                                    } else {
                                        kronos_network_map.insert(final_hash, rule, 0);
                                    }

                                    network_hash_vec.push(final_hash);
                                }
                            }

                            if let Some(udp) = network_target.udp {
                                net = net | 1;
                                let direction = match udp.direction {
                                    Direction::Ingress => -1,
                                    Direction::Egress => 1,
                                    Direction::Both => 0,
                                };
                                let rule = NRule {
                                    direction: direction,
                                    max_req: udp.maxreq,
                                    action: policy_ebpf.action,
                                    num_of_request: 0,
                                };

                                for port in udp.ports.iter() {
                                    // let hash = djb2_hash(domain_name);
                                    let final_hash =
                                        port.clone() as u32 ^ policy_ebpf.label_namespace_hash;
                                    let final_hash = final_hash as u64;
                                    if policy_ebpf.onlyallow == 1 {
                                        tcp_allow_rule.count = 1;
                                        tcp_allow_rule.action = policy_ebpf.action;
                                        kronos_network_allow_map.insert(
                                            final_hash,
                                            NetworkAllowValue::Rule(rule),
                                            0,
                                        )?;
                                    } else {
                                        kronos_network_map.insert(final_hash, rule, 0);
                                    }

                                    network_hash_vec.push(final_hash);
                                }
                            }

                            if policy_ebpf.onlyallow == 1 {
                                let label_namespace_hash = policy_ebpf.label_namespace_hash as u64;
                                match kronos_network_allow_map.get(&label_namespace_hash, 0).ok() {
                                    Some(x) => {
                                        if let NetworkAllowValue::LNValue { dns, udp, tcp } = x {
                                            dns_allow_rule.count += dns.count;
                                            tcp_allow_rule.count += tcp.count;
                                            udp_allow_rule.count += udp.count;
                                        }
                                    }
                                    None => {}
                                }

                                let mut lnvalue = NetworkAllowValue::LNValue {
                                    dns: dns_allow_rule,
                                    udp: tcp_allow_rule,
                                    tcp: udp_allow_rule,
                                };
                                kronos_network_allow_map.insert(label_namespace_hash, lnvalue, 0);
                            }
                            ebpf_cache
                                .policy_net
                                .insert(policy_ebpf.policy_uid.clone(), net);

                            ebpf_cache
                                .policy_network_map
                                .insert(policy_ebpf.policy_uid, network_hash_vec);
                        }
                        _ => {}
                    }
                }
                PolicyBpfEvent::Delete(policy_remove_info) => {
                    // DELETE file related info from ebpf map and cache
                    let policy_id = policy_remove_info.policy_id;
                    info!("policy bpf event called with policy id:{policy_id}");
                    if let Some(file_hash_vec) = ebpf_cache.policy_filehash_map.remove(&policy_id) {
                        for file_hash in file_hash_vec.iter() {
                            info!("removing file hash:{file_hash}");
                            kronos_file_map.remove(file_hash)?;
                        }
                    }

                    // DELETE source related info from ebpf map and cache

                    if let Some(source_hash_vec) =
                        ebpf_cache.policy_sourcehash_map.remove(&policy_id)
                    {
                        for source_hash in source_hash_vec.iter() {
                            info!("removing source hash:{source_hash}");
                            kronos_sourcefile_map.remove(source_hash)?;
                        }
                    }

                    // DELETE Binary related info from ebpf map and cache

                    if let Some(binary_hash_vec) =
                        ebpf_cache.policy_binaryhash_map.remove(&policy_id)
                    {
                        for binary_hash in binary_hash_vec.iter() {
                            info!("removing source hash:{binary_hash}");
                            if policy_remove_info.onlyallow == true {
                                kronos_binary_allow_map.remove(binary_hash)?;
                            } else {
                                kronos_binary_map.remove(binary_hash)?;
                            }
                        }
                        for label_namespace_hash in
                            policy_remove_info.label_namespace_hash_vec.iter()
                        {
                            let label_namespace_hash = label_namespace_hash.clone() as u64;
                            match kronos_binary_allow_map.get(&label_namespace_hash, 0).ok() {
                                Some(v) => {
                                    if let BinaryAllowMap::LNvalue(mut rule) = v {
                                        // rule.count -= 1;
                                        let arule = Allowrule {
                                            count: rule.count - 1,
                                            action: rule.action,
                                        };
                                        // let value = v + 1;
                                        kronos_binary_allow_map.insert(
                                            label_namespace_hash,
                                            BinaryAllowMap::LNvalue(arule),
                                            0,
                                        )?;
                                    }
                                    // kronos_binary_allow_map.insert(label_namespace_hash, value, 0);
                                }
                                None => {}
                            }
                        }
                    }

                    // DELETE Network related info from ebpf map and cache
                    if let Some(network_hash_vec) = ebpf_cache.policy_network_map.remove(&policy_id)
                    {
                        let mut net = 0;

                        if let Some(network) = ebpf_cache.policy_net.remove(&policy_id) {
                            net = network;
                        }
                        for net_hash in network_hash_vec.iter() {
                            info!("removing source hash:{net_hash}");
                            if policy_remove_info.onlyallow == true {
                                kronos_network_allow_map.remove(net_hash)?;
                            } else {
                                kronos_network_map.remove(net_hash)?;
                            }
                        }
                        let mut net = 0;
                        for label_namespace_hash in
                            policy_remove_info.label_namespace_hash_vec.iter()
                        {
                            let label_namespace_hash = label_namespace_hash.clone() as u64;
                            match kronos_network_allow_map.get(&label_namespace_hash, 0).ok() {
                                Some(v) => {
                                    if let NetworkAllowValue::LNValue { dns, udp, tcp } = v {
                                        let mut udp_rule = udp;
                                        let mut tcp_rule = tcp;
                                        let mut dns_rule = dns;
                                        if net & 1 != 0 {
                                            udp_rule.count = udp_rule.count - 1;
                                        }

                                        if net & 2 != 0 {
                                            tcp_rule.count = tcp_rule.count - 1;
                                        }

                                        if net & 4 != 0 {
                                            dns_rule.count = dns_rule.count - 1;
                                        }
                                        kronos_network_allow_map.insert(
                                            label_namespace_hash,
                                            NetworkAllowValue::LNValue {
                                                dns: dns_rule,
                                                udp: udp_rule,
                                                tcp: tcp_rule,
                                            },
                                            0,
                                        );
                                    }
                                    // kronos_binary_allow_map.insert(label_namespace_hash, value, 0);
                                }
                                None => {}
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn pod_ebpf_manager(
        &self,
        mut pod_rx: mpsc::Receiver<PodEbpfEvent>,
        ebpf_maps: KronosPodEbpfMaps,
    ) -> Result<()> {
        struct EbpfCache {
            pod_cid_map: Arc<DashMap<Arc<str>, u64>>,
        }
        let ebpf_cache = EbpfCache {
            pod_cid_map: Arc::new(DashMap::new()),
        };

        let mut kronos_pod_map = ebpf_maps.kronos_pod_map;

        // let mut kronos_pod_map: HashMap<_, u64, PodBpfMap> =
        // // KRONOS_PODS Map will contain the cgroup_id to podebpfinfo map
        //     HashMap::try_from(self.ebpf.take_map("KRONOS_PODS").unwrap()).unwrap();

        while let Some(pod_event) = pod_rx.recv().await {
            match pod_event {
                PodEbpfEvent::Add {
                    poduid,
                    pod_cid,
                    namespace_hash,
                    target,
                } => {
                    info!("received pod :{} in ebpf manager", poduid);
                    ebpf_cache.pod_cid_map.insert(poduid.clone(), pod_cid);
                    let pod_ebpf_map = PodBpfMap {
                        target,
                        namespace_hash,
                    };
                    kronos_pod_map.insert(pod_cid, pod_ebpf_map, 0)?;
                }
                PodEbpfEvent::Delete { poduid, target } => {
                    info!(
                        "received pod deletion event for pod :{} in ebpf manager",
                        poduid
                    );
                    let cgroupid = ebpf_cache.pod_cid_map.get(&poduid).ok_or_else(|| {
                        anyhow::anyhow!("No cgroup ID found for pod UID: {}", poduid)
                    })?;
                    let cgroupid: u64 = *cgroupid;
                    if target == 0 {
                        kronos_pod_map.remove(&cgroupid)?;
                    } else {
                        let mut podbpfmap = kronos_pod_map.get(&cgroupid, 0).unwrap();
                        podbpfmap.target = target;
                        kronos_pod_map.insert(cgroupid, podbpfmap, 0)?;
                    }
                }
            }
        }
        Ok(())
    }
}

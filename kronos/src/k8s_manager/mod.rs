use crate::cache_manager::{
    CacheMapOperation, CacheSetOperations, ContainerCache, PodCache, PolicyCache, PolicyInfo,
    TargetCache,
};

use futures::future::join;
use futures::{Stream, StreamExt};
use helpers::system::kernel::{get_cgroup_driver, CgroupDriver, CGROUPFS_PATH};
use helpers::{djb2_hash, k8s_helpers::kubernetes, system::kernel};
use k8s_watch::{get_pods_from_labels_namespace, watch_crd, watch_pods};
use kube::ResourceExt;
use log::info;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};
use tokio::sync::{mpsc, oneshot};
use types::KronosPodContainerInfo;
use types::{
    policyEbpfRemove, CgroupPodContainerInfo, KronosEvent, KronosPod, PodEbpfEvent, PodEvent,
    PolicyBpfEvent, PolicyEbpfAdd, RuleType,
    CRD::{Action, KronosSecurityPolicySpec},
};

use anyhow::{Context, Result};
mod k8s_watch;

pub struct K8sManager {
    cgroup_driver: CgroupDriver,
    pod_map_tx: mpsc::Sender<PodCache>,

    pub policy_map_tx: mpsc::Sender<PolicyCache>,
    target_cache_tx: mpsc::Sender<TargetCache>,

    container_tx: mpsc::Sender<ContainerCache>,

    pod_filter_map: Arc<RwLock<HashMap<Arc<str>, u32>>>,
    // channel for policies
    pub ebpf_policy_sender: mpsc::Sender<PolicyBpfEvent>,

    //Channel for Pod
    pub ebpf_pod_sender: mpsc::Sender<PodEbpfEvent>,
}

pub struct ChannelSender {
    pub pod_map_tx: mpsc::Sender<PodCache>,
    pub policy_map_tx: mpsc::Sender<PolicyCache>,
    pub target_cache_tx: mpsc::Sender<TargetCache>,

    pub container_tx: mpsc::Sender<ContainerCache>,

    // channel for policies
    pub ebpf_policy_sender: mpsc::Sender<PolicyBpfEvent>,

    //Channel for Pod
    pub ebpf_pod_sender: mpsc::Sender<PodEbpfEvent>,
}

impl K8sManager {
    pub fn new(channel_sender: ChannelSender, cgroup_driver: CgroupDriver) -> Self {
        let k8s_manager = K8sManager {
            cgroup_driver: cgroup_driver,
            pod_map_tx: channel_sender.pod_map_tx,
            policy_map_tx: channel_sender.policy_map_tx,
            target_cache_tx: channel_sender.target_cache_tx,
            container_tx: channel_sender.container_tx,
            ebpf_policy_sender: channel_sender.ebpf_policy_sender,
            ebpf_pod_sender: channel_sender.ebpf_pod_sender,
            pod_filter_map: Arc::new(RwLock::new(HashMap::new())),
        };
        k8s_manager
    }

    async fn send_policy_to_ebpf_manager(
        &self,
        policyid: Arc<str>,
        policy: KronosSecurityPolicySpec,
        hash_vec: Vec<u32>,
    ) -> Result<()> {
        let action: u8 = match policy.action {
            Action::Block => 1,
            Action::Audit => 0,
        };
        let mut onlyallow = 0;
        if policy.only_allow {
            onlyallow = 1;
        }
        // let labels = policy.selectors.match_labels.clone();
        // let policy_namespace = Arc::<str>::from(policy.selectors.namespace.clone());
        // let namespace_hash = djb2_hash(&policy_namespace);
        let mut policy_target = 0;

        for lb_name_hash in hash_vec.iter() {
            if let Some(file_target) = policy.targets.file.clone() {
                policy_target |= 1;

                let policy_ebpf: PolicyEbpfAdd = PolicyEbpfAdd {
                    // cgroup_id: cgroup_id,
                    action: action,
                    onlyallow,
                    policy_uid: policyid.clone(),
                    rule: RuleType::File {
                        is_owner: file_target.is_owner,
                        filenames: file_target.values,
                        sources: file_target.source,
                    },
                    label_namespace_hash: lb_name_hash.clone(),
                };

                // sending policy data to ebpf
                if let Err(e) = self
                    .ebpf_policy_sender
                    .try_send(PolicyBpfEvent::Add(policy_ebpf))
                {
                    eprintln!("Failed to send pod event to ebpf manager: {:?}", e);
                    // You might want to handle or log this in some way, as the event was not sent
                }
            }

            if let Some(binaries) = policy.targets.binaries.clone() {
                policy_target |= 2;

                let policy_ebpf: PolicyEbpfAdd = PolicyEbpfAdd {
                    // cgroup_id: cgroup_id,
                    action: action,
                    onlyallow,
                    policy_uid: policyid.clone(),
                    rule: RuleType::Binary(binaries),
                    label_namespace_hash: lb_name_hash.clone(),
                };

                // sending policy data to ebpf
                if let Err(e) = self
                    .ebpf_policy_sender
                    .try_send(PolicyBpfEvent::Add(policy_ebpf))
                {
                    eprintln!("Failed to send pod event to ebpf manager: {:?}", e);
                    // You might want to handle or log this in some way, as the event was not sent
                }
            }

            if let Some(network_target) = policy.targets.network.clone() {
                policy_target |= 3;

                let policy_ebpf: PolicyEbpfAdd = PolicyEbpfAdd {
                    // cgroup_id: cgroup_id,
                    action: action,
                    onlyallow,
                    policy_uid: policyid.clone(),
                    rule: RuleType::Network(network_target),
                    label_namespace_hash: lb_name_hash.clone(),
                };

                // sending policy data to ebpf
                if let Err(e) = self
                    .ebpf_policy_sender
                    .try_send(PolicyBpfEvent::Add(policy_ebpf))
                {
                    eprintln!("Failed to send pod event to ebpf manager: {:?}", e);
                    // You might want to handle or log this in some way, as the event was not sent
                }
            }

            info!(
                "policy target for the policy:{}, is {}",
                policyid.clone(),
                policy_target
            );

            // Add target to the policy target bitflag
            self.target_cache_tx
                .try_send(TargetCache::PolicyTarget(CacheMapOperation::Add {
                    key: lb_name_hash.clone(),
                    value: policy_target,
                }))
                .context("Error while sending policy target to target cache")?;
        }
        let policy_info = PolicyInfo {
            onlyallow: policy.only_allow,
            label_namespace_hash_vec: hash_vec,
        };
        self.policy_map_tx
            .try_send(PolicyCache::PolicyMap(CacheMapOperation::Add {
                key: policyid.clone(),
                value: policy_info,
            }))
            .context("Error while sending policy info to policy map")?;
        Ok(())
    }

    async fn remove_policy_from_ebpf_map(&self, policy_id: Arc<str>) -> Result<()> {
        info!("remove_policy_from_ebpf_map is called with id {policy_id}");

        let (send, recv) = oneshot::channel();
        self.policy_map_tx
            .send(PolicyCache::PolicyMap(CacheMapOperation::Remove {
                key: policy_id.clone(),
                sender: Some(send),
            }))
            .await
            .context("Error while removing policy info for policy id ")?;

        if let Ok(policy_info) = recv.await {
            match policy_info {
                Some(info) => {
                    let policy_ebpf_remove = policyEbpfRemove {
                        policy_id: policy_id,
                        onlyallow: info.onlyallow,
                        label_namespace_hash_vec: info.label_namespace_hash_vec,
                    };

                    if let Err(e) = self
                        .ebpf_policy_sender
                        .try_send(PolicyBpfEvent::Delete(policy_ebpf_remove))
                    {
                        eprintln!(
                            "Failed to send policy event to ebpf manager while delete: {:?}",
                            e
                        );
                    }
                }
                None => {}
            }
        }
        Ok(())
    }

    async fn send_pods_to_ebpf_manager(&self, pod: KronosPod) -> Result<()> {
        let poduid = pod.poduid.clone();
        let new_poduid = poduid.replace("-", "_");
        let pod_cgroup_path =
            kernel::get_pod_cgroup_path(&new_poduid, &pod.qos_class, &self.cgroup_driver);

        let namespace_hash = djb2_hash(&pod.namespace);

        let pod_cid = unsafe { kernel::get_cgroup_id(pod_cgroup_path.clone()) };
        info!(
            "pod cgroupid: {} for cgroup path{}",
            pod_cid, pod_cgroup_path
        );

        let (send, recv) = oneshot::channel();
        self.target_cache_tx.try_send(TargetCache::GetTarget {
            key: pod.label_namespace_hash,
            sender: send,
        })?;

        if let Ok(target) = recv.await {
            info!("receved target {target}");
            if target == 0 {
                return Ok(());
            }
            let pod_ebpf_event = PodEbpfEvent::Add {
                poduid: poduid.clone(),
                pod_cid: pod_cid,
                namespace_hash: pod.label_namespace_hash,
                target: target,
            };

            if let Err(e) = self.ebpf_pod_sender.try_send(pod_ebpf_event) {
                eprintln!(
                    "Failed to send pod event to ebpf manager: while adding {:?}",
                    e
                );
                // You might want to handle or log this in some way, as the event was not sent
            }
        }
        Ok(())
    }

    async fn remove_pods_from_ebpf_map(&self, poduid: Arc<str>, target: u8) -> Result<()> {
        let pod_ebpf_event = PodEbpfEvent::Delete { poduid, target };

        // send pod event to pod ebpf manager
        if let Err(e) = self.ebpf_pod_sender.try_send(pod_ebpf_event) {
            eprintln!(
                "Failed to send pod event to ebpf manager while removing the pod: {:?}",
                e
            );
            // You might want to handle or log this in some way, as the event was not sent
        }
        Ok(())
    }

    async fn handle_pod_add(&self, pod: KronosPodContainerInfo) -> Result<()> {
        let pod_uid = pod.poduid;
        let new_poduid = pod_uid.replace("-", "_");

        let podname = pod.podname;
        let qos_class = pod.qos_class;

        let mut cid_vec: Vec<u64> = Vec::new();
        for container in pod.container_map.iter() {
            let c_pod_cont_info = CgroupPodContainerInfo {
                poduid: pod_uid.clone(),
                podname: podname.clone(),
                namespace: pod.namespace.clone(),
                container_id: container.container_id.clone(),
                container_name: container.container_name.clone(),
                container_image: container.container_image.clone(),
            };
            // NOTE: container_id looks like this containerd://de89a6cd92d2... the first element of the
            // split will be the runtime and the second is the actual id of the container
            let container_id_split: Vec<&str> = c_pod_cont_info.container_id.split("://").collect();
            let cgroup_path = kernel::get_container_cgroup_path(
                &new_poduid,
                &qos_class,
                container_id_split[1],
                container_id_split[0],
                &self.cgroup_driver,
            );
            let cgroup_id = unsafe { kernel::get_cgroup_id(cgroup_path) };

            // self.cgroup_id_map.insert(cgroup_id, c_pod_cont_info);
            self.container_tx
                .try_send(ContainerCache::ContainerInfo(CacheMapOperation::Add {
                    key: cgroup_id,
                    value: Arc::new(c_pod_cont_info),
                }))?;

            cid_vec.push(cgroup_id);
        }

        // self.pod_to_cid_map.insert(pod_uid.clone(), cid_vec);
        self.container_tx
            .try_send(ContainerCache::PodToCid(CacheMapOperation::Add {
                key: pod_uid.clone(),
                value: Arc::new(cid_vec),
            }))?;
        Ok(())
    }

    async fn handle_pod_remove(&self, poduid: Arc<str>) -> Result<()> {
        let (send, recv) = oneshot::channel();
        self.container_tx
            .try_send(ContainerCache::PodToCid(CacheMapOperation::Remove {
                key: poduid.clone(),
                sender: Some(send),
            }))?;

        // removing cgroup_id container info only when the poduid got some return value
        if let Ok(Some(Container_cids)) = recv.await {
            for id in Container_cids.iter() {
                self.container_tx.try_send(ContainerCache::ContainerInfo(
                    CacheMapOperation::Remove {
                        key: id.clone(),
                        sender: None,
                    },
                ))?;
            }
        }
        // TODO: Remove pods from the PodCache map
        Ok(())
    }
    // async fn handle_policy_add(&self) {}
    async fn handle_policy_remove(&self, label_namespace: u32) -> Result<()> {
        let (send, recv) = oneshot::channel();
        self.target_cache_tx
            .try_send(TargetCache::PolicyTarget(CacheMapOperation::Remove {
                key: label_namespace.clone(),
                sender: Some(send),
            }))?;
        if let Ok(Some(target)) = recv.await {
            // If this target is zero there are no policies associated with this label+namespace
            // key hence we need to remove all pods associated with this in PodCache(this contains
            // label_namespace to podid_set map) and ebpf. For ebpf just sending the target as it
            // is is sufficient

            let (send, recv) = oneshot::channel();
            if target != 0 {
                self.pod_map_tx
                    .try_send(PodCache::PodMap(CacheMapOperation::Get {
                        key: label_namespace,
                        sender: send,
                    }))?;
            } else {
                self.pod_map_tx
                    .try_send(PodCache::PodMap(CacheMapOperation::Remove {
                        key: label_namespace,
                        sender: Some(send),
                    }))?;
            }

            if let Ok(Some(podset)) = recv.await {
                for pod_id in podset.iter() {
                    // self.handle_pod_remove(pod_id.clone());
                    self.remove_pods_from_ebpf_map(pod_id.clone(), target)
                        .await?;
                }
            }
        }
        Ok(())
    }
    async fn handle_pods(self: Arc<K8sManager>) -> Result<()> {
        let (pod_tx, mut pod_rx): (mpsc::Sender<PodEvent>, mpsc::Receiver<PodEvent>) =
            mpsc::channel(100);

        let handle = tokio::spawn(async move {
            watch_pods(pod_tx.clone()).await;
        });

        while let Some(event) = pod_rx.recv().await {
            match event {
                PodEvent::Add(pod) => {
                    // spawn this as a seperate task using spawn_blocking

                    let namespace = pod.namespace.clone();
                    let podlabels = pod.labels.clone();
                    for label in podlabels.iter() {
                        let label_namespace = format!("{}{}", label.clone(), namespace.clone());
                        let label_namespace = Arc::from(label_namespace);

                        let label_namespace_hash = djb2_hash(&label_namespace);
                        let mut is_kronos_pod = false;
                        {
                            let mut read_guard =
                                self.pod_filter_map.read().expect("Failed to read");
                            if let Some(count) = read_guard.get(&label_namespace) {
                                if count.clone() > 0 {
                                    is_kronos_pod = true;
                                }
                            }
                        }
                        if is_kronos_pod {
                            // let kronospod = KronosPodContainerInfo {
                            //     poduid: pod.poduid.clone(),
                            //     podname: pod.podname.clone(),
                            //     qos_class: pod.qos_class.clone(),
                            //     label_namespace: label_namespace, // container_map: container_map,
                            //     namespace: namespace.clone(),
                            //     label: label.to_owned(),
                            //     container_map: pod.container_map.clone(),
                            // };
                            // self.handle_pod_add(kronospod).await;

                            let kronospod = KronosPod {
                                poduid: pod.poduid.clone(),
                                podname: pod.podname.clone(),
                                qos_class: pod.qos_class.clone(),
                                label_namespace: label_namespace,
                                label_namespace_hash,
                                namespace: namespace.clone(),
                            };

                            info!("pod : {}", pod.poduid.clone());
                            self.send_pods_to_ebpf_manager(kronospod).await?;
                        }
                    }
                }
                PodEvent::Delete(podid) => {
                    info!("pod : {}", podid.clone());
                    // self.handle_pod_remove(podid.clone());
                    // remove pod from ebpf maps
                    self.remove_pods_from_ebpf_map(podid, 0).await;
                }
            }
        }
        // handle.await;
        Ok(())
    }

    async fn handle_policies(self: Arc<K8sManager>) -> Result<()> {
        let (kronos_tx, mut kronos_rx): (mpsc::Sender<KronosEvent>, mpsc::Receiver<KronosEvent>) =
            mpsc::channel(100);

        tokio::spawn(async move {
            watch_crd(kronos_tx).await;
        });

        // The pods are added only after handling the polcies and updating ebpf maps this should
        // be synchronous to ensure the correctnes of the enforcement. This whole pipeline should
        // not be asynchronous
        // TODO: Execute handle_policy_add as a seperate task and await it before listing the pods
        // so that we can update the cache concurrently

        while let Some(event) = kronos_rx.recv().await {
            match event {
                KronosEvent::Add(policy) => {
                    info!("got a policy");
                    let namespace = Arc::<str>::from(policy.spec.selectors.namespace.clone());
                    let labels = policy.spec.selectors.match_labels.clone();
                    let policy_id = Arc::<str>::from(policy.uid().clone().unwrap());

                    let mut hash_vec: Vec<u32> = Vec::new();
                    let self_clone = self.clone();
                    {
                        // Update pod_filter cache
                        let mut write_guard = self_clone
                            .pod_filter_map
                            .write()
                            .expect("Failed to acquire write lock");
                        for label in labels.iter() {
                            let label_namespace = format!("{}{}", label.clone(), namespace.clone());
                            let label_namespace = Arc::from(label_namespace);
                            let label_namespace_hash = djb2_hash(&label_namespace);
                            hash_vec.push(label_namespace_hash);
                            match write_guard.get_mut(&label_namespace) {
                                Some(count) => {
                                    *count += 1;
                                }
                                None => {
                                    write_guard.insert(label_namespace, 1);
                                }
                            }
                        }
                    }

                    let new_self = self.clone();
                    let policy_handle = tokio::spawn(async move {
                        new_self
                            .send_policy_to_ebpf_manager(policy_id, policy.spec, hash_vec)
                            .await;
                    });

                    let concatenated_labels = labels.join(",");

                    // info!("namespace : {namespace}, labels:{concatenated_labels}");

                    // logic to get the pods matching with the namespace and labels after adding
                    // policy
                    //  function to get a stream of PodInfo items
                    let mut pod_info_stream = Box::pin(
                        get_pods_from_labels_namespace(concatenated_labels, namespace.clone())
                            .await,
                    );
                    // wait the policy related caches to be set before adding pods to them
                    // Consume the stream, processing each PodInfo as it becomes available

                    // let the policies applied before processing the pods
                    policy_handle.await?;
                    while let Some(pod_info) = pod_info_stream.next().await {
                        let mut pod_label = Arc::from("");
                        for label in labels.iter() {
                            match pod_info.labels.get(label) {
                                Some(label) => {
                                    pod_label = label.to_owned();
                                    break;
                                }
                                None => {
                                    continue;
                                }
                            }
                        }

                        let label_namespace = format!("{}{}", pod_label.clone(), namespace.clone());
                        let label_namespace: Arc<str> = Arc::from(label_namespace);

                        let label_namespace_hash = djb2_hash(&label_namespace);
                        let kronos_pod_container_info = KronosPodContainerInfo {
                            poduid: pod_info.poduid.clone(),
                            podname: pod_info.podname.clone(),
                            qos_class: pod_info.qos_class.clone(),
                            namespace: namespace.clone(),
                            label: pod_label,
                            label_namespace: label_namespace.clone(),
                            container_map: pod_info.container_map,
                        };
                        let kronospod = KronosPod {
                            poduid: pod_info.poduid,
                            podname: pod_info.podname,
                            qos_class: pod_info.qos_class,
                            label_namespace: label_namespace,
                            label_namespace_hash,
                            namespace: namespace.clone(),
                        };

                        // self.handle_pod_add(kronos_pod_container_info).await;
                        let new_self = self.clone();
                        tokio::spawn(async move {
                            new_self.send_pods_to_ebpf_manager(kronospod).await;
                        });
                    }
                }
                KronosEvent::Delete(policy) => {
                    info!("got a policy");
                    let namespace = Arc::<str>::from(policy.spec.selectors.namespace.clone());
                    let labels = policy.spec.selectors.match_labels.clone();
                    let policy_id = Arc::<str>::from(policy.uid().clone().unwrap());

                    {
                        // Update pod_filter cache
                        let mut write_guard = self
                            .pod_filter_map
                            .write()
                            .expect("Failed to acquire write lock");
                        for label in labels.iter() {
                            let label_namespace = format!("{}{}", label.clone(), namespace.clone());
                            let label_namespace = Arc::from(label_namespace);

                            let label_namespace_hash = djb2_hash(&label_namespace);
                            match write_guard.get_mut(&label_namespace) {
                                Some(count) => {
                                    if *count == 1 {
                                        write_guard.remove(&label_namespace);
                                    } else {
                                        *count -= 1;
                                    }
                                }
                                None => {}
                            }
                            let new_self = self.clone();
                            tokio::spawn(async move {
                                new_self.handle_policy_remove(label_namespace_hash).await;
                            });
                        }
                    }

                    self.remove_policy_from_ebpf_map(policy_id).await;
                }
            }
        }
        Ok(())
    }

    pub async fn k8s_manager(self: Arc<Self>) {
        let self_clone = self.clone();
        let pod_handle = self_clone.handle_pods();
        let policy_handle = self.handle_policies();

        let _ = join(pod_handle, policy_handle).await;
    }
}

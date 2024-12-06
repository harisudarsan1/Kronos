use crate::cache_manager::{
    container_actor_handle, manage_pod_actor, manage_policy_actor, manage_target_cache_actor,
    ContainerActor, PodActor, PolicyActor, TargetCacheActor,
};
use crate::ebpf_manager::EbpfManager;
use crate::k8s_manager::{ChannelSender, K8sManager};
use futures::join;
use std::sync::Arc;
use tokio::sync::mpsc;

pub async fn start_daemon() {
    let (ebpf_policy_tx, ebpf_policy_rx) = mpsc::channel(1000); // Adjust buffer size as needed
    let (ebpf_pod_tx, ebpf_pod_rx) = mpsc::channel(1000); // Adjust buffer size as needed
                                                          //
    let (pod_map_tx, pod_map_rx) = mpsc::channel(1000);
    let (policy_target_tx, policy_target_rx) = mpsc::channel(1000);

    let (container_tx, container_rx) = mpsc::channel(1000);
    let (policy_tx, policy_rx) = mpsc::channel(1000);

    let container_cache_handle = tokio::spawn(async move {
        let container_actor = ContainerActor::new(container_rx);
        container_actor_handle(container_actor).await;
    });
    let pod_cache_handle = tokio::spawn(async move {
        let pod_actor = PodActor::new(pod_map_rx);
        manage_pod_actor(pod_actor).await;
    });

    let policy_cache_handle = tokio::spawn(async move {
        let policy_actor = PolicyActor::new(policy_rx);
        manage_policy_actor(policy_actor).await;
    });

    let target_cache_handle = tokio::spawn(async move {
        let target_actor = TargetCacheActor::new(policy_target_rx);
        manage_target_cache_actor(target_actor).await;
    });

    let channel_sender = ChannelSender {
        pod_map_tx: pod_map_tx,
        container_tx: container_tx,
        policy_map_tx: policy_tx,
        target_cache_tx: policy_target_tx,
        ebpf_policy_sender: ebpf_policy_tx,
        ebpf_pod_sender: ebpf_pod_tx,
    };
    tokio::spawn(async move {
        let k8s_manager = Arc::new(K8sManager::new(channel_sender));
        k8s_manager.k8s_manager().await;
    });
    let ebpf_manager = Arc::new(EbpfManager::new());
    ebpf_manager.ebpf_manager(ebpf_policy_rx, ebpf_pod_rx).await;
}

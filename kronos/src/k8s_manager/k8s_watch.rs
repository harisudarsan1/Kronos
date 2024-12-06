use anyhow::{Context, Ok, Result};
use futures::{stream, Stream, StreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, ListParams, ResourceExt},
    runtime::{
        watcher::{self, watcher, Event},
        WatchStreamExt,
    },
    Client,
};
use log::info;
use std::{collections::HashSet, sync::Arc};
use tokio::sync::mpsc;

use types::{ContainerInfo, KronosEvent, PodEvent, PodInfo, CRD::KronosSecurityPolicy};

pub async fn watch_pods(tx: mpsc::Sender<PodEvent>) -> Result<()> {
    info!("watch pods called");
    let client = Client::try_default().await?;

    info!("k8s client initialized");
    let pods: Api<Pod> = Api::all(client);

    // Create a watcher for pods, yielding events of type Event<Pod>
    let mut watcher_stream = watcher(pods, watcher::Config::default()).boxed();

    //Process each event from the stream
    while let Some(event) = watcher_stream.next().await {
        match event.ok() {
            Some(event) => match event {
                Event::Apply(pod) => {
                    let podinfo = get_pod_info(pod);
                    match podinfo.ok() {
                        Some(podinfo) => {
                            // tx.send(PodEvent::Add(podinfo)).await.unwrap()

                            if let Err(e) = tx.try_send(PodEvent::Add(podinfo)) {
                                eprintln!("Failed to send pod to handle pod: {:?}", e);
                                // You might want to handle or log this in some way, as the event was not sent
                            }
                        }
                        _ => {
                            continue;
                        }
                    }
                }
                Event::Delete(pod) => {
                    let podid = Arc::<str>::from(pod.uid().unwrap());
                    // tx.send(PodEvent::Delete(podid)).await.unwrap();

                    if let Err(e) = tx.try_send(PodEvent::Delete(podid)) {
                        eprintln!("Failed to send pod to handle pod: {:?}", e);
                        // You might want to handle or log this in some way, as the event was not sent
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    Ok(())
}

pub async fn watch_crd(tx: mpsc::Sender<KronosEvent>) -> Result<()> {
    info!("watch crd called");
    let client = Client::try_default().await?;
    let kronos: Api<KronosSecurityPolicy> = Api::all(client);

    // Create a watcher for Kronos cluster CRD
    let mut kronos_watch_stream = watcher(kronos, watcher::Config::default()).boxed();

    while let Some(event) = kronos_watch_stream.next().await {
        match event.ok() {
            Some(event) => match event {
                Event::Apply(crd) => {
                    info!("policy added ");
                    // tx.send(KronosEvent::Add(crd)).await.unwrap();

                    if let Err(e) = tx.try_send(KronosEvent::Add(crd)) {
                        eprintln!("Failed to send crd to handle crd: {:?}", e);
                        // You might want to handle or log this in some way, as the event was not sent
                    }
                }
                Event::Delete(crd) => {
                    info!("policy deleted ");
                    if let Err(e) = tx.try_send(KronosEvent::Delete(crd)) {
                        eprintln!("Failed to send crd to handle crd: {:?}", e);
                        // You might want to handle or log this in some way, as the event was not sent
                    }
                }
                Event::InitApply(crd) => {
                    info!("policy added ");
                    if let Err(e) = tx.try_send(KronosEvent::Add(crd)) {
                        eprintln!("Failed to send crd to handle crd: {:?}", e);
                        // You might want to handle or log this in some way, as the event was not sent
                    }
                }
                _ => {}
            },
            _ => {
                continue;
            }
        }
    }
    Ok(())
}

pub async fn get_pods_from_labels_namespace(
    labels: String,
    namespace: Arc<str>,
) -> impl Stream<Item = PodInfo> {
    let client = Client::try_default().await.unwrap();
    let lp = ListParams::default().labels(&labels);
    let pods: Api<Pod> = Api::namespaced(client.clone(), &namespace);

    // Stream over each Pod returned from the API and transform it into PodInfo
    stream::iter(pods.list(&lp).await.unwrap()).filter_map(|p| async {
        match get_pod_info(p).ok() {
            Some(pod_info) => Some(pod_info),
            None => None, // Filter out errors, or handle them as needed
        }
    })
}

fn get_pod_info(pod: Pod) -> anyhow::Result<PodInfo> {
    let mut container_vec: Vec<ContainerInfo> = Vec::new();
    let namespace = pod
        .namespace()
        .map(Arc::<str>::from)
        .ok_or_else(|| anyhow::anyhow!("Pod namespace is missing"))?;

    if let Some(pod_status) = pod.status.clone() {
        if let Some(container_statuses) = pod_status.container_statuses {
            for sts in container_statuses {
                let container_id =
                    Arc::<str>::from(sts.container_id.unwrap_or_else(|| "none".to_string()));
                let container_info = ContainerInfo {
                    container_id: container_id.clone(),
                    container_name: Arc::<str>::from(sts.name),
                    container_image: Arc::<str>::from(sts.image),
                    image_id: Arc::<str>::from(sts.image_id),
                };
                container_vec.push(container_info);
            }
        }
    }

    let mut pod_labels: HashSet<Arc<str>> = HashSet::new();
    for (key, value) in pod.labels() {
        let pod_label = format!("{}={}", key, value);
        pod_labels.insert(Arc::<str>::from(pod_label));
    }

    let pod_uid = pod
        .metadata
        .uid
        .clone()
        .map(Arc::<str>::from)
        .ok_or_else(|| anyhow::anyhow!("Pod UID is missing"))?;

    let pod_name = pod
        .metadata
        .name
        .clone()
        .map(Arc::<str>::from)
        .ok_or_else(|| anyhow::anyhow!("Pod name is missing"))?;

    let qos_class = pod
        .status
        .as_ref()
        .and_then(|status| status.qos_class.clone())
        .map(|qos| Arc::<str>::from(qos.to_lowercase()))
        .ok_or_else(|| anyhow::anyhow!("QoS class is missing"))?;

    let pod_info = PodInfo {
        poduid: pod_uid,
        podname: pod_name,
        qos_class,
        namespace,
        labels: pod_labels,
        container_map: container_vec,
    };

    Ok(pod_info)
}

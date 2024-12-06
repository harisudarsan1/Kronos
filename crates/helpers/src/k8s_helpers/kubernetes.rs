pub enum K8sCluster {
    K3s,
    Minikube,
    Microk8s,
    KubeAdm,
    Kind,
}
pub fn get_k8s_cluster_manager() -> K8sCluster {
    K8sCluster::Microk8s
}

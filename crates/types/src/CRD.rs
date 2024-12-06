use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use std::sync::Arc;

#[skip_serializing_none]
#[derive(CustomResource, JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[kube(
    group = "kronos.io",
    version = "v1alpha1",
    kind = "KronosSecurityPolicy",
    namespaced
)]
#[kube(status = "KronosSecurityPolicyStatus")]
#[serde(rename_all = "camelCase")]
pub struct KronosSecurityPolicySpec {
    pub severity: Option<u8>,        // Optional, defaults to 1 if not provided
    pub tags: Option<Vec<Arc<str>>>, // Optional list of tags
    pub message: Option<Arc<str>>,   // Optional message field
    pub only_allow: bool,            // Optional bool for onlyAllow behavior
    pub targets: Targets,            // The targets section (capabilities, file, network, etc.)
    pub selectors: Selectors,        // The selectors section for pod targeting
    pub action: Action,              // Action field (enum with external tagging)
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Targets {
    pub capabilities: Option<Vec<Arc<str>>>, // List of capabilities to allow/block
    pub file: Option<FileTarget>,            // File-specific target
    pub network: Option<NetworkTarget>,      // Network-specific target
    pub directory: Option<DirectoryTarget>,  // Directory-specific target
    pub binaries: Option<Vec<Arc<str>>>,     // List of binaries to allow/block
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileTarget {
    pub is_owner: bool,                // Whether the resource must be the owner
    pub values: Vec<Arc<str>>,         // List of file paths
    pub source: Option<Vec<Arc<str>>>, // Optional list of binary paths as sources
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkTarget {
    // pub protocol: Option<Arc<str>>, // Protocol like TCP, UDP, DNS, HTTP, etc.
    pub dns: Option<DNSTarget>,   // DNS-specific options
    pub http: Option<HTTPTarget>, // HTTP-specific options
    pub tcp: Option<TCPTarget>,   // TCP-specific options
    pub udp: Option<UDPTarget>,   // UDP-specific options
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DNSTarget {
    // pub direction: Direction,        // Enum for ingress, egress, or both
    pub maxreq: Option<u32>,         // Maximum requests allowed
    pub domain_names: Vec<Arc<str>>, // Allowed or blocked domain names
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPTarget {
    pub direction: Direction,             // Enum for ingress, egress, or both
    pub maxreq: Option<u32>,              // Maximum requests allowed
    pub methods: Option<Vec<HTTPMethod>>, // Enum for allowed HTTP methods (GET, PUT, DELETE, etc.)
}

#[serde_as]
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TCPTarget {
    pub direction: Direction, // Enum for ingress, egress, or both
    pub maxreq: Option<u32>,  // Maximum requests allowed
    pub ports: Vec<u16>,      // List of TCP ports to allow/block
}

#[serde_as]
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UDPTarget {
    pub direction: Direction, // Enum for ingress, egress, or both
    pub maxreq: Option<u32>,  // Maximum requests allowed
    pub ports: Vec<u16>,      // List of UDP ports to allow/block
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryTarget {
    pub values: Vec<Arc<str>>,         // List of directories to audit or block
    pub source: Option<Vec<Arc<str>>>, // Optional list of binary paths as sources
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Selectors {
    pub match_labels: Vec<Arc<str>>, // Key-value pair for label matching with lifetime
    pub namespace: Arc<str>,         // Namespace or "all" for all namespaces
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KronosSecurityPolicyStatus {
    pub is_ok: bool, // Placeholder status field
}

// --- ENUMS ---

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Block,
    Audit,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    //use -1 for ingress , 1 for egress and 0 for both
    Ingress,
    Egress,
    Both,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum HTTPMethod {
    GET,
    PUT,
    DELETE,
    POST,
}

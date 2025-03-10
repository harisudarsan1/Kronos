use crate::InstallArgs;
use anyhow::{Ok, Result};
// use helpers::system::kernel;
use kube::{
    api::{Api, ListParams, Patch, PatchParams, ResourceExt},
    runtime::{
        wait::{await_condition, conditions},
        watcher, WatchStreamExt,
    },
    Client, CustomResource, CustomResourceExt,
};

use k8s_openapi::{
    api::core::v1::Node, apiextensions_apiserver::pkg::apis::apiextensions::v1 as apiexts, serde,
};

use types::CRD::{KronosSecurityPolicy, KronosSecurityPolicySpec, KronosSecurityPolicyStatus};

use apiexts::CustomResourceDefinition;

const CRDNAME: &str = "kronossecuritypolicies.kronos.io";
pub async fn install() -> anyhow::Result<()> {
    // TODO
    // createNamespace()
    // installcrd()
    let client = Client::try_default().await.unwrap();

    let apply = PatchParams::apply("kronos_apply").force();

    let crdClient: Api<CustomResourceDefinition> = Api::all(client.clone());

    crdClient
        .patch(CRDNAME, &apply, &Patch::Apply(&KronosSecurityPolicy::crd()))
        .await
        .unwrap();
    // install kronos()
    // install kronosoperator()
    // Add RBAC policies
    // println!("recieved namespace {}", args.namespace);
    //
    // println!("recieved image {}", args.image);
    //
    // println!("recieved registry {}", args.registry);
    println!("installing CRD");
    Ok(())
}

use clap::{Args, Parser, Subcommand, ValueEnum};
use install::install;

mod checkenvironment;
mod checkhealth;
mod filter;
mod install;
mod selfupdate;
mod uninstall;

#[derive(Parser, Debug)]
#[command(name="Kronos-CLI",author,version,about,long_about = None)]
struct Cmd {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Installs kronos and kronos-operator in the specified environment
    Install(InstallArgs),

    /// Checks Health for kronos daemon and kronos Operator
    CheckHealth,

    /// Checks the Environment and analyses whether kronos can be installed or not.
    CheckEnvironment,

    /// Helps filtering Alerts and Logs from Kronos Daemon
    Filter(FilterArgs),

    /// Command for updating the kronos-cli to the latest version
    SelfUpdate,

    /// Uninstall Kronos from the Kubernetes Cluster
    Uninstall,
}

#[derive(Args, Debug, Clone)]
pub struct InstallArgs {
    /// Set the Namespace to install Kronos and its system
    #[arg(short, long = "namespace", default_value_t = String::from("kronos"))]
    namespace: String,

    /// Set the Image name and tag
    #[arg(short, long,default_value_t= String::from("kronos/kronos:stable"))]
    image: String,

    /// Set the image registry to download image
    #[arg(short, long,default_value_t = String::from("docker.io"))]
    registry: String,

    /// It Checks whether kronos system is installed properly
    #[arg(long)]
    verify: bool,
}

#[derive(Args, Debug, Clone)]
pub struct FilterArgs {
    /// Type of the Telemetry to filter
    #[arg(short, long, value_enum)]
    teletype: TelemetryTypes,

    /// filter by namespace
    #[arg(short, long)]
    namespace: Option<String>,

    /// Filter by label selectors
    #[arg(short, long)]
    label: Option<String>,

    /// Filter by Container Name
    #[arg(short, long)]
    container: Option<String>,

    /// Filter by Pod Name
    #[arg(short, long)]
    pod: Option<String>,

    /// Output the filtered values to a file
    #[arg(short, long, value_name = "FILE")]
    output_file: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum TelemetryTypes {
    /// Filter Traces
    Trace,

    /// Filter Logs
    Log,
}

#[tokio::main]
async fn main() {
    let cli = Cmd::parse();

    match &cli.command {
        Commands::Install(_args) => {
            install().await;
        }
        Commands::CheckHealth => {}
        Commands::CheckEnvironment => {
            checkenvironment::check_environment();
        }

        // Commands::Save(saveargs) => save(&String::from("hello")),
        _ => {
            println!("{:?}", cli);
        }
    }
}

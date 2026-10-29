use clap::Parser;

use rustdrop::cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Cli {
        command,
        verbose,
        quiet,
    } = Cli::parse();

    match command {
        Command::Send(args) => rustdrop::commands::send(args, verbose, quiet).await,
        Command::Receive(args) => rustdrop::commands::receive(args, verbose, quiet).await,
        Command::List(args) => rustdrop::commands::list(args, verbose, quiet).await,
        Command::Completions(args) => rustdrop::commands::completions(args),
        Command::Pair(args) => rustdrop::commands::pair(args, verbose, quiet),
    }
}

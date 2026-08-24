use anyhow::Result;
use clap::{Parser, Subcommand};

use vault::vault::{VaultCommand, run_vault_command};

#[derive(Debug, Parser)]
#[command(
    name = "vault",
    about = "Dotenv secrets vault: encrypt values in place, keep ciphertext in git",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Vault operations (encrypt/decrypt/check/keypair/hooks/migrate/...)
    #[command(flatten)]
    Vault(VaultCommand),
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Vault(command) => run_vault_command(command),
    }
}

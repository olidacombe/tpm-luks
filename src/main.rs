use eyre::Result;
use tpm_luks::cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::new();
    cli.run()?;
    Ok(())
}

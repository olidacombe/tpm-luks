use eyre::Result;
use tpm_luks::cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::new();
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    cli.run()?;
    Ok(())
}

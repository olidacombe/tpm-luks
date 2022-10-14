use eyre::Result;
use std::env;
use tpm_luks::cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::new();
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    env::set_var("TSS2_LOG", "all+NONE");
    cli.run()?;
    Ok(())
}

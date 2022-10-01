/// To build distributable binary (WIP):
/// ```
/// rustup target add x86_64-unknown-linux-musl
/// cargo build --release --target=x86_64-unknown-linux-musl
/// ```
/// Refs:
/// - https://stackoverflow.com/questions/40695010/how-to-compile-a-static-musl-binary-of-a-rust-project-with-native-dependencies
/// - https://gitlab.com/rust_musl_docker/image
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

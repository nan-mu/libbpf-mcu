mod diagnostic;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Compile verified eBPF into a portable RV32IM image")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Run a JIT check, raw compilation or ISA matrix.
    Diagnostic {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Compile {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Action::Diagnostic { args } => {
            let code =
                diagnostic::run(args.into_iter()).map_err(|error| anyhow::anyhow!("{error}"))?;
            if code != 0 {
                std::process::exit(i32::from(code));
            }
            Ok(())
        }
        Action::Compile { input, output_dir } => {
            let (layout, bytes) = mcu_jit::portable(&input)?;
            layout.write_pair(&output_dir, &bytes)
        }
    }
}

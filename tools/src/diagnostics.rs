use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};

use anyhow::{Result, ensure};
use clap::Subcommand;
use mcu_image::{sha256_hex, write_atomic};
use serde_json::{Value, json};

#[derive(Subcommand)]
pub enum Action {
    /// Estimate caller, native and interrupt stack use for an AOT ELF.
    StackBudget {
        #[arg(long)]
        elf: PathBuf,
        #[arg(long)]
        su: Option<PathBuf>,
        #[arg(long, default_value_t = 1024)]
        caller_used_c: u64,
        #[arg(long, default_value_t = 0)]
        irq_peak_i: u64,
        #[arg(long, default_value_t = 8192)]
        stack_limit_s: u64,
        #[arg(long, default_value_t = 512)]
        helper_margin: u64,
        #[arg(long, default_value = "llvm-objdump")]
        objdump: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        require_ok: bool,
    },
    /// Summarize statuses in results.json from the independent JIT oracle.
    OracleSummary { results: PathBuf },
    /// Print cases matching a program name and optional result status.
    OracleQuery {
        results: PathBuf,
        program: String,
        #[arg(long)]
        status: Option<String>,
    },
}

fn immediate(value: &str) -> Option<u64> {
    let value = value.strip_prefix('-')?;
    value.strip_prefix("0x").map_or_else(
        || value.parse().ok(),
        |hex| u64::from_str_radix(hex, 16).ok(),
    )
}

impl Action {
    pub fn run(self) -> Result<()> {
        match self {
            Self::StackBudget {
                elf,
                su,
                caller_used_c,
                irq_peak_i,
                stack_limit_s,
                helper_margin,
                objdump,
                out,
                require_ok,
            } => {
                let bytes = fs::read(&elf)?;
                let elf = elf.canonicalize()?;
                let mut usage = BTreeMap::<String, u64>::new();
                if let Some(su) = su {
                    for line in fs::read_to_string(su)?.lines() {
                        let mut columns = line.split('\t');
                        if let (Some(location), Some(size)) =
                            (columns.next(), columns.next().and_then(|c| c.parse().ok()))
                        {
                            let name = location.rsplit(':').next().unwrap_or_default().to_owned();
                            usage
                                .entry(name)
                                .and_modify(|old| *old = (*old).max(size))
                                .or_insert(size);
                        }
                    }
                }
                let frame = if let Some(frame) = usage
                    .get("xdp_prog1")
                    .or_else(|| usage.get("xdp_prog"))
                    .copied()
                    .filter(|frame| *frame != 0)
                {
                    Some(frame)
                } else {
                    let output = Command::new(objdump).arg("-d").arg(&elf).output()?;
                    String::from_utf8(output.stdout)?
                        .lines()
                        .filter_map(|line| {
                            let (_, args) = line.split_once("addi")?;
                            let args = args.split(',').map(str::trim).collect::<Vec<_>>();
                            match args.as_slice() {
                                ["sp", "sp", amount] => immediate(amount),
                                _ => None,
                            }
                        })
                        .max()
                        .filter(|_| output.status.success())
                };
                let (ok, receipt) = if let Some(frame) = frame {
                    let helper = usage
                        .iter()
                        .filter(|(name, _)| name.contains("lookup") || name.contains("helper"))
                        .map(|(_, frame)| *frame)
                        .max()
                        .unwrap_or(helper_margin);
                    let aot = u128::from(frame) + u128::from(helper);
                    let total = u128::from(caller_used_c) + aot + u128::from(irq_peak_i);
                    let ok = total <= u128::from(stack_limit_s);
                    let errors = if ok {
                        vec![]
                    } else {
                        vec![format!("C+A+I={total} > S={stack_limit_s}")]
                    };
                    (
                        ok,
                        json!({"schema":"bs.safety.stack_budget.v1", "ok":ok, "errors":errors, "elf":elf, "elf_sha256":sha256_hex(&bytes),
                        "C":caller_used_c, "A":u64::try_from(aot)?, "A_aot":frame, "A_helper":helper, "I":irq_peak_i,
                        "S":stack_limit_s, "model":"shared_caller_stack"}),
                    )
                } else {
                    (
                        false,
                        json!({"schema":"bs.safety.stack_budget.v1", "ok":false, "elf":elf, "elf_sha256":sha256_hex(&bytes),
                        "errors":["unable to derive AOT stack peak A from .su or objdump"]}),
                    )
                };
                let out = out.unwrap_or_else(|| elf.with_file_name("stack-budget.json"));
                write_atomic(&out, &serde_json::to_vec_pretty(&receipt)?)?;
                println!("wrote {} ok={ok}", out.display());
                ensure!(ok || !require_ok, "stack budget check failed");
                Ok(())
            }
            Self::OracleSummary { results } => {
                let doc: Value = serde_json::from_slice(&fs::read(results)?)?;
                let mut counts = BTreeMap::new();
                for row in doc["cases"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("missing cases"))?
                {
                    let status = row["status"].as_str().unwrap_or("unknown");
                    let suite = row["suite"].as_str().unwrap_or("-");
                    *counts.entry((suite, status)).or_insert(0) += 1;
                }
                for ((suite, status), count) in counts {
                    println!("{suite}\t{status}\t{count}");
                }
                Ok(())
            }
            Self::OracleQuery {
                results,
                program,
                status,
            } => {
                let doc: Value = serde_json::from_slice(&fs::read(results)?)?;
                let mut matches = false;
                for row in doc["cases"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("missing cases"))?
                {
                    if row["name"]
                        .as_str()
                        .is_some_and(|name| name.contains(&program))
                        && status
                            .as_ref()
                            .is_none_or(|status| row["status"] == *status)
                    {
                        println!("{}", serde_json::to_string_pretty(row)?);
                        matches = true;
                    }
                }
                ensure!(matches, "no matching oracle cases");
                Ok(())
            }
        }
    }
}

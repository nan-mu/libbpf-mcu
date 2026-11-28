use std::{
    io::Read,
    path::Path,
    process::{Command, Output, Stdio},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use wait_timeout::ChildExt;

const TIMEOUT: Duration = Duration::from_secs(300);

fn run(checker: &Path, args: &[&std::ffi::OsStr], timeout: Duration) -> Result<Output> {
    let mut child = Command::new(checker)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("execute {}", checker.display()))?;
    let mut stdout = child.stdout.take().context("capture PREVAIL stdout")?;
    let mut stderr = child.stderr.take().context("capture PREVAIL stderr")?;
    thread::scope(|scope| {
        let out = scope.spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let err = scope.spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });
        let Some(status) = child.wait_timeout(timeout)? else {
            child.kill()?;
            child.wait()?;
            bail!("PREVAIL timed out after {} seconds", timeout.as_secs());
        };
        Ok(Output {
            status,
            stdout: out
                .join()
                .map_err(|_| anyhow::anyhow!("PREVAIL stdout reader stopped"))??,
            stderr: err
                .join()
                .map_err(|_| anyhow::anyhow!("PREVAIL stderr reader stopped"))??,
        })
    })
}

fn entry(listing: &str) -> Result<(&str, &str)> {
    let mut entries = listing.lines().filter_map(|line| {
        let mut columns = line.trim().trim_start_matches('#').split_whitespace();
        let section = columns.next()?.strip_prefix("section=")?;
        let function = columns.next()?.strip_prefix("function=")?;
        (matches!(section, "xdp" | "xdp1") && !function.is_empty() && columns.next().is_none())
            .then_some((section, function))
    });
    let result = entries
        .next()
        .with_context(|| format!("PREVAIL expected one XDP entry: {listing}"))?;
    ensure!(
        entries.next().is_none(),
        "PREVAIL expected one XDP entry: {listing}"
    );
    Ok(result)
}

pub fn verify(checker: &Path, object: &Path) -> Result<()> {
    let listing = run(checker, &["-l".as_ref(), object.as_os_str()], TIMEOUT)?;
    ensure!(
        listing.status.success(),
        "PREVAIL failed to list programs: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let listing = String::from_utf8(listing.stdout)?;
    let (section, function) = entry(&listing)?;
    let label = if section == function {
        section.to_owned()
    } else {
        format!("{section}/{function}")
    };
    let checked = run(
        checker,
        &[
            "--stack-size".as_ref(),
            "512".as_ref(),
            "--section".as_ref(),
            section.as_ref(),
            "--function".as_ref(),
            function.as_ref(),
            object.as_os_str(),
        ],
        TIMEOUT,
    )?;
    let output = String::from_utf8(checked.stdout)?;
    ensure!(
        checked.status.success(),
        "PREVAIL exited {} for {label}: {}{}",
        checked.status,
        output,
        String::from_utf8_lossy(&checked.stderr)
    );
    let expected = format!("PASS: {label}");
    ensure!(
        output.lines().any(|line| {
            line == expected
                || line
                    .strip_prefix(&expected)
                    .and_then(|suffix| suffix.strip_prefix(" (terminates within "))
                    .and_then(|suffix| suffix.strip_suffix(" loop iterations)"))
                    .is_some_and(|count| {
                        !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit())
                    })
        }),
        "PREVAIL did not report PASS for {label}: {output}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_a_verifier_that_exceeds_its_deadline() {
        let result = run(
            Path::new("/bin/sleep"),
            &["2".as_ref()],
            Duration::from_millis(30),
        );
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[test]
    fn selects_the_only_xdp_entry_and_rejects_ambiguous_listing() {
        assert_eq!(
            entry("# section=xdp1 function=my_fn\n# section=tc function=other").unwrap(),
            ("xdp1", "my_fn")
        );
        assert!(entry("# section=xdp function=a\n# section=xdp1 function=b").is_err());
        assert!(entry("# section=tc function=other").is_err());
    }
}

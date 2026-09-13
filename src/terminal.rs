//! Stream handling shared by query results and local command reports.
use std::io::{self, IsTerminal, Write};

/// A consumer closing its pipe is normal. Do not interrupt an in-progress
/// mutation or panic because its result no longer has a reader.
pub(crate) fn write_stdout(text: &str) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    let result = stdout.write_all(text.as_bytes()).and_then(|_| {
        if text.ends_with('\n') {
            Ok(())
        } else {
            stdout.write_all(b"\n")
        }
    });
    match result {
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => Ok(result?),
    }
}

pub(crate) fn read_stdin(description: &str) -> anyhow::Result<String> {
    use io::Read;
    let mut stdin = io::stdin().lock();
    if stdin.is_terminal() {
        let eof = if cfg!(windows) {
            "Ctrl-Z then Enter"
        } else {
            "Ctrl-D"
        };
        // This instruction is needed even with --quiet to explain the wait.
        writeln!(
            io::stderr().lock(),
            "Enter {description}; finish with EOF ({eof})."
        )?;
    }
    let mut text = String::new();
    stdin.read_to_string(&mut text)?;
    Ok(text)
}

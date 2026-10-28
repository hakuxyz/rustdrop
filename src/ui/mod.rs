//! Terminal presentation: progress bars, spinners and prompts.
//!
//! All rendering goes to **stderr** so stdout stays clean for machine
//! consumable output (`--json`, pipes).

use std::io::IsTerminal;
use std::sync::Mutex;
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::transfer::{ProgressSink, TransferReport};

const SPINNER_CHARS: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ";
const BAR_CHARS: &str = "█░";
const TICK: Duration = Duration::from_millis(80);

/// [`ProgressSink`] implementation used by the CLI.
pub struct CliProgress {
    quiet: bool,
    verbose: bool,
    tty: bool,
    multi: MultiProgress,
    spinner: Mutex<Option<ProgressBar>>,
    overall: Mutex<Option<ProgressBar>>,
    file: Mutex<Option<ProgressBar>>,
}

impl CliProgress {
    pub fn new(quiet: bool, verbose: bool) -> Self {
        Self {
            quiet,
            verbose,
            tty: std::io::stderr().is_terminal(),
            multi: MultiProgress::new(),
            spinner: Mutex::new(None),
            overall: Mutex::new(None),
            file: Mutex::new(None),
        }
    }

    /// Print a standalone line that plays nicely with active bars.
    pub fn line(&self, msg: &str) {
        if self.quiet {
            return;
        }
        if self.tty {
            let _ = self.multi.println(msg);
        } else {
            eprintln!("{msg}");
        }
    }

    /// Same as [`Self::line`] but only in `--verbose` mode.
    pub fn debug_line(&self, msg: &str) {
        if self.verbose {
            self.line(&dim(msg));
        }
    }

    /// Always printed (even with `--quiet`): security-relevant information.
    pub fn security_line(&self, msg: &str) {
        if self.tty {
            let _ = self.multi.println(format!("\x1b[1m\x1b[33m{msg}\x1b[0m"));
        } else {
            eprintln!("{msg}");
        }
    }

    fn ensure_spinner(&self) -> Option<ProgressBar> {
        if !self.tty || self.quiet {
            return None;
        }
        let mut guard = self.spinner.lock().expect("spinner lock poisoned");
        if let Some(bar) = guard.as_ref() {
            return Some(bar.clone());
        }
        let style = ProgressStyle::with_template("{spinner:.cyan} {wide_msg}")
            .expect("valid spinner template")
            .tick_chars(SPINNER_CHARS);
        let bar = self.multi.add(ProgressBar::new_spinner());
        bar.set_style(style);
        bar.enable_steady_tick(TICK);
        *guard = Some(bar.clone());
        Some(bar)
    }

    fn clear_spinner(&self) {
        if let Ok(mut guard) = self.spinner.lock()
            && let Some(bar) = guard.take()
        {
            bar.finish_and_clear();
        }
    }

    fn ensure_bars(&self) {
        if !self.tty || self.quiet {
            return;
        }
        let mut overall = self.overall.lock().expect("overall lock poisoned");
        if overall.is_none() {
            let style = ProgressStyle::with_template(
                "{spinner:.green} {elapsed_precise} {bar:32.cyan/blue} \
                 {bytes}/{total_bytes} {bytes_per_sec} {eta}",
            )
            .expect("valid overall template")
            .progress_chars(BAR_CHARS);
            let bar = self.multi.add(ProgressBar::new(0));
            bar.set_style(style);
            *overall = Some(bar);
        }
        let mut file = self.file.lock().expect("file lock poisoned");
        if file.is_none() {
            let style = ProgressStyle::with_template(
                "{bar:32.yellow/dim} {bytes}/{total_bytes} {wide_msg}",
            )
            .expect("valid file template")
            .progress_chars(BAR_CHARS);
            let bar = self.multi.add(ProgressBar::new(0));
            bar.set_style(style);
            *file = Some(bar);
        }
    }
}

impl ProgressSink for CliProgress {
    fn status(&self, msg: &str) {
        if self.quiet {
            return;
        }
        if let Some(spinner) = self.ensure_spinner() {
            spinner.set_message(msg.to_string());
        } else {
            eprintln!("{msg}");
        }
    }

    fn discovered(&self, name: &str, addr: &str) {
        self.debug_line(&format!("discovered {name} at {addr}"));
    }

    fn connected(&self, peer: &str) {
        self.line(&format!("  connected to {peer}"));
    }

    fn trust_code(&self, code: &str) {
        self.security_line(&format!("  trust code: {code}"));
    }

    fn begin(&self, _files: usize, _bytes: u64) {
        self.clear_spinner();
        self.ensure_bars();
    }

    fn file(&self, path: &str, size: u64) {
        let guard = self.file.lock().expect("file lock poisoned");
        if let Some(bar) = guard.as_ref() {
            bar.reset();
            bar.set_length(size);
            bar.set_message(shorten(path, 48));
        }
        drop(guard);
        self.debug_line(&format!("sending {path}"));
    }

    fn advance(&self, bytes: u64) {
        let guard = self.overall.lock().expect("overall lock poisoned");
        if let Some(bar) = guard.as_ref() {
            bar.inc(bytes);
        }
        drop(guard);
        let guard = self.file.lock().expect("file lock poisoned");
        if let Some(bar) = guard.as_ref() {
            bar.inc(bytes);
        }
    }

    fn file_hash(&self, path: &str, hash: &str) {
        self.debug_line(&format!("blake3 {hash}  {path}"));
    }

    fn verify(&self, path: &str, ok: bool) {
        if ok {
            self.debug_line(&format!("verified {path}"));
        } else {
            self.line(&format!("  \x1b[31mchecksum mismatch: {path}\x1b[0m"));
        }
    }

    fn finish(&self, report: &TransferReport) {
        if let Ok(guard) = self.overall.lock()
            && let Some(bar) = guard.as_ref()
        {
            bar.finish_with_message("done");
        }
        if let Ok(guard) = self.file.lock()
            && let Some(bar) = guard.as_ref()
        {
            bar.finish_and_clear();
        }
        self.clear_spinner();
        if !self.quiet {
            self.line(&format!("  \x1b[32m✓\x1b[0m {report}"));
        }
    }
}

impl Drop for CliProgress {
    fn drop(&mut self) {
        self.clear_spinner();
    }
}

/// Interactive "do you accept this transfer?" prompt.
///
/// Returns `true` when the user confirms. When stdin is not a terminal the
/// prompt is refused: automation must be explicit (`--yes`).
pub fn confirm_transfer(peer: &str, preview: &crate::transfer::receiver::TransferPreview) -> bool {
    use dialoguer::Confirm;
    use dialoguer::theme::ColorfulTheme;

    if !std::io::stdin().is_terminal() {
        eprintln!("refusing to prompt: stdin is not a terminal (re-run with --yes)");
        return false;
    }

    let paths = if preview.first_paths.is_empty() {
        String::new()
    } else {
        let shown = preview.first_paths.join(", ");
        let more = preview.files.saturating_sub(preview.first_paths.len());
        if more > 0 {
            format!("\n            {shown} \x1b[2m(+{more} more)\x1b[0m")
        } else {
            format!("\n            {shown}")
        }
    };

    let prompt = format!(
        "accept {} file(s) ({}) from {peer}?{paths}",
        preview.files,
        crate::transfer::human_bytes(preview.bytes)
    );

    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(false)
        .interact()
        .unwrap_or(false)
}

/// Pick one receiver from a discovered list (interactive only).
pub fn select_receiver(
    receivers: &[crate::discovery::DiscoveredReceiver],
) -> Option<crate::discovery::DiscoveredReceiver> {
    use dialoguer::Select;
    use dialoguer::theme::ColorfulTheme;

    if receivers.is_empty() {
        return None;
    }
    if receivers.len() == 1 {
        return Some(receivers[0].clone());
    }
    if !std::io::stdin().is_terminal() {
        eprintln!("multiple receivers found; pass --name or --to disambiguate");
        return None;
    }

    let items: Vec<String> = receivers
        .iter()
        .map(|r| {
            let addr = r
                .addresses
                .first()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "?".into());
            format!("{} ({addr})", r.device_name)
        })
        .collect();

    Select::with_theme(&ColorfulTheme::default())
        .with_prompt("choose a receiver")
        .items(&items)
        .default(0)
        .interact()
        .ok()
        .and_then(|i| receivers.get(i).cloned())
}

fn dim(s: &str) -> String {
    format!("\x1b[2m{s}\x1b[0m")
}

/// Middle-elide long paths so bars stay readable.
fn shorten(path: &str, max: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= max {
        return path.to_string();
    }
    if max < 4 {
        let cut: String = chars[..max].iter().collect();
        return cut;
    }
    let head_len = (max - 3) / 2;
    let tail_len = max - 3 - head_len;
    let head: String = chars[..head_len].iter().collect();
    let tail: String = chars[chars.len() - tail_len..].iter().collect();
    format!("{head}...{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortening_is_stable() {
        assert_eq!(shorten("short.txt", 20), "short.txt");
        let long = "some/very/deep/nested/tree/of/files/filename.txt";
        let out = shorten(long, 20);
        assert_eq!(out.len(), 20);
        assert!(out.contains("..."));
    }

    #[test]
    fn quiet_progress_is_safe_to_construct() {
        let p = CliProgress::new(true, false);
        p.status("ignored");
        p.trust_code("ABCD-EFGH");
        p.finish(&TransferReport {
            peer: "x".into(),
            files: 0,
            bytes: 0,
            elapsed: Duration::from_secs(0),
        });
    }
}

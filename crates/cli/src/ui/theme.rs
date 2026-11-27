//! Terminal capability detection and the shared color/typography system.
//! Every UI module draws its palette from here so color meaning is
//! consistent: green = active/completed scanning, magenta = final
//! aggregation, red/orange/yellow/blue = severity tiers, cyan =
//! informational, gray = metadata and pending work.

use colored::Colorize;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicU8, Ordering};

/// Process-wide test override: 0 = environment decides, 1 = always color,
/// 2 = never color. It mirrors `colored`'s manual override so the call-time
/// gate below and the formatting library always agree.
static OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// Force or suppress color regardless of the environment (tests only).
#[cfg(test)]
pub(crate) fn set_color_override(colorize: bool) {
    OVERRIDE.store(if colorize { 1 } else { 2 }, Ordering::Relaxed);
    colored::control::set_override(colorize);
}

/// Return to environment-driven color decisions (tests only).
#[cfg(test)]
pub(crate) fn unset_color_override() {
    OVERRIDE.store(0, Ordering::Relaxed);
    colored::control::unset_override();
}

/// Whether ANSI color may be emitted right now.
///
/// `colored` snapshots `NO_COLOR` and the TTY check in a process-global
/// `lazy_static` on first use, so a value set later — as tests do — would be
/// silently ignored. Re-check both at call time; `NO_COLOR` always wins, while
/// an explicit manual test override can bypass only the TTY check. https://no-color.org
fn colors_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    match OVERRIDE.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    std::io::stdout().is_terminal()
}

/// Apply `paint` only when color is allowed; otherwise return `text` verbatim.
fn paint(text: &str, paint: impl FnOnce(&str) -> String) -> String {
    if colors_enabled() {
        paint(text)
    } else {
        text.to_owned()
    }
}

/// Severity tiers are defined once in `riftlock-core` so the terminal, report
/// totals and SARIF cannot drift apart. Re-exported to keep this module's
/// existing public path intact.
pub use riftlock_core::Severity;

/// ASCII-only rendering: `RIFTLOCK_ASCII=1`, `TERM=dumb`, or a locale that
/// is not UTF-8 (`LC_ALL` / `LC_CTYPE` / `LANG`, in that precedence).
/// Emblem and separators degrade to plain ASCII.
#[must_use]
pub fn unicode_ok() -> bool {
    if std::env::var_os("RIFTLOCK_ASCII").is_some_and(|v| v == "1") {
        return false;
    }
    if std::env::var_os("TERM").is_some_and(|t| t == "dumb") {
        return false;
    }
    for key in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(locale) = std::env::var(key) {
            return locale.to_uppercase().ends_with("UTF-8");
        }
    }
    // No locale set: assume UTF-8 (most modern terminals).
    true
}

/// Terminal width, best effort: `COLUMNS` when exported, else 80.
#[must_use]
pub fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse().ok())
        .filter(|w: &usize| (10..500).contains(w))
        .unwrap_or(80)
}

/// Horizontal editorial separator spanning the usable width.
#[must_use]
pub fn separator() -> String {
    let w = term_width().min(80);
    let line: String = if unicode_ok() {
        "─".repeat(w)
    } else {
        "-".repeat(w)
    };
    paint(&line, |text| text.dimmed().to_string())
}

/// Brand / primary typography: silver-white, bold.
pub fn brand(text: &str) -> String {
    paint(text, |text| text.white().bold().to_string())
}

/// Secondary metadata: muted gray.
pub fn muted(text: &str) -> String {
    paint(text, |text| text.dimmed().to_string())
}

/// Active and completed scanning: terminal neon green.
pub fn scanning(text: &str) -> String {
    paint(text, |text| text.truecolor(57, 255, 20).to_string())
}

/// Final aggregation signature: terminal neon green, reserved for that phase alone.
pub fn aggregation(text: &str) -> String {
    paint(text, |text| text.truecolor(57, 255, 20).to_string())
}

/// Positive finding markers: bright pink.
pub fn blush_pink(text: &str) -> String {
    paint(text, |text| text.truecolor(255, 105, 180).to_string())
}

/// Live probe activity: neon orange.
pub fn neon_orange(text: &str) -> String {
    paint(text, |text| text.truecolor(255, 165, 0).to_string())
}

/// Informational events: neutral cyan.
pub fn info(text: &str) -> String {
    paint(text, |text| text.cyan().to_string())
}

/// Credential discoveries: cyan, distinct from severity colors. The color
/// carries no severity meaning — the finding keeps its own tier and evidence.
pub fn credential(text: &str) -> String {
    paint(text, |text| text.cyan().to_string())
}

/// Warnings and failures: red.
pub fn failure(text: &str) -> String {
    paint(text, |text| text.red().to_string())
}

/// Operator-facing warnings that are not failures.
pub fn warning(text: &str) -> String {
    paint(text, |text| text.yellow().to_string())
}

/// The uppercase severity tag, colored per the palette:
/// Critical red, High orange, Medium yellow, Low blue, Info cyan.
#[must_use]
pub fn severity_tag(sev: Severity) -> String {
    let tag = match sev {
        Severity::Critical => "[CRITICAL]",
        Severity::High => "[HIGH]",
        Severity::Medium => "[MEDIUM]",
        Severity::Low => "[LOW]",
        Severity::Info => "[INFO]",
    };
    paint(tag, |tag| match sev {
        Severity::Critical => tag.red().bold().to_string(),
        Severity::High => tag.truecolor(255, 140, 0).bold().to_string(),
        Severity::Medium => tag.yellow().to_string(),
        Severity::Low => tag.blue().to_string(),
        Severity::Info => tag.cyan().to_string(),
    })
}

/// Serialize tests that mutate process-global state (env vars, the
/// `colored` override); parallel tests would otherwise race.
#[cfg(test)]
pub(crate) fn global_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn separators_fit_the_width_floor() {
        let _global = global_lock();
        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_color_override(false);
        std::env::set_var("COLUMNS", "80");
        let width = separator().chars().count();
        std::env::remove_var("COLUMNS");
        unset_color_override();
        assert_eq!(width, 80);
    }

    #[test]
    fn ascii_mode_collapses_the_separator() {
        let _global = global_lock();
        let _env = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_color_override(false);
        std::env::set_var("RIFTLOCK_ASCII", "1");
        let line = separator();
        std::env::remove_var("RIFTLOCK_ASCII");
        unset_color_override();
        assert!(line.starts_with("---"));
    }
}

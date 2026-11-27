//! Process-wide one-line stderr logger. Scanners run concurrently, so each
//! line takes a shared lock: interleaved fragments would be unreadable.
//! Printable UTF-8 is preserved; control characters cannot inject extra lines.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

static LINE: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static SPINNER_ON: AtomicBool = AtomicBool::new(false);

/// A spinner line on the bottom of the terminal, erased when dropped.
pub struct Spinner {
    handle: Option<std::thread::JoinHandle<()>>,
}

/// Animate an ASCII spinner below the log until the returned guard drops.
/// A terminal is required; redirected stderr gets no escape sequences.
#[must_use]
pub fn start_spinner(label: &str) -> Spinner {
    if !ansi_enabled(std::io::stderr().is_terminal()) || SPINNER_ON.swap(true, Ordering::Relaxed) {
        return Spinner { handle: None };
    }
    let label = label.to_string();
    let handle = std::thread::spawn(move || {
        const FRAMES: [&str; 4] = ["|", "/", "-", "\\"];
        const GLITCH: &[u8] = b"#@$%&*+=<>/\\|!?";
        let mut frame = 0u64;
        while SPINNER_ON.load(Ordering::Relaxed) {
            if !ansi_enabled(std::io::stderr().is_terminal()) {
                break;
            }
            // 5-15 glitch characters after the label, re-rolled each tick by
            // a small xorshift: no rand dependency, still looks unstable.
            let mut seed = frame.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1);
            let len = 5 + (seed % 11) as usize;
            let mut glitch = String::with_capacity(len);
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                glitch.push(GLITCH[(seed % GLITCH.len() as u64) as usize] as char);
            }
            {
                let _guard = LINE
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut err = std::io::stderr();
                if ansi_enabled(std::io::stderr().is_terminal()) {
                    let _ = write!(
                        err,
                        "\r\x1b[2K{} {label} {glitch}",
                        FRAMES[(frame as usize) % FRAMES.len()]
                    );
                } else {
                    let _ = write!(
                        err,
                        "{} {label} {glitch}",
                        FRAMES[(frame as usize) % FRAMES.len()]
                    );
                }
                let _ = err.flush();
            }
            frame = frame.wrapping_add(1);
            std::thread::sleep(Duration::from_millis(90));
        }
    });
    Spinner {
        handle: Some(handle),
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        SPINNER_ON.store(false, Ordering::Relaxed);
        let _ = handle.join();
        let _guard = LINE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if ansi_enabled(std::io::stderr().is_terminal()) {
            let mut err = std::io::stderr();
            // Finish the spinner's own row so output after the scan starts
            // below it instead of reusing the animation's terminal position.
            let _ = writeln!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

fn sanitize(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut chars = msg.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            if c == '\n' || c == '\t' || !c.is_control() {
                out.push(c);
            }
            continue;
        }
        match chars.next() {
            Some('[') => {
                let mut params = String::new();
                for d in chars.by_ref() {
                    if ('@'..='~').contains(&d) {
                        if d == 'm'
                            && params
                                .chars()
                                .all(|p| p.is_ascii_digit() || p == ';' || p == ':')
                        {
                            out.push_str("\x1b[");
                            out.push_str(&params);
                            out.push('m');
                        }
                        break;
                    }
                    params.push(d);
                }
            }
            Some(']') => {
                let mut previous = '\0';
                for d in chars.by_ref() {
                    if d == '\x07' || (previous == '\x1b' && d == '\\') {
                        break;
                    }
                    previous = d;
                }
            }
            _ => {}
        }
    }
    out
}

fn ansi_enabled(terminal: bool) -> bool {
    terminal && !std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

fn color_discovery_tag(line: &str, terminal: bool) -> String {
    const TAG: &str = "[Discovery]";
    if ansi_enabled(terminal) && line.starts_with(TAG) {
        format!("\x1b[36m{TAG}\x1b[0m{}", &line[TAG.len()..])
    } else {
        line.to_owned()
    }
}

/// Print `msg` as one line on stderr, serialized against other callers.
/// A poisoned lock still prints: a panicked scanner must not silence the
/// rest of the run.
pub fn line(msg: &str) {
    let _guard = LINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let line = color_discovery_tag(&sanitize(msg), std::io::stderr().is_terminal());
    if SPINNER_ON.load(Ordering::Relaxed) && ansi_enabled(std::io::stderr().is_terminal()) {
        // Erase the spinner line before the log line; the spinner thread
        // repaints it on its next tick.
        eprint!("\r\x1b[2K");
    }
    eprintln!("{line}");
}

/// One serialized stderr line, `format!` arguments.
#[macro_export]
macro_rules! logln {
    ($($arg:tt)*) => {
        $crate::logger::line(&format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn preserves_unicode_and_sgr_but_strips_terminal_injection() {
        assert_eq!(
            super::sanitize(
                "Smuggling — \x1b[38;2;255;165;0mcolor\x1b[0m\nnext\t!\r\x1b[2J\x1b]0;hacked\x07"
            ),
            "Smuggling — \x1b[38;2;255;165;0mcolor\x1b[0m\nnext\t!"
        );
    }

    #[test]
    fn discovery_tag_is_cyan_only_for_terminal_logs() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let line = "[Discovery] Crawled https://example.test/ -> 2 links";
        std::env::remove_var("NO_COLOR");
        assert_eq!(
            super::color_discovery_tag(line, true),
            "\x1b[36m[Discovery]\x1b[0m Crawled https://example.test/ -> 2 links"
        );
        assert_eq!(super::color_discovery_tag(line, false), line);
        std::env::set_var("NO_COLOR", "1");
        assert_eq!(super::color_discovery_tag(line, true), line);
        std::env::remove_var("NO_COLOR");
        assert_eq!(
            super::color_discovery_tag("[+] Engine finished", true),
            "[+] Engine finished"
        );
    }

    #[test]
    fn lock_survives_poisoning() {
        let _ = std::panic::catch_unwind(|| {
            let _g = super::LINE.lock().expect("lock");
            panic!("poison the logger");
        });
        // Poisoned lock must still allow a line through.
        super::line("logger ok");
    }
}

//! CLI branding and authorized-use notices.
//! Pure presentation: these helpers never clear the screen or touch scanner
//! state.

use super::theme::warning;
use std::io::{self, IsTerminal, Write};

fn color_enabled() -> bool {
    io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn paint(text: &str, color: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{color}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

fn print_stderr(text: &str) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(text.as_bytes());
    let _ = stderr.flush();
}

fn push_boxed_line(
    out: &mut String,
    content: &str,
    visible_len: usize,
    width: usize,
    border: &str,
) {
    out.push_str(border);
    out.push_str("  ");
    out.push_str(content);
    out.push_str(&" ".repeat(width - 2 - visible_len));
    out.push_str(border);
    out.push('\n');
}

/// Print the boxed Riftlock logo. Color is enabled only for a terminal without
/// `NO_COLOR`; redirected output remains plain text.
pub fn print_logo() {
    let color = color_enabled();
    let dim_gray = |s: &str| paint(s, "2;37", color);
    let bright_red = |s: &str| paint(s, "1;38;5;196", color);

    let mut out = String::new();
    out.push_str(&format!(
        "{}\n",
        dim_gray("╔════════════════════════════════════════════════════════════════╗")
    ));
    out.push_str(&format!(
        "{}\n",
        dim_gray("║                                                                ║")
    ));
    for (rift, lock) in [
        (
            "  ██████╗ ██╗███████╗████████╗██╗",
            "      ██████╗  ██████╗██╗  ██╗ ",
        ),
        (
            "  ██╔══██╗██║██╔════╝╚══██╔══╝██║",
            "     ██╔═══██╗██╔════╝██║ ██╔╝ ",
        ),
        (
            "  ██████╔╝██║█████╗     ██║   ██║",
            "     ██║   ██║██║     █████╔╝  ",
        ),
        (
            "  ██╔══██╗██║██╔══╝     ██║   ██║",
            "     ██║   ██║██║     ██╔═██╗  ",
        ),
        (
            "  ██║  ██║██║██║        ██║   ███████╗",
            "╚██████╔╝╚██████╗██║  ██╗ ",
        ),
        (
            "  ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚══════╝",
            " ╚═════╝  ╚═════╝╚═╝  ╚═╝ ",
        ),
    ] {
        out.push_str(&dim_gray("║"));
        out.push_str(&bright_red(rift));
        out.push_str(&bright_red(lock));
        out.push_str(&dim_gray("║\n"));
    }
    out.push_str(&format!(
        "{}\n",
        dim_gray("║                                                                ║")
    ));
    out.push_str(&format!(
        "{}{}{}\n",
        dim_gray("║                "),
        dim_gray("· D A S T   S C A N N E R ·"),
        dim_gray("                     ║")
    ));
    out.push_str(&format!(
        "{}\n",
        dim_gray("╚════════════════════════════════════════════════════════════════╝")
    ));
    print_stderr(&out);
}

/// Print the boxed authorization reminder, highlighting the warning and the
/// active-depth flags when color is available.
pub fn print_auth_banner() {
    const INNER_WIDTH: usize = 72;
    let color = color_enabled();
    let red = |s: &str| paint(s, "1;38;5;196", color);
    let yellow = |s: &str| paint(s, "1;33", color);
    let dim_gray = |s: &str| paint(s, "2;37", color);
    let mut out = String::new();
    out.push_str(&dim_gray(
        "╔════════════════════════════════════════════════════════════════════════╗\n",
    ));
    push_boxed_line(
        &mut out,
        &red("[!] AUTHORIZED USE ONLY"),
        "[!] AUTHORIZED USE ONLY".len(),
        INNER_WIDTH,
        &dim_gray("║"),
    );
    push_boxed_line(&mut out, "", 0, INNER_WIDTH, &dim_gray("║"));

    let depth_suffix = "   sends active probes (reflection, SQLi, redirects)      ";
    push_boxed_line(
        &mut out,
        &format!("{}{}", yellow("--depth read"), depth_suffix),
        "--depth read".len() + depth_suffix.len(),
        INNER_WIDTH,
        &dim_gray("║"),
    );

    let godmode_prefix = "      sends ";
    let godmode_suffix = " payloads (injection, bypass, fuzz)   ";
    let godmode_content = format!(
        "{}{}{}{}",
        yellow("--godmode"),
        godmode_prefix,
        red("DESTRUCTIVE"),
        godmode_suffix
    );
    push_boxed_line(
        &mut out,
        &godmode_content,
        "--godmode".len() + godmode_prefix.len() + "DESTRUCTIVE".len() + godmode_suffix.len(),
        INNER_WIDTH,
        &dim_gray("║"),
    );
    push_boxed_line(&mut out, "", 0, INNER_WIDTH, &dim_gray("║"));

    for content in [
        "Both flags can damage production systems, trigger WAF bans, or        ",
        "corrupt data. ONLY run them against systems you own or have           ",
        "WRITTEN PERMISSION to test. Unsolicited scanning is illegal in        ",
        "most jurisdictions (US CFAA, UK CMA, EU Directive 2013/40/EU).       ",
        "",
        "By continuing you confirm you have authorization for this target.    ",
    ] {
        push_boxed_line(
            &mut out,
            content.trim_end(),
            content.trim_end().len(),
            INNER_WIDTH,
            &dim_gray("║"),
        );
    }
    out.push_str(&dim_gray(
        "╚════════════════════════════════════════════════════════════════════════╝\n",
    ));
    print_stderr(&out);
}

/// The raw authorized-use warning, one line per warning theme entry.
fn warning_lines() -> Vec<&'static str> {
    vec![
        "[!] WARNING: RIFTLOCK IS FOR AUTHORIZED SECURITY TESTING ONLY.",
        "[!] UNAUTHORIZED USE IS STRICTLY PROHIBITED.",
    ]
}

/// Print the authorized-use warning to stderr: two yellow warning lines
/// followed by one blank line. Never clears the screen.
pub fn boot(_target: &str, _mode: &str) {
    for line in warning_lines() {
        eprintln!("{}", warning(line));
    }
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_states_the_authorized_use_rule() {
        let lines = warning_lines();
        assert!(lines[0].contains("AUTHORIZED SECURITY TESTING ONLY"));
        assert!(lines[1].contains("UNAUTHORIZED USE IS STRICTLY PROHIBITED"));
    }

    #[test]
    fn warnings_carry_the_warning_tag_without_ansi() {
        for line in warning_lines() {
            assert!(line.starts_with("[!] "), "missing [!] tag: {line:?}");
            assert!(!line.contains('\x1B'), "raw line carries ANSI: {line:?}");
        }
    }

    #[test]
    fn warnings_are_pure_ascii() {
        for line in warning_lines() {
            assert!(line.is_ascii(), "non-ASCII: {line:?}");
        }
    }
}

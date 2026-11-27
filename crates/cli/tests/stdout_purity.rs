//! Machine-readable stdout must contain only the document; diagnostics go to
//! stderr. These tests run the real binary against a controlled local server.

use std::process::Command;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn run(format: &str, uri: &str) -> std::process::Output {
    let format = format.to_owned();
    let uri = uri.to_owned();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_riftlock"))
            .args([
                "scan",
                &uri,
                "--allow-private",
                "true",
                "--depth",
                "normal",
                "--format",
                &format,
            ])
            .env("NO_COLOR", "1")
            // The run writes and removes its checkpoint in the cwd.
            .current_dir(std::env::temp_dir())
            .output()
            .expect("run riftlock")
    })
    .await
    .expect("join")
}

#[tokio::test(flavor = "multi_thread")]
async fn json_stdout_is_one_parseable_document() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>ok</body></html>"))
        .mount(&server)
        .await;
    let output = run("json", &server.uri()).await;
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let doc: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not one JSON doc: {e}\n{stdout}"));
    assert_eq!(doc["schema_version"], 1);
    assert!(doc.get("metadata").is_some());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("[status]"),
        "diagnostics missing from stderr: {stderr}"
    );
    let report_path = stderr
        .lines()
        .find_map(|line| line.strip_prefix("    File: "))
        .expect("read-depth scan should announce its automatic HTML report path");
    let report_directory = stderr
        .lines()
        .find_map(|line| line.strip_prefix("    Directory: "))
        .expect("read-depth scan should announce its report directory");
    assert_eq!(
        std::path::Path::new(report_path)
            .parent()
            .map(std::path::Path::to_str)
            .flatten(),
        Some(report_directory),
        "reported directory should contain the HTML report"
    );
    assert!(
        stderr.contains("    Open: file://"),
        "missing open link: {stderr}"
    );
    assert!(
        report_path.ends_with(".html"),
        "unexpected report path: {report_path}"
    );
    assert!(
        std::path::Path::new(report_path).is_file(),
        "report was not written: {report_path}"
    );
    std::fs::remove_file(report_path).expect("remove generated report");
}

#[tokio::test(flavor = "multi_thread")]
async fn ndjson_every_line_parses_and_summary_is_last() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>ok</body></html>"))
        .mount(&server)
        .await;
    let output = run("ndjson", &server.uri()).await;
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "no ndjson output");
    for line in &lines {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("non-JSON stdout line: {e}\n{line}"));
    }
    let summary: serde_json::Value = serde_json::from_str(lines[lines.len() - 1]).expect("summary");
    assert_eq!(summary["event"], "scan.summary");
    assert_eq!(
        lines.iter().filter(|l| l.contains("scan.summary")).count(),
        1
    );
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("[status]"),
        "diagnostics missing from stderr: {stderr}"
    );
}

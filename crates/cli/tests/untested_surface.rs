//! Untested endpoint dispositions are visible in every scan output mode.

use std::process::{Command, Output};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn run(format: &str, uri: &str) -> Output {
    let format = format.to_owned();
    let uri = uri.to_owned();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_riftlock"))
            .args([
                "scan",
                &uri,
                "--provider",
                "generic",
                "--depth",
                "read",
                "--allow-private",
                "true",
                "--format",
                &format,
            ])
            .env("NO_COLOR", "1")
            .current_dir(std::env::temp_dir())
            .output()
            .expect("run riftlock")
    })
    .await
    .expect("join")
}

async fn auth_wall() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>lab</body></html>"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    server
}

#[tokio::test(flavor = "multi_thread")]
async fn json_and_ndjson_include_untested_surface_without_human_report() {
    let server = auth_wall().await;

    let output = run("json", &server.uri()).await;
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not one JSON document (status {:?}): {error}\n{stdout}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let surface = doc["metadata"]["untested_surface"]
        .as_array()
        .expect("JSON metadata includes endpoint-level untested surface");
    assert!(
        surface
            .iter()
            .any(|record| record["outcome"] == "auth_required"),
        "expected auth-required endpoint record: {surface:?}"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("[status]"), "missing status line: {stderr}");
    assert!(
        !stderr.contains("WE ALSO TESTED") && !stderr.contains("ABOUT THIS SCAN"),
        "human final report leaked to machine-format stderr: {stderr}"
    );

    let output = run("ndjson", &server.uri()).await;
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert!(!lines.is_empty(), "NDJSON output is empty");
    let mut summary = None;
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("invalid NDJSON line: {error}\n{line}"));
        if value["event"] == "scan.summary" {
            summary = Some(value);
        }
    }
    let summary = summary.expect("NDJSON summary event");
    assert!(summary["untested_surface"]
        .as_array()
        .expect("NDJSON summary includes endpoint-level untested surface")
        .iter()
        .any(|record| record["outcome"] == "auth_required"));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("[status]"), "missing status line: {stderr}");
    assert!(
        !stderr.contains("WE ALSO TESTED") && !stderr.contains("ABOUT THIS SCAN"),
        "human final report leaked to machine-format stderr: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn human_output_places_untested_surface_before_final_analysis() {
    let server = auth_wall().await;
    let output = run("human", &server.uri()).await;
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let surface_at = stdout
        .find("WE ALSO TESTED")
        .expect("final report includes the tested-surface summary");
    let final_at = stdout
        .find("ABOUT THIS SCAN")
        .expect("final report includes scan coverage notes");
    assert!(
        surface_at < final_at,
        "tested-surface summary must precede scan notes: {stdout}"
    );
}

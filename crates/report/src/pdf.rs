//! Plain-text PDF report: a title line plus one line per finding, paginated
//! across A4 pages. Uses a built-in Helvetica font so no system font file is
//! needed.

use crate::TestedSurface;
use printpdf::{
    BuiltinFont, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerIndex,
    PdfPageIndex,
};
use riftlock_core::Finding;

/// A4 page geometry in millimetres.
const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const MARGIN: f32 = 20.0;
const LINE_HEIGHT: f32 = 6.0;
/// (page height - 2 * margin) / line height, floored.
const LINES_PER_PAGE: usize = 42;

/// PDF export failure (font registration or document serialization).
#[derive(Debug, thiserror::Error)]
#[error("PDF export failed: {0}")]
pub struct PdfError(#[from] printpdf::Error);

/// Render `findings` and the tested surface as a text PDF report. Each page,
/// form and API entry occupies its own line in the WE ALSO TESTED section.
///
/// # Errors
/// Returns [`PdfError`] if printpdf fails to register the built-in font or
/// serialize the document.
pub fn to_pdf(findings: &[Finding], tested: &TestedSurface) -> Result<Vec<u8>, PdfError> {
    let lines = report_lines(findings, tested);

    let (doc, first_page, first_layer) = PdfDocument::new(
        "RIFTLOCK SECURITY REPORT",
        Mm(PAGE_W),
        Mm(PAGE_H),
        "Layer 1",
    );
    // shortcut: the built-in Helvetica only covers Windows-1252, so
    // non-encodable evidence characters are silently dropped by printpdf.
    // Switch to an embedded TTF font when Unicode evidence text matters.
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;

    let mut page = first_page;
    let mut layer = first_layer;
    let mut on_page = 0usize;
    for (text, size) in &lines {
        if on_page == LINES_PER_PAGE {
            let (p, l) = doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer 1");
            page = p;
            layer = l;
            on_page = 0;
        }
        let wrapped = wrap_pdf_line(text, *size);
        for segment in &wrapped {
            if on_page == LINES_PER_PAGE {
                let (p, l) = doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer 1");
                page = p;
                layer = l;
                on_page = 0;
            }
            let y = PAGE_H - MARGIN - on_page as f32 * LINE_HEIGHT;
            write_line(&doc, page, layer, y, segment, *size, &font);
            on_page += 1;
        }
    }

    doc.save_to_bytes().map_err(PdfError)
}

/// Wrap a long report line to a conservative A4 character width, preserving
/// whole words. PDF uses Helvetica; proportional glyph widths vary, so a
/// conservative text limit avoids clipping long discovered URLs.
fn wrap_pdf_line(text: &str, size: f32) -> Vec<String> {
    // 1pt = 0.3528mm. Helvetica's average advance is ~0.5em, so a glyph is
    // roughly size * 0.5 * 0.3528 mm wide. 0.19 is slightly conservative
    // (Helvetica averages a little over 0.5em for mixed text), leaving room
    // for wide characters without wrapping URLs much earlier than needed.
    let max_chars = ((PAGE_W - 2.0 * MARGIN) / (size * 0.19)).floor() as usize;
    if text.chars().count() <= max_chars.max(1) {
        return vec![text.to_owned()];
    }
    let width = max_chars.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if word.chars().count() > width {
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            let mut chunk = String::new();
            for character in word.chars() {
                chunk.push(character);
                if chunk.chars().count() == width {
                    lines.push(std::mem::take(&mut chunk));
                }
            }
            line = chunk;
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Ordered PDF text lines, factored out so layout behavior can be tested
/// independently from PDF serialization details.
fn report_lines(findings: &[Finding], tested: &TestedSurface) -> Vec<(String, f32)> {
    let mut lines: Vec<(String, f32)> = vec![
        ("RIFTLOCK SECURITY REPORT".to_string(), 16.0),
        ("WE ALSO TESTED".to_string(), 12.0),
        (format!("Pages: {}", tested.page_count), 10.0),
    ];
    for (label, entries) in [
        ("Pages", &tested.pages),
        ("Forms", &tested.forms),
        ("APIs", &tested.apis),
    ] {
        if !entries.is_empty() {
            lines.push((format!("{label}:"), 10.0));
            lines.extend(entries.iter().map(|entry| (format!("  {entry}"), 9.0)));
        }
    }
    lines.push(("".to_string(), 10.0));
    if findings.is_empty() {
        lines.push(("No findings were produced by this scan.".to_string(), 10.0));
    } else {
        for finding in findings {
            lines.push((
                format!(
                    "{} — {}: {}",
                    crate::severity(finding),
                    crate::rule_id(finding.evidence()),
                    crate::details(finding)
                ),
                10.0,
            ));
        }
    }
    lines
}

/// Write one text line onto a page layer at `y` millimetres from the bottom.
fn write_line(
    doc: &PdfDocumentReference,
    page: PdfPageIndex,
    layer: PdfLayerIndex,
    y: f32,
    text: &str,
    size: f32,
    font: &IndirectFontRef,
) {
    let layer = doc.get_page(page).get_layer(layer);
    layer.begin_text_section();
    layer.set_font(font, size);
    layer.set_text_cursor(Mm(MARGIN), Mm(y));
    layer.write_text(text, font);
    layer.end_text_section();
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::{Evidence, ProofGate};

    fn make(evidence: Evidence) -> Finding {
        ProofGate::admit(evidence).expect("admitted")
    }

    #[test]
    fn pdf_has_magic_bytes_and_body() {
        let findings = vec![make(Evidence::LeakedSecret {
            key_type: riftlock_core::KeyType::SupabaseSecret,
            location: "page".into(),
            masked: "sb_secret_********".into(),
            full: Default::default(),
        })];
        let out = to_pdf(&findings, &TestedSurface::default()).expect("pdf renders");
        assert!(out.starts_with(b"%PDF-"));
        assert!(out.len() > 500, "trivially small PDF: {} bytes", out.len());
    }

    #[test]
    fn tested_surface_entries_are_written_one_per_line() {
        let tested = TestedSurface {
            page_count: 2,
            pages: vec!["http://192.168.21.8:3001/".into()],
            forms: vec![],
            apis: vec![
                "http://192.168.21.8:3001/api/Challenges/?key=nftMintChallenge".into(),
                "http://192.168.21.8:3001/api/Products".into(),
            ],
        };
        let lines = report_lines(&[], &tested);
        let text: Vec<_> = lines.iter().map(|(line, _)| line.as_str()).collect();
        assert!(text.contains(&"  http://192.168.21.8:3001/api/Products"));
        assert!(text.contains(&"  http://192.168.21.8:3001/api/Challenges/?key=nftMintChallenge"));
        assert!(text.contains(&"  http://192.168.21.8:3001/"));
        assert_eq!(
            text.iter()
                .filter(|line| line.starts_with("  http://192.168.21.8:3001/api/"))
                .count(),
            2,
            "each API URL should have its own PDF text line"
        );
    }

    #[test]
    fn empty_report_still_renders_a_valid_pdf() {
        let out = to_pdf(&[], &TestedSurface::default()).expect("pdf renders");
        assert!(out.starts_with(b"%PDF-"));
        assert!(out.len() > 500);
    }

    #[test]
    fn wrapping_uses_the_full_a4_text_width() {
        // ~99 characters fit at 9pt; a 90-character URL must stay on one line.
        let url = format!("https://example.test/{}", "a".repeat(70));
        assert!(url.chars().count() >= 90);
        assert_eq!(wrap_pdf_line(&url, 9.0), vec![url.clone()]);

        // A URL longer than the page is hard-split, and no segment may exceed
        // the page width (previous formula wrapped at ~41 characters).
        let long = format!("https://example.test/{}", "b".repeat(300));
        let segments = wrap_pdf_line(&long, 9.0);
        assert!(segments.len() >= 3);
        for segment in &segments {
            assert!(
                segment.chars().count() <= 100,
                "segment too wide for A4: {} chars",
                segment.chars().count()
            );
        }
        assert_eq!(segments.concat(), long.replace(' ', ""));
    }

    #[test]
    fn many_findings_paginate() {
        let findings: Vec<Finding> = (0..(LINES_PER_PAGE * 2 + 1))
            .map(|i| {
                make(Evidence::SseDesync {
                    endpoint: format!("https://x/{i}/sse"),
                })
            })
            .collect();
        let out = to_pdf(&findings, &TestedSurface::default()).expect("pdf renders");
        assert!(out.starts_with(b"%PDF-"));
        // b"/Type/Page" also matches the "/Type/Pages" tree, so N pages -> N+1.
        let pages = out.windows(10).filter(|w| w == b"/Type/Page").count();
        assert!(pages >= 3, "expected 3 pages, counted {pages}");
    }
}

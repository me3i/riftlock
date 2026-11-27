//! Plain-text PDF report: a title line plus one line per finding, paginated
//! across A4 pages. Uses a built-in Helvetica font so no system font file is
//! needed.

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

/// Render `findings` as a text PDF report (title plus one line per finding,
/// same ordering as [`crate::markdown::to_markdown`]).
///
/// # Errors
/// Returns [`PdfError`] if printpdf fails to register the built-in font or
/// serialize the document.
pub fn to_pdf(findings: &[Finding]) -> Result<Vec<u8>, PdfError> {
    // (text, font size): the title first, then one line per finding.
    let mut lines: Vec<(String, f32)> = vec![("RIFTLOCK SECURITY REPORT".to_string(), 16.0)];
    if findings.is_empty() {
        lines.push(("No findings were produced by this scan.".to_string(), 10.0));
    } else {
        for f in findings {
            lines.push((
                format!(
                    "{} — {}: {}",
                    crate::severity(f),
                    crate::rule_id(f.evidence()),
                    crate::details(f)
                ),
                10.0,
            ));
        }
    }

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
        let y = PAGE_H - MARGIN - on_page as f32 * LINE_HEIGHT;
        write_line(&doc, page, layer, y, text, *size, &font);
        on_page += 1;
    }

    doc.save_to_bytes().map_err(PdfError)
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
        let out = to_pdf(&findings).expect("pdf renders");
        assert!(out.starts_with(b"%PDF-"));
        assert!(out.len() > 500, "trivially small PDF: {} bytes", out.len());
    }

    #[test]
    fn empty_report_still_renders_a_valid_pdf() {
        let out = to_pdf(&[]).expect("pdf renders");
        assert!(out.starts_with(b"%PDF-"));
        assert!(out.len() > 500);
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
        let out = to_pdf(&findings).expect("pdf renders");
        assert!(out.starts_with(b"%PDF-"));
        // b"/Type/Page" also matches the "/Type/Pages" tree, so N pages -> N+1.
        let pages = out.windows(10).filter(|w| w == b"/Type/Page").count();
        assert!(pages >= 3, "expected 3 pages, counted {pages}");
    }
}

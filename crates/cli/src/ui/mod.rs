//! Presentation layer for the Riftlock terminal experience: branding,
//! capability-aware theming, scan lifecycle and findings rendering. Pure presentation — no scanning logic lives here; every
//! status shown is driven by real engine events.

pub mod brand;
pub mod credentials;
pub mod final_report;
pub mod findings;
pub mod lifecycle;
pub mod theme;

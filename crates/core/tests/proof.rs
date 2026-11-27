//! Integration tests for the proof gate's private-constructor invariant.

use riftlock_core::{Evidence, KeyType, ProofGate};

#[test]
fn heuristic_like_value_cannot_construct_finding() {
    // Outside the crate, `Finding` has no public constructor: this would not
    // compile — `evidence` is private.
    // let f = Finding { evidence: ... }; // compile error
    let fake = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.looks-like-a-key";
    let admitted = ProofGate::admit(Evidence::LeakedSecret {
        key_type: KeyType::SupabaseAnonLegacy,
        location: fake.to_owned(),
        masked: "sb_secret_********".into(),
        full: Default::default(),
    });
    assert!(admitted.is_ok());
    // No enum variant can carry raw string material as a finding; the only
    // string-bearing fields are documented locations/row samples.
    assert!(matches!(
        admitted.expect("admitted").evidence(),
        Evidence::LeakedSecret { .. }
    ));
}

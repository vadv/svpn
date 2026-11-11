//! Hashed owner registry: RAM-only, no expiry or persistence.

use svpn::exit_state::StickyOwners;

// ── owner lifecycle ──

#[test]
fn retains_replaces_and_lists_owners() {
    let mut owners = StickyOwners::default();
    assert!(owners.is_empty());
    assert_eq!(owners.link_of(100), None);
    owners.assign(200, 1);
    owners.assign(100, 0);
    assert_eq!(owners.iter(), vec![(100, 0), (200, 1)]);
    owners.assign(100, 1);
    assert_eq!(owners.link_of(100), Some(1));
    assert_eq!(owners.len(), 2);
    assert_eq!(owners.iter(), vec![(100, 1), (200, 1)]);
    assert!(StickyOwners::default().is_empty(), "restart has no history");
}

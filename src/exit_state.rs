//! Hashed sticky owners, retained until process exit; nothing touches disk.

use std::collections::HashMap;

/// Automatic hashed ASN groups and explicit sticky blocks; never balanced groups.
#[derive(Default)]
pub struct StickyOwners {
    // shortcut: historical ASN keys remain until restart; revisit if measured map growth warrants a cap.
    owners: HashMap<u64, usize>,
}

impl StickyOwners {
    pub fn assign(&mut self, group: u64, link: usize) {
        self.owners.insert(group, link);
    }

    pub fn link_of(&self, group: u64) -> Option<usize> {
        self.owners.get(&group).copied()
    }

    /// Group → owner link pairs, sorted for stable dashboard output.
    pub fn iter(&self) -> Vec<(u64, usize)> {
        let mut pairs: Vec<_> = self
            .owners
            .iter()
            .map(|(&group, &link)| (group, link))
            .collect();
        pairs.sort_unstable();
        pairs
    }

    pub fn len(&self) -> usize {
        self.owners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }
}

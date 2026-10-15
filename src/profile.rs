//! UDP wire-shape profiles (EPIC-005 I03/I04): the wire representation of
//! the channel sealed record `[seq 8][ct][tag 16]`. Orchestration and
//! strategy selection belong to session (I07+).
//!
//! `Plain` — diagnostic U-L0: the record equals the UDP payload.
//! `Mosh` — mosh-like prefix: u64 little-endian (seq + direction bit in the
//! MSB) instead of the big-endian `Cipher`. Not compatible with SSP (GCM
//! instead of OCB, different plaintext structure) — a look-alike, not an
//! emulation.
//! `Obfs` — random prefix and padding (lengths derived from two random
//! header bytes): uniformly random UDP without WireGuard signatures.
//! Deviation from "multiple of 16": exact multiplicity requires an explicit
//! length field (a detectable structure) or brute-forcing the sealed
//! boundary; smearing lengths by ±15 B achieves the same goal without
//! structure.
//! Consumed by session in I07/I08 — dead code for the bin build until then.
#![allow(dead_code)]

use anyhow::{Context, Result, ensure};

use crate::crypto::{self, MAX_PLAINTEXT};

/// Minimal mosh packet: 8 B prefix + 4 B ciphertext + 16 B tag.
pub const MIN_WIRE: usize = 28;
/// Maximum profile UDP payload: the channel sealed record in full.
pub const MAX_WIRE: usize = MAX_PLAINTEXT + 24;
/// Obfs header `[b1][b2]`: prefix = b1%16, padding = b2%16.
pub const OBF_HEADER: usize = 2;
/// Worst-case obfs overhead: prefix 15 + padding 15.
const OBF_EXTRA: usize = 30;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Profile {
    Plain,
    Mosh,
    Obfs,
}

impl Profile {
    /// Maximum DATA fragment of this profile: wire budget minus overhead
    /// (record header 21 B + GCM 24 B + the profile's shape).
    pub fn max_fragment(&self) -> usize {
        match self {
            Profile::Plain | Profile::Mosh => crate::channel::MAX_FRAGMENT,
            Profile::Obfs => MAX_WIRE - OBF_HEADER - OBF_EXTRA - 21 - 24,
        }
    }

    /// Converts a sealed record into the profile's wire bytes in place.
    /// Plain/Mosh — no allocations; Obfs rebuilds the buffer (grows).
    pub fn wrap_in_place(&self, sealed: &mut Vec<u8>) -> Result<()> {
        self.check_len(sealed.len(), "sealed")?;
        if matches!(self, Profile::Mosh) {
            sealed[..8].reverse();
        }
        if matches!(self, Profile::Obfs) {
            let [b1, b2] = crypto::random::<2>()?;
            let prefix = usize::from(b1 % 16);
            let pad = usize::from(b2 % 16);
            ensure!(
                OBF_HEADER + prefix + sealed.len() + pad <= MAX_WIRE,
                "obfs wire budget exceeded for sealed length {}",
                sealed.len()
            );
            let junk_prefix = crypto::random::<15>()?;
            let junk_pad = crypto::random::<15>()?;
            let mut wire = Vec::with_capacity(OBF_HEADER + prefix + sealed.len() + pad);
            wire.push(b1);
            wire.push(b2);
            wire.extend_from_slice(&junk_prefix[..prefix]);
            wire.extend_from_slice(sealed);
            wire.extend_from_slice(&junk_pad[..pad]);
            *sealed = wire;
        }
        Ok(())
    }

    /// Inverse conversion: the profile's wire bytes back into a channel
    /// sealed record.
    pub fn unwrap_in_place(&self, wire: &mut Vec<u8>) -> Result<()> {
        if matches!(self, Profile::Obfs) {
            ensure!(
                wire.len() >= OBF_HEADER + MIN_WIRE,
                "obfs wire length {} too short",
                wire.len()
            );
            let prefix = OBF_HEADER + usize::from(wire[0] % 16);
            let pad = usize::from(wire[1] % 16);
            let sealed_end = wire
                .len()
                .checked_sub(pad)
                .filter(|&end| end >= prefix + MIN_WIRE && end - prefix <= MAX_WIRE)
                .context("obfs padding exceeds wire")?;
            let sealed_len = sealed_end - prefix;
            wire.copy_within(prefix..sealed_end, 0);
            wire.truncate(sealed_len);
            return Ok(());
        }
        self.check_len(wire.len(), "wire")?;
        if matches!(self, Profile::Mosh) {
            wire[..8].reverse();
        }
        Ok(())
    }

    fn check_len(&self, len: usize, what: &str) -> Result<()> {
        ensure!(
            (MIN_WIRE..=MAX_WIRE).contains(&len),
            "{what} length {len} outside {MIN_WIRE}..={MAX_WIRE}"
        );
        Ok(())
    }
}

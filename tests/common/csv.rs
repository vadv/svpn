//! Temporary CSV text for dashboard download integration tests.
#![allow(dead_code)] // Included by all common users; only CSV tests need this fixture.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
};

pub struct Csv(pub PathBuf);

impl Csv {
    pub fn new(contents: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "svpn-web-csv-{}-{}.csv",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }
}

impl Drop for Csv {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

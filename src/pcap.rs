//! Test pcap writer: a global header + DLT_RAW records (IPv4+UDP).
//! Shared by the profile socket-dance tests and the QUIC tests.

pub struct PcapBuilder {
    out: Vec<u8>,
}

impl PcapBuilder {
    pub fn new() -> Self {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes()); // magic
        out.extend_from_slice(&2u16.to_le_bytes()); // major
        out.extend_from_slice(&4u16.to_le_bytes()); // minor
        out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&101u32.to_le_bytes()); // DLT_RAW (IPv4)
        Self { out }
    }

    /// Wraps a datagram in IPv4+UDP headers (checksums 0, no fragmentation).
    pub fn add_datagram(&mut self, payload: &[u8]) {
        let total = 20 + 8 + payload.len();
        self.out.extend_from_slice(&1_732_930_564u32.to_le_bytes()); // ts_sec (fixed)
        self.out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        self.out.extend_from_slice(&(total as u32).to_le_bytes()); // incl_len
        self.out.extend_from_slice(&(total as u32).to_le_bytes()); // orig_len
        let mut ip = Vec::with_capacity(20);
        ip.extend_from_slice(&[0x45, 0x00]);
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x01]); // id
        ip.extend_from_slice(&[0x00, 0x00]); // flags/offset: MF=0 — no outer fragmentation
        ip.extend_from_slice(&[64, 17]); // ttl, proto UDP
        ip.extend_from_slice(&[0x00, 0x00]); // checksum
        ip.extend_from_slice(&[127, 0, 0, 1]);
        ip.extend_from_slice(&[127, 0, 0, 2]);
        self.out.extend_from_slice(&ip);
        self.out.extend_from_slice(&[0xd3, 0x51, 0xea, 0x60]); // ports 54065→60000
        self.out
            .extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        self.out.extend_from_slice(&[0x00, 0x00]); // udp checksum
        self.out.extend_from_slice(payload);
    }

    pub fn finish(self, path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, self.out).unwrap();
    }
}

impl Default for PcapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

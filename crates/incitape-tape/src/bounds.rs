#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    pub max_record_bytes: u32,
    pub max_frame_len: u32,
    pub max_decompressed_bytes: u64,
    pub max_tape_file_bytes: u64,
    pub max_records_per_tape: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        let max_record_bytes = 8 * 1024 * 1024;
        Self {
            max_record_bytes,
            max_frame_len: max_record_bytes + 64,
            max_decompressed_bytes: 512 * 1024 * 1024,
            max_tape_file_bytes: 1024 * 1024 * 1024,
            max_records_per_tape: 2_000_000,
        }
    }
}

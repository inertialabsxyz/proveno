use crate::vm::gas::VmError;

/// Memory accounting — monotonic high-water mark.
/// Frees are not credited. Charges are applied at allocation time.
#[derive(Debug)]
pub struct MemoryMeter {
    /// Monotonically increasing allocated total.
    allocated: u64,
    limit: u64,
}

impl MemoryMeter {
    pub fn new(limit: u64) -> Self {
        MemoryMeter {
            allocated: 0,
            limit,
        }
    }

    /// Add `bytes` to the allocated total.
    /// Returns `Err(VmError::MemoryExhausted)` if the new total exceeds the limit.
    pub fn track_alloc(&mut self, bytes: u64) -> Result<(), VmError> {
        self.allocated = self.allocated.saturating_add(bytes);
        if self.allocated > self.limit {
            Err(VmError::MemoryExhausted)
        } else {
            Ok(())
        }
    }

    /// Current high-water mark (bytes).
    pub fn used(&self) -> u64 {
        self.allocated
    }
}

/// Allocation sizes per spec §6.
pub mod alloc_size {
    /// String: 24-byte header + content bytes.
    pub fn string(len: usize) -> u64 {
        24 + len as u64
    }

    /// Table base: 64 bytes.
    pub fn table_base() -> u64 {
        64
    }

    /// Each hash slot: 40 bytes.
    pub fn table_hash_slot() -> u64 {
        40
    }

    /// Each array slot: 16 bytes.
    pub fn table_array_slot() -> u64 {
        16
    }

    /// Closure: 32 + upvalue_count * 8.
    pub fn closure(upvalue_count: u8) -> u64 {
        32 + upvalue_count as u64 * 8
    }

    /// Stack frame: 64 + local_count * 8.
    pub fn stack_frame(local_count: u8) -> u64 {
        64 + local_count as u64 * 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_alloc_within_limit() {
        let mut m = MemoryMeter::new(100);
        assert!(m.track_alloc(50).is_ok());
        assert_eq!(m.used(), 50);
    }

    #[test]
    fn mem_alloc_exact_limit() {
        let mut m = MemoryMeter::new(100);
        assert!(m.track_alloc(100).is_ok());
        assert_eq!(m.used(), 100);
    }

    #[test]
    fn mem_alloc_exceeds_limit() {
        let mut m = MemoryMeter::new(100);
        assert_eq!(m.track_alloc(101), Err(VmError::MemoryExhausted));
    }

    #[test]
    fn mem_monotonic_no_credit() {
        let mut m = MemoryMeter::new(1000);
        m.track_alloc(300).unwrap();
        // Simulating "free + realloc": we still charge both
        m.track_alloc(300).unwrap();
        assert_eq!(m.used(), 600);
    }
}

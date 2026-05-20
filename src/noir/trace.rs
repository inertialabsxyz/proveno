// Phase 2 stub — full implementation in noir/2-trace-emission
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceStep {
    pub pc: u32,
    pub opcode: u8,
    pub operand: i64,
    pub stack_top: i64,
    pub next_pc: u32,
}

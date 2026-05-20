use crate::compiler::proto::Instruction;

pub const NOP: u8 = 0;
pub const PUSH_K: u8 = 1;
pub const PUSH_NIL: u8 = 2;
pub const PUSH_TRUE: u8 = 3;
pub const PUSH_FALSE: u8 = 4;
pub const POP: u8 = 5;
pub const DUP: u8 = 6;
pub const LOAD_LOCAL: u8 = 7;
pub const STORE_LOCAL: u8 = 8;
pub const LOAD_UP: u8 = 9;
pub const STORE_UP: u8 = 10;
pub const NEW_TABLE: u8 = 11;
pub const GET_TABLE: u8 = 12;
pub const SET_TABLE: u8 = 13;
pub const GET_FIELD: u8 = 14;
pub const SET_FIELD: u8 = 15;
pub const ADD: u8 = 16;
pub const SUB: u8 = 17;
pub const MUL: u8 = 18;
pub const IDIV: u8 = 19;
pub const MOD: u8 = 20;
pub const NEG: u8 = 21;
pub const EQ: u8 = 22;
pub const NE: u8 = 23;
pub const LT: u8 = 24;
pub const LE: u8 = 25;
pub const GT: u8 = 26;
pub const GE: u8 = 27;
pub const NOT: u8 = 28;
pub const AND: u8 = 29;
pub const OR: u8 = 30;
pub const CONCAT: u8 = 31;
pub const LEN: u8 = 32;
pub const JMP: u8 = 33;
pub const JMP_IF: u8 = 34;
pub const JMP_IF_NOT: u8 = 35;
pub const CALL: u8 = 36;
pub const RET: u8 = 37;
pub const CLOSURE: u8 = 38;
pub const TOOL_CALL: u8 = 39;
pub const PCALL: u8 = 40;
pub const LOG: u8 = 41;
pub const ERROR: u8 = 42;
pub const ITER_INIT_SORTED: u8 = 43;
pub const ITER_INIT_ARRAY: u8 = 44;
pub const ITER_NEXT: u8 = 45;

pub fn instruction_to_opcode_id(i: &Instruction) -> u8 {
    match i {
        Instruction::Nop => NOP,
        Instruction::PushK(_) => PUSH_K,
        Instruction::PushNil => PUSH_NIL,
        Instruction::PushTrue => PUSH_TRUE,
        Instruction::PushFalse => PUSH_FALSE,
        Instruction::Pop => POP,
        Instruction::Dup => DUP,
        Instruction::LoadLocal(_) => LOAD_LOCAL,
        Instruction::StoreLocal(_) => STORE_LOCAL,
        Instruction::LoadUp(_) => LOAD_UP,
        Instruction::StoreUp(_) => STORE_UP,
        Instruction::NewTable => NEW_TABLE,
        Instruction::GetTable => GET_TABLE,
        Instruction::SetTable => SET_TABLE,
        Instruction::GetField(_) => GET_FIELD,
        Instruction::SetField(_) => SET_FIELD,
        Instruction::Add => ADD,
        Instruction::Sub => SUB,
        Instruction::Mul => MUL,
        Instruction::IDiv => IDIV,
        Instruction::Mod => MOD,
        Instruction::Neg => NEG,
        Instruction::Eq => EQ,
        Instruction::Ne => NE,
        Instruction::Lt => LT,
        Instruction::Le => LE,
        Instruction::Gt => GT,
        Instruction::Ge => GE,
        Instruction::Not => NOT,
        Instruction::And(_) => AND,
        Instruction::Or(_) => OR,
        Instruction::Concat(_) => CONCAT,
        Instruction::Len => LEN,
        Instruction::Jmp(_) => JMP,
        Instruction::JmpIf(_) => JMP_IF,
        Instruction::JmpIfNot(_) => JMP_IF_NOT,
        Instruction::Call(_) => CALL,
        Instruction::Ret(_) => RET,
        Instruction::Closure(_) => CLOSURE,
        Instruction::ToolCall => TOOL_CALL,
        Instruction::PCall(_) => PCALL,
        Instruction::Log => LOG,
        Instruction::Error => ERROR,
        Instruction::IterInitSorted(_) => ITER_INIT_SORTED,
        Instruction::IterInitArray(_) => ITER_INIT_ARRAY,
        Instruction::IterNext(_) => ITER_NEXT,
    }
}

pub fn instruction_to_operand(i: &Instruction) -> i64 {
    match i {
        Instruction::Nop => 0,
        Instruction::PushK(idx) => *idx as i64,
        Instruction::PushNil => 0,
        Instruction::PushTrue => 0,
        Instruction::PushFalse => 0,
        Instruction::Pop => 0,
        Instruction::Dup => 0,
        Instruction::LoadLocal(slot) => *slot as i64,
        Instruction::StoreLocal(slot) => *slot as i64,
        Instruction::LoadUp(slot) => *slot as i64,
        Instruction::StoreUp(slot) => *slot as i64,
        Instruction::NewTable => 0,
        Instruction::GetTable => 0,
        Instruction::SetTable => 0,
        Instruction::GetField(idx) => *idx as i64,
        Instruction::SetField(idx) => *idx as i64,
        Instruction::Add => 0,
        Instruction::Sub => 0,
        Instruction::Mul => 0,
        Instruction::IDiv => 0,
        Instruction::Mod => 0,
        Instruction::Neg => 0,
        Instruction::Eq => 0,
        Instruction::Ne => 0,
        Instruction::Lt => 0,
        Instruction::Le => 0,
        Instruction::Gt => 0,
        Instruction::Ge => 0,
        Instruction::Not => 0,
        Instruction::And(offset) => *offset as i64,
        Instruction::Or(offset) => *offset as i64,
        Instruction::Concat(n) => *n as i64,
        Instruction::Len => 0,
        Instruction::Jmp(offset) => *offset as i64,
        Instruction::JmpIf(offset) => *offset as i64,
        Instruction::JmpIfNot(offset) => *offset as i64,
        Instruction::Call(argc) => *argc as i64,
        Instruction::Ret(n) => *n as i64,
        Instruction::Closure(idx) => *idx as i64,
        Instruction::ToolCall => 0,
        Instruction::PCall(argc) => *argc as i64,
        Instruction::Log => 0,
        Instruction::Error => 0,
        Instruction::IterInitSorted(offset) => *offset as i64,
        Instruction::IterInitArray(offset) => *offset as i64,
        Instruction::IterNext(offset) => *offset as i64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn all_variants() -> Vec<(Instruction, u8, i64)> {
        vec![
            (Instruction::Nop, 0, 0),
            (Instruction::PushK(5), 1, 5),
            (Instruction::PushNil, 2, 0),
            (Instruction::PushTrue, 3, 0),
            (Instruction::PushFalse, 4, 0),
            (Instruction::Pop, 5, 0),
            (Instruction::Dup, 6, 0),
            (Instruction::LoadLocal(3), 7, 3),
            (Instruction::StoreLocal(3), 8, 3),
            (Instruction::LoadUp(1), 9, 1),
            (Instruction::StoreUp(1), 10, 1),
            (Instruction::NewTable, 11, 0),
            (Instruction::GetTable, 12, 0),
            (Instruction::SetTable, 13, 0),
            (Instruction::GetField(10), 14, 10),
            (Instruction::SetField(10), 15, 10),
            (Instruction::Add, 16, 0),
            (Instruction::Sub, 17, 0),
            (Instruction::Mul, 18, 0),
            (Instruction::IDiv, 19, 0),
            (Instruction::Mod, 20, 0),
            (Instruction::Neg, 21, 0),
            (Instruction::Eq, 22, 0),
            (Instruction::Ne, 23, 0),
            (Instruction::Lt, 24, 0),
            (Instruction::Le, 25, 0),
            (Instruction::Gt, 26, 0),
            (Instruction::Ge, 27, 0),
            (Instruction::Not, 28, 0),
            (Instruction::And(-3), 29, -3),
            (Instruction::Or(-3), 30, -3),
            (Instruction::Concat(4), 31, 4),
            (Instruction::Len, 32, 0),
            (Instruction::Jmp(-10), 33, -10),
            (Instruction::JmpIf(5), 34, 5),
            (Instruction::JmpIfNot(5), 35, 5),
            (Instruction::Call(2), 36, 2),
            (Instruction::Ret(1), 37, 1),
            (Instruction::Closure(0), 38, 0),
            (Instruction::ToolCall, 39, 0),
            (Instruction::PCall(2), 40, 2),
            (Instruction::Log, 41, 0),
            (Instruction::Error, 42, 0),
            (Instruction::IterInitSorted(-5), 43, -5),
            (Instruction::IterInitArray(-5), 44, -5),
            (Instruction::IterNext(-5), 45, -5),
        ]
    }

    #[test]
    fn all_variants_have_unique_ids() {
        let variants = all_variants();
        assert_eq!(
            variants.len(),
            46,
            "expected 46 variants (Nop=0 through IterNext=45)"
        );

        for (instr, expected_id, _) in &variants {
            assert_eq!(
                instruction_to_opcode_id(instr),
                *expected_id,
                "wrong opcode id for {:?}",
                instr
            );
        }

        let ids: HashSet<u8> = variants
            .iter()
            .map(|(i, _, _)| instruction_to_opcode_id(i))
            .collect();
        assert_eq!(ids.len(), variants.len(), "duplicate opcode IDs detected");
    }

    #[test]
    fn all_variants_operand_encodes_correctly() {
        for (instr, _, expected_operand) in all_variants() {
            assert_eq!(
                instruction_to_operand(&instr),
                expected_operand,
                "wrong operand for {:?}",
                instr
            );
        }
    }
}

#[cfg(feature = "std")]
use std::{cell::RefCell, rc::Rc};
#[cfg(not(feature = "std"))]
use {
    alloc::{
        boxed::Box,
        format,
        rc::Rc,
        string::{String, ToString},
        vec,
        vec::Vec,
    },
    core::cell::RefCell,
};

use crate::{
    compiler::proto::{CompiledProgram, Constant, Instruction, UpvalueDesc},
    host::{
        tool_registry::ToolRegistry,
        transcript::{ToolCallRecord, Transcript},
    },
    noir::{
        opcodes::{instruction_to_opcode_id, instruction_to_operand},
        trace::TraceStep,
    },
    types::{
        table::{LuaKey, LuaTable, RawsetResult},
        value::{BuiltinId, LuaClosure, LuaError, LuaString, LuaValue},
    },
    vm::{
        builtins::{self, build_globals, ceil_log2},
        gas::{GasMeter, VmError, gas_cost},
        memory::{MemoryMeter, alloc_size},
    },
};

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VmConfig {
    pub gas_limit: u64,
    pub memory_limit_bytes: u64,
    pub max_call_depth: usize,
    pub max_tool_calls: usize,
    pub max_tool_bytes_in: usize,
    pub max_tool_bytes_out: usize,
    pub max_output_bytes: usize,
    pub record_trace: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        VmConfig {
            gas_limit: 200_000,
            memory_limit_bytes: 16 * 1024 * 1024,
            max_call_depth: 64,
            max_tool_calls: 16,
            max_tool_bytes_in: 64 * 1024,
            max_tool_bytes_out: 1024 * 1024,
            max_output_bytes: 256 * 1024,
            record_trace: false,
        }
    }
}

// ── Stack slot ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum StackSlot {
    Value(LuaValue),
    /// A local slot that has been "closed over" by a closure. Reads and writes
    /// go through the shared cell so that both the closure's upvalue and any
    /// future LoadLocal/StoreLocal on this slot see the same value.
    Shared(Rc<RefCell<LuaValue>>),
    IterHandle(IterHandle),
}

impl StackSlot {
    fn as_value(&self) -> Result<LuaValue, VmError> {
        match self {
            StackSlot::Value(v) => Ok(v.clone()),
            StackSlot::Shared(cell) => Ok(cell.borrow().clone()),
            StackSlot::IterHandle(_) => Err(VmError::RuntimeError(LuaValue::String(
                LuaString::from_str("attempt to use iterator handle as value"),
            ))),
        }
    }

    fn into_value(self) -> Result<LuaValue, VmError> {
        match self {
            StackSlot::Value(v) => Ok(v),
            StackSlot::Shared(cell) => Ok(cell.borrow().clone()),
            StackSlot::IterHandle(_) => Err(VmError::RuntimeError(LuaValue::String(
                LuaString::from_str("attempt to use iterator handle as value"),
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IterHandle {
    Sorted {
        keys: Vec<LuaValue>,
        index: usize,
        table: Rc<RefCell<LuaTable>>,
    },
    Array {
        table: Rc<RefCell<LuaTable>>,
        index: i64,
    },
}

// ── Call frame ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CallFrame {
    pub proto_idx: usize,
    pub pc: usize,
    pub base: usize,
    pub upvalues: Vec<UpvalueSlot>,
    pub expected_returns: u8,
}

/// An upvalue: a shared mutable cell containing a `LuaValue`.
#[derive(Debug, Clone)]
pub struct UpvalueSlot(pub Rc<RefCell<LuaValue>>);

// ── pcall checkpoint ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PCallCheckpoint {
    pub stack_len: usize,
    pub frame_len: usize,
}

// ── Output ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VmOutput {
    pub return_value: LuaValue,
    pub logs: Vec<String>,
    pub gas_used: u64,
    pub memory_used: u64,
    pub transcript: Vec<ToolCallRecord>,
    pub trace: Vec<TraceStep>,
}

// ── HostInterface trait ───────────────────────────────────────────────────────

pub trait HostInterface {
    fn call_tool(&mut self, name: &str, args: &LuaTable) -> Result<LuaTable, String>;
}

pub struct NoopHost;

impl HostInterface for NoopHost {
    fn call_tool(&mut self, name: &str, _args: &LuaTable) -> Result<LuaTable, String> {
        Err(format!("tool '{}' not registered", name))
    }
}

// ── Vm struct ─────────────────────────────────────────────────────────────────

pub struct Vm<H: HostInterface> {
    config: VmConfig,
    gas: GasMeter,
    mem: MemoryMeter,
    stack: Vec<StackSlot>,
    frames: Vec<CallFrame>,
    logs: Vec<String>,
    transcript: Transcript,
    registry: ToolRegistry<H>,
    globals: LuaTable,
}

impl<H: HostInterface> Vm<H> {
    pub fn new(config: VmConfig, host: H) -> Self {
        let gas = GasMeter::new(config.gas_limit);
        let mem = MemoryMeter::new(config.memory_limit_bytes);
        Vm {
            config,
            gas,
            mem,
            stack: Vec::new(),
            frames: Vec::new(),
            logs: Vec::new(),
            transcript: Transcript::new(),
            registry: ToolRegistry::new(host),
            globals: build_globals(),
        }
    }

    /// Create a VM with an attached `OraclePolicy`. Tool calls are checked
    /// against the policy's domain allowlist, method restriction, and schemas.
    #[cfg(feature = "std")]
    pub fn new_with_policy(config: VmConfig, host: H, policy: crate::policy::OraclePolicy) -> Self {
        let gas = GasMeter::new(config.gas_limit);
        let mem = MemoryMeter::new(config.memory_limit_bytes);
        Vm {
            config,
            gas,
            mem,
            stack: Vec::new(),
            frames: Vec::new(),
            logs: Vec::new(),
            transcript: Transcript::new(),
            registry: ToolRegistry::with_policy(host, policy),
            globals: build_globals(),
        }
    }

    pub fn execute(
        &mut self,
        program: &CompiledProgram,
        input: LuaValue,
    ) -> Result<VmOutput, VmError> {
        // Reset state for fresh execution.
        self.stack.clear();
        self.frames.clear();
        self.logs.clear();
        self.transcript = Transcript::new();
        self.registry.reset();

        // Push the top-level chunk (prototype 0).
        let proto0 = &program.prototypes[0];
        self.mem
            .track_alloc(alloc_size::stack_frame(proto0.local_count))?;

        // Push locals (params + nils) for the top-level frame.
        let base = 0;
        let frame = CallFrame {
            proto_idx: 0,
            pc: 0,
            base,
            upvalues: Vec::new(),
            expected_returns: 1,
        };
        self.frames.push(frame);

        // Allocate local slots.
        for _ in 0..proto0.local_count {
            self.stack.push(StackSlot::Value(LuaValue::Nil));
        }

        // Bind input to first param if applicable.
        if proto0.param_count >= 1 && proto0.local_count >= 1 {
            self.stack[base] = StackSlot::Value(input);
        }

        let mut return_value = LuaValue::Nil;
        let mut trace: Vec<TraceStep> = Vec::new();

        // Compute global base offset for each prototype: prototype_offsets[i] is
        // the index of prototype i's first instruction in the flattened bytecode.
        let prototype_offsets: Vec<usize> = {
            let mut offsets = Vec::with_capacity(program.prototypes.len());
            let mut off = 0usize;
            for proto in &program.prototypes {
                offsets.push(off);
                off += proto.code.len();
            }
            offsets
        };

        loop {
            let proto_idx = self.frames.last().unwrap().proto_idx;
            let pc = self.frames.last().unwrap().pc;
            let code_len = program.prototypes[proto_idx].code.len();

            if pc >= code_len {
                // Implicit return nil at end of function.
                match self.do_return(0) {
                    Ok(Some(v)) => {
                        return_value = v;
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }
                if self.frames.is_empty() {
                    break;
                }
                continue;
            }

            let instr = program.prototypes[proto_idx].code[pc].clone();
            self.frames.last_mut().unwrap().pc += 1;

            // Capture pre-dispatch state for tracing (all frames).
            let trace_this = self.config.record_trace;
            let (trace_pc, trace_opcode, trace_operand, trace_stack_top) = if trace_this {
                let global_pc = (prototype_offsets[proto_idx] + pc) as u32;
                let opcode = instruction_to_opcode_id(&instr);
                let operand = instruction_to_operand(&instr);
                let stack_top = match self.stack.last() {
                    Some(StackSlot::Value(LuaValue::Integer(n))) => *n,
                    Some(StackSlot::Value(LuaValue::Boolean(b))) => {
                        if *b {
                            1
                        } else {
                            0
                        }
                    }
                    Some(StackSlot::Shared(cell)) => match &*cell.borrow() {
                        LuaValue::Integer(n) => *n,
                        LuaValue::Boolean(b) => {
                            if *b {
                                1
                            } else {
                                0
                            }
                        }
                        _ => 0,
                    },
                    _ => 0,
                };
                (global_pc, opcode, operand, stack_top)
            } else {
                (0, 0, 0, 0)
            };

            // Compute global next_pc after dispatch: offset of the current frame's
            // prototype plus the post-dispatch local pc.
            let next_global_pc = |frames: &[CallFrame], offsets: &[usize]| -> u32 {
                match frames.last() {
                    Some(f) => (offsets[f.proto_idx] + f.pc) as u32,
                    None => 0,
                }
            };

            match self.dispatch(program, instr) {
                Ok(Some(v)) => {
                    if trace_this {
                        let next_pc = next_global_pc(&self.frames, &prototype_offsets);
                        trace.push(TraceStep {
                            pc: trace_pc,
                            opcode: trace_opcode,
                            operand: trace_operand,
                            stack_top: trace_stack_top,
                            next_pc,
                        });
                    }
                    return_value = v;
                    break;
                }
                Ok(None) => {
                    if trace_this {
                        let next_pc = next_global_pc(&self.frames, &prototype_offsets);
                        trace.push(TraceStep {
                            pc: trace_pc,
                            opcode: trace_opcode,
                            operand: trace_operand,
                            stack_top: trace_stack_top,
                            next_pc,
                        });
                    }
                }
                Err(e) => {
                    let line = program.prototypes[proto_idx]
                        .lines
                        .get(pc)
                        .copied()
                        .unwrap_or(0);
                    return Err(VmError::WithLine(line, Box::new(e)));
                }
            }

            if self.frames.is_empty() {
                break;
            }
        }

        Ok(VmOutput {
            return_value,
            logs: self.logs.clone(),
            gas_used: self.gas.used(),
            memory_used: self.mem.used(),
            transcript: self.transcript.records().to_vec(),
            trace,
        })
    }

    /// Dispatch a single instruction. Returns Ok(Some(v)) if execution is done
    /// (top-level return), Ok(None) to continue, Err to propagate error.
    fn dispatch(
        &mut self,
        program: &CompiledProgram,
        instr: Instruction,
    ) -> Result<Option<LuaValue>, VmError> {
        self.gas.charge(gas_cost::BASE_INSTRUCTION)?;

        match instr {
            Instruction::Nop => {}

            Instruction::PushK(idx) => {
                let frame = self.frames.last().unwrap();
                let proto = &program.prototypes[frame.proto_idx];
                let val = constant_to_value(&proto.constants[idx as usize]);
                self.stack.push(StackSlot::Value(val));
            }

            Instruction::PushNil => {
                self.stack.push(StackSlot::Value(LuaValue::Nil));
            }

            Instruction::PushTrue => {
                self.stack.push(StackSlot::Value(LuaValue::Boolean(true)));
            }

            Instruction::PushFalse => {
                self.stack.push(StackSlot::Value(LuaValue::Boolean(false)));
            }

            Instruction::Pop => {
                self.stack.pop();
            }

            Instruction::Dup => {
                let top = self.stack.last().ok_or_else(stack_underflow)?.clone();
                self.stack.push(top);
            }

            Instruction::LoadLocal(slot) => {
                let base = self.frames.last().unwrap().base;
                let idx = base + slot as usize;
                let val = self.stack[idx].as_value()?;
                self.stack.push(StackSlot::Value(val));
            }

            Instruction::StoreLocal(slot) => {
                let val = self.pop_value()?;
                let base = self.frames.last().unwrap().base;
                let idx = base + slot as usize;
                match &self.stack[idx] {
                    StackSlot::Shared(cell) => {
                        *cell.borrow_mut() = val;
                    }
                    _ => {
                        self.stack[idx] = StackSlot::Value(val);
                    }
                }
            }

            Instruction::LoadUp(idx) => {
                let val = self.frames.last().unwrap().upvalues[idx as usize]
                    .0
                    .borrow()
                    .clone();
                self.stack.push(StackSlot::Value(val));
            }

            Instruction::StoreUp(idx) => {
                let val = self.pop_value()?;
                *self.frames.last().unwrap().upvalues[idx as usize]
                    .0
                    .borrow_mut() = val;
            }

            Instruction::NewTable => {
                self.gas.charge(gas_cost::TABLE_ALLOC)?;
                self.mem.track_alloc(alloc_size::table_base())?;
                let t = Rc::new(RefCell::new(LuaTable::new()));
                self.stack.push(StackSlot::Value(LuaValue::Table(t)));
            }

            Instruction::GetTable => {
                self.gas.charge(gas_cost::TABLE_GET)?;
                let key = self.pop_value()?.into_key().map_err(VmError::from)?;
                let raw_table_val = self.pop_value()?;
                let table_val = self.resolve_sentinel(raw_table_val);
                let t = table_val.as_table().map_err(VmError::from)?;
                let result = t.borrow().get(&key).cloned().unwrap_or(LuaValue::Nil);
                self.stack.push(StackSlot::Value(result));
            }

            Instruction::SetTable => {
                let value = self.pop_value()?;
                let key = self.pop_value()?.into_key().map_err(VmError::from)?;
                let table_val = self.pop_value()?;
                let t = table_val.as_table().map_err(VmError::from)?;
                self.do_rawset(&t, key, value)?;
            }

            Instruction::GetField(idx) => {
                self.gas.charge(gas_cost::TABLE_GET)?;
                let frame = self.frames.last().unwrap();
                let proto = &program.prototypes[frame.proto_idx];
                let key = constant_to_string_key(&proto.constants[idx as usize])?;
                let raw_table_val = self.pop_value()?;
                // Resolve sentinel strings to their module table from globals.
                let table_val = self.resolve_sentinel(raw_table_val);
                let t = table_val.as_table().map_err(VmError::from)?;
                let result = t.borrow().get(&key).cloned().unwrap_or(LuaValue::Nil);
                self.stack.push(StackSlot::Value(result));
            }

            Instruction::SetField(idx) => {
                let value = self.pop_value()?;
                let frame = self.frames.last().unwrap();
                let proto = &program.prototypes[frame.proto_idx];
                let key = constant_to_string_key(&proto.constants[idx as usize])?;
                let table_val = self.pop_value()?;
                let t = table_val.as_table().map_err(VmError::from)?;
                self.do_rawset(&t, key, value)?;
            }

            Instruction::Add => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let r = a.lua_add(&b).map_err(VmError::from)?;
                self.stack.push(StackSlot::Value(r));
            }

            Instruction::Sub => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let r = a.lua_sub(&b).map_err(VmError::from)?;
                self.stack.push(StackSlot::Value(r));
            }

            Instruction::Mul => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let r = a.lua_mul(&b).map_err(VmError::from)?;
                self.stack.push(StackSlot::Value(r));
            }

            Instruction::IDiv => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let r = a.lua_idiv(&b).map_err(VmError::from)?;
                self.stack.push(StackSlot::Value(r));
            }

            Instruction::Mod => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let r = a.lua_mod(&b).map_err(VmError::from)?;
                self.stack.push(StackSlot::Value(r));
            }

            Instruction::Neg => {
                let a = self.pop_value()?;
                let r = a.lua_unm().map_err(VmError::from)?;
                self.stack.push(StackSlot::Value(r));
            }

            Instruction::Eq => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                self.stack.push(StackSlot::Value(LuaValue::Boolean(a == b)));
            }

            Instruction::Ne => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                self.stack.push(StackSlot::Value(LuaValue::Boolean(a != b)));
            }

            Instruction::Lt => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let ord = a.lua_cmp(&b).map_err(VmError::from)?;
                self.stack
                    .push(StackSlot::Value(LuaValue::Boolean(ord.is_lt())));
            }

            Instruction::Le => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let ord = a.lua_cmp(&b).map_err(VmError::from)?;
                self.stack
                    .push(StackSlot::Value(LuaValue::Boolean(ord.is_le())));
            }

            Instruction::Gt => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let ord = a.lua_cmp(&b).map_err(VmError::from)?;
                self.stack
                    .push(StackSlot::Value(LuaValue::Boolean(ord.is_gt())));
            }

            Instruction::Ge => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let ord = a.lua_cmp(&b).map_err(VmError::from)?;
                self.stack
                    .push(StackSlot::Value(LuaValue::Boolean(ord.is_ge())));
            }

            Instruction::Not => {
                let a = self.pop_value()?;
                self.stack
                    .push(StackSlot::Value(LuaValue::Boolean(!a.is_truthy())));
            }

            Instruction::And(offset) => {
                // Short-circuit: if top is falsy, jump past RHS (leave falsy
                // on stack as the result).  If truthy, fall through — the
                // compiler emits a Pop to discard the LHS before evaluating
                // the RHS.
                let top = self
                    .stack
                    .last()
                    .ok_or_else(stack_underflow)?
                    .as_value()?
                    .clone();
                if !top.is_truthy() {
                    self.jump_by(offset);
                }
            }

            Instruction::Or(offset) => {
                // Short-circuit: if top is truthy, jump past RHS (leave truthy
                // on stack as the result).  If falsy, fall through — the
                // compiler emits a Pop to discard the LHS before evaluating
                // the RHS.
                let top = self
                    .stack
                    .last()
                    .ok_or_else(stack_underflow)?
                    .as_value()?
                    .clone();
                if top.is_truthy() {
                    self.jump_by(offset);
                }
            }

            Instruction::Concat(n) => {
                let n = n as usize;
                // Pop n values.
                let mut parts = Vec::with_capacity(n);
                for _ in 0..n {
                    parts.push(self.pop_value()?);
                }
                parts.reverse();
                // Fold left-to-right.
                let mut acc = parts[0].clone();
                for part in &parts[1..] {
                    acc = acc.lua_concat(part).map_err(VmError::from)?;
                }
                let result_len = match &acc {
                    LuaValue::String(s) => s.len(),
                    _ => 0,
                };
                // gas: len(result)
                self.gas.charge(result_len as u64)?;
                self.mem.track_alloc(alloc_size::string(result_len))?;
                self.stack.push(StackSlot::Value(acc));
            }

            Instruction::Len => {
                self.gas.charge(gas_cost::LEN)?;
                let a = self.pop_value()?;
                let r = a.lua_len().map_err(VmError::from)?;
                self.stack.push(StackSlot::Value(r));
            }

            Instruction::Jmp(offset) => {
                self.jump_by(offset);
            }

            Instruction::JmpIf(offset) => {
                let val = self.pop_value()?;
                if val.is_truthy() {
                    self.jump_by(offset);
                }
            }

            Instruction::JmpIfNot(offset) => {
                let val = self.pop_value()?;
                if !val.is_truthy() {
                    self.jump_by(offset);
                }
            }

            Instruction::Call(argc) => {
                self.gas.charge(gas_cost::FUNCTION_CALL)?;

                if self.frames.len() >= self.config.max_call_depth {
                    return Err(VmError::CallDepthExceeded);
                }

                // Stack layout before Call(argc):
                //   [... func, arg0, arg1, ..., arg(argc-1)]
                // Pop args first (last pushed = last arg).
                let mut args: Vec<LuaValue> = Vec::with_capacity(argc as usize);
                for _ in 0..argc {
                    args.push(self.pop_value()?);
                }
                args.reverse();
                let raw_func = self.pop_value()?;

                // Resolve sentinel string globals (e.g. __tostring → Builtin).
                let func_val = self.resolve_sentinel(raw_func);

                match func_val {
                    LuaValue::Builtin(BuiltinId::TableSort) => {
                        // Special case: table.sort needs re-entrant dispatch.
                        self.do_table_sort(program, &args)?;
                        // table.sort returns nil; push so the statement-level Pop works.
                        self.stack.push(StackSlot::Value(LuaValue::Nil));
                    }
                    LuaValue::Builtin(id) => {
                        let results = builtins::call_builtin(
                            id,
                            &args,
                            &mut self.gas,
                            &mut self.mem,
                            &mut self.logs,
                        )?;
                        // Always push exactly one value (nil if empty, first if multiple).
                        let ret = results.into_iter().next().unwrap_or(LuaValue::Nil);
                        self.stack.push(StackSlot::Value(ret));
                    }
                    LuaValue::Function(closure) => {
                        self.push_call_frame(program, closure, args, 1)?;
                    }
                    other => {
                        return Err(VmError::TypeError(format!(
                            "attempt to call a {} value",
                            other.type_name()
                        )));
                    }
                }
            }

            Instruction::Ret(n) => {
                self.gas.charge(gas_cost::FUNCTION_RETURN)?;
                match self.do_return(n as usize) {
                    Ok(Some(v)) => return Ok(Some(v)),
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }
            }

            Instruction::Closure(proto_idx) => {
                let proto = &program.prototypes[proto_idx as usize];
                let upvalue_count = proto.upvalue_count;
                self.mem.track_alloc(alloc_size::closure(upvalue_count))?;

                let upvalue_descs = proto.upvalues.clone();
                let mut upvalues = Vec::with_capacity(upvalue_descs.len());
                for desc in upvalue_descs {
                    match desc {
                        UpvalueDesc::Local(slot) => {
                            let base = self.frames.last().unwrap().base;
                            let stack_idx = base + slot as usize;
                            // If this slot is already shared (captured before), reuse its cell.
                            // Otherwise, convert it to a Shared slot so future StoreLocal
                            // writes through the cell and the closure sees the updated value.
                            let cell = match &self.stack[stack_idx] {
                                StackSlot::Shared(existing) => existing.clone(),
                                StackSlot::Value(v) => {
                                    let c = Rc::new(RefCell::new(v.clone()));
                                    self.stack[stack_idx] = StackSlot::Shared(c.clone());
                                    c
                                }
                                StackSlot::IterHandle(_) => {
                                    return Err(VmError::RuntimeError(LuaValue::String(
                                        LuaString::from_str(
                                            "cannot capture iterator handle as upvalue",
                                        ),
                                    )));
                                }
                            };
                            upvalues.push(UpvalueSlot(cell));
                        }
                        UpvalueDesc::Upvalue(idx) => {
                            let uv = self.frames.last().unwrap().upvalues[idx as usize].clone();
                            upvalues.push(uv);
                        }
                    }
                }

                let closure = LuaClosure {
                    proto_idx: proto_idx as usize,
                    upvalues: upvalues.iter().map(|u| u.0.clone()).collect(),
                };
                self.stack
                    .push(StackSlot::Value(LuaValue::Function(closure)));

                // Store upvalues back for LoadUp/StoreUp in the calling frame
                // Note: we don't need to do anything special because closures
                // capture by value at creation time per spec §8.4.
                // upvalues is dropped here; the closure owns its Rc copies.
                let _ = upvalues;
            }

            Instruction::PCall(argc) => {
                self.gas.charge(gas_cost::PCALL_SETUP)?;

                // Pop args and function.
                let mut args: Vec<LuaValue> = Vec::with_capacity(argc as usize);
                for _ in 0..argc {
                    args.push(self.pop_value()?);
                }
                args.reverse();
                let raw_pcall_func = self.pop_value()?;
                let func_val = self.resolve_sentinel(raw_pcall_func);

                // Save checkpoint.
                let checkpoint = PCallCheckpoint {
                    stack_len: self.stack.len(),
                    frame_len: self.frames.len(),
                };

                // Handle builtin callees directly (no frame push needed).
                match &func_val {
                    LuaValue::Builtin(BuiltinId::TableSort) => {
                        let result = self.do_table_sort(program, &args);
                        match result {
                            Ok(()) => {
                                self.stack.push(StackSlot::Value(LuaValue::Boolean(true)));
                                self.stack.push(StackSlot::Value(LuaValue::Nil));
                            }
                            Err(e) if e.is_unrecoverable() => return Err(e),
                            Err(e) => {
                                self.gas.charge(gas_cost::PCALL_UNWIND)?;
                                self.stack.truncate(checkpoint.stack_len);
                                self.frames.truncate(checkpoint.frame_len);
                                let err_val = error_to_lua_value(e);
                                self.stack.push(StackSlot::Value(LuaValue::Boolean(false)));
                                self.stack.push(StackSlot::Value(err_val));
                            }
                        }
                        return Ok(None);
                    }
                    LuaValue::Builtin(id) => {
                        let id = *id;
                        let result = builtins::call_builtin(
                            id,
                            &args,
                            &mut self.gas,
                            &mut self.mem,
                            &mut self.logs,
                        );
                        match result {
                            Ok(vals) => {
                                self.stack.push(StackSlot::Value(LuaValue::Boolean(true)));
                                let ret = vals.into_iter().next().unwrap_or(LuaValue::Nil);
                                self.stack.push(StackSlot::Value(ret));
                            }
                            Err(e) if e.is_unrecoverable() => return Err(e),
                            Err(e) => {
                                self.gas.charge(gas_cost::PCALL_UNWIND)?;
                                self.stack.truncate(checkpoint.stack_len);
                                self.frames.truncate(checkpoint.frame_len);
                                let err_val = error_to_lua_value(e);
                                self.stack.push(StackSlot::Value(LuaValue::Boolean(false)));
                                self.stack.push(StackSlot::Value(err_val));
                            }
                        }
                        return Ok(None);
                    }
                    _ => {}
                }

                let closure = match func_val.as_function() {
                    Ok(c) => c.clone(),
                    Err(e) => {
                        // Type error trying to call a non-function.
                        let vm_err = VmError::from(e);
                        self.stack.push(StackSlot::Value(LuaValue::Boolean(false)));
                        self.stack
                            .push(StackSlot::Value(error_to_lua_value(vm_err)));
                        return Ok(None);
                    }
                };

                if self.frames.len() >= self.config.max_call_depth {
                    self.stack.push(StackSlot::Value(LuaValue::Boolean(false)));
                    self.stack
                        .push(StackSlot::Value(LuaValue::String(LuaString::from_str(
                            "call depth exceeded",
                        ))));
                    return Ok(None);
                }

                self.push_call_frame(program, closure, args, 1)?;

                // Run the inner call to completion within this pcall.
                let result = self.run_inner(program);

                match result {
                    Ok(ret_val) => {
                        self.stack.push(StackSlot::Value(LuaValue::Boolean(true)));
                        self.stack.push(StackSlot::Value(ret_val));
                    }
                    Err(e) if e.is_unrecoverable() => return Err(e),
                    Err(e) => {
                        self.gas.charge(gas_cost::PCALL_UNWIND)?;
                        // Unwind stack and frames back to checkpoint.
                        self.stack.truncate(checkpoint.stack_len);
                        self.frames.truncate(checkpoint.frame_len);
                        let err_val = error_to_lua_value(e);
                        self.stack.push(StackSlot::Value(LuaValue::Boolean(false)));
                        self.stack.push(StackSlot::Value(err_val));
                    }
                }
            }

            Instruction::ToolCall => {
                let args_val = self.pop_value()?;
                let name_val = self.pop_value()?;

                let name = match &name_val {
                    LuaValue::String(s) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
                    _ => return Err(VmError::TypeError("tool name must be a string".into())),
                };
                let args_table = match args_val.as_table() {
                    Ok(t) => t,
                    Err(_) => return Err(VmError::TypeError("tool args must be a table".into())),
                };

                let resp_table = self.registry.call(
                    &name,
                    &args_table.borrow(),
                    &self.config,
                    &mut self.gas,
                    &mut self.transcript,
                )?;

                let t = Rc::new(RefCell::new(resp_table));
                self.stack.push(StackSlot::Value(LuaValue::Table(t)));
            }

            Instruction::Log => {
                let val = self.pop_value()?;
                let ls = val.to_lua_string();
                let msg = String::from_utf8_lossy(ls.as_bytes()).into_owned();
                self.gas.charge(gas_cost::LOG_BASE + msg.len() as u64)?;
                self.logs.push(msg);
            }

            Instruction::Error => {
                let val = self.pop_value()?;
                self.gas.charge(gas_cost::ERROR_RAISE)?;
                return Err(VmError::RuntimeError(val));
            }

            Instruction::IterInitSorted(offset) => {
                let table_val = self.pop_value()?;
                let t = table_val.as_table().map_err(VmError::from)?;
                let keys = t.borrow().sorted_keys();
                let n = keys.len();
                // Gas: n * ceil_log2(n + 1)
                let sort_gas = n as u64 * ceil_log2(n + 1);
                self.gas.charge(sort_gas)?;

                if n == 0 {
                    self.jump_by(offset);
                } else {
                    self.stack.push(StackSlot::IterHandle(IterHandle::Sorted {
                        keys,
                        index: 0,
                        table: t,
                    }));
                }
            }

            Instruction::IterInitArray(offset) => {
                let table_val = self.pop_value()?;
                let t = table_val.as_table().map_err(VmError::from)?;
                self.gas.charge(gas_cost::BASE_INSTRUCTION)?;
                // Check if array is empty: peek first element.
                let first = t.borrow().get(&LuaKey::Integer(1)).cloned();
                if first.is_none() {
                    self.jump_by(offset);
                } else {
                    self.stack.push(StackSlot::IterHandle(IterHandle::Array {
                        table: t,
                        index: 1,
                    }));
                }
            }

            Instruction::IterNext(offset) => {
                // Peek at top — must be an IterHandle.
                let top_is_iter = matches!(self.stack.last(), Some(StackSlot::IterHandle(_)));
                if !top_is_iter {
                    return Err(VmError::RuntimeError(LuaValue::String(
                        LuaString::from_str("IterNext: expected iterator handle on stack"),
                    )));
                }

                // We need to borrow the handle mutably but also push values.
                // Take the handle out, process, put it back.
                let handle = match self.stack.pop().unwrap() {
                    StackSlot::IterHandle(h) => h,
                    _ => unreachable!(),
                };

                match handle {
                    IterHandle::Sorted {
                        keys,
                        mut index,
                        table,
                    } => {
                        if index >= keys.len() {
                            // Exhausted: don't put handle back, jump.
                            self.jump_by(offset);
                        } else {
                            let key = keys[index].clone();
                            let lua_key = key.clone().into_key().map_err(VmError::from)?;
                            let value = table
                                .borrow()
                                .get(&lua_key)
                                .cloned()
                                .unwrap_or(LuaValue::Nil);
                            index += 1;
                            self.gas.charge(gas_cost::ITER_SORTED_STEP)?;
                            // Put handle back with updated index.
                            self.stack.push(StackSlot::IterHandle(IterHandle::Sorted {
                                keys,
                                index,
                                table,
                            }));
                            self.stack.push(StackSlot::Value(key));
                            self.stack.push(StackSlot::Value(value));
                        }
                    }
                    IterHandle::Array { table, index } => {
                        let value = table
                            .borrow()
                            .get(&LuaKey::Integer(index))
                            .cloned()
                            .unwrap_or(LuaValue::Nil);
                        if matches!(value, LuaValue::Nil) {
                            // Exhausted: don't put handle back, jump.
                            self.jump_by(offset);
                        } else {
                            self.gas.charge(gas_cost::ITER_ARRAY_STEP)?;
                            self.stack.push(StackSlot::IterHandle(IterHandle::Array {
                                table,
                                index: index + 1,
                            }));
                            self.stack.push(StackSlot::Value(LuaValue::Integer(index)));
                            self.stack.push(StackSlot::Value(value));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Set table with metered gas/memory.
    fn do_rawset(
        &mut self,
        t: &Rc<RefCell<LuaTable>>,
        key: LuaKey,
        value: LuaValue,
    ) -> Result<(), VmError> {
        let old_cap = t.borrow().capacity();
        let result = t
            .borrow_mut()
            .rawset_tracked(key, value)
            .map_err(VmError::from)?;

        match result {
            RawsetResult::Updated => {
                self.gas.charge(gas_cost::TABLE_SET_EXISTING)?;
            }
            RawsetResult::Inserted {
                grew,
                new_hash_capacity,
            } => {
                self.gas.charge(gas_cost::TABLE_SET_NEW_KEY)?;
                if grew {
                    // Gas: new_capacity (entries_after_rehash)
                    self.gas.charge(new_hash_capacity as u64)?;
                    // Memory: delta capacity * 40
                    let delta = new_hash_capacity.saturating_sub(old_cap) as u64;
                    self.mem
                        .track_alloc(delta * alloc_size::table_hash_slot())?;
                } else {
                    // Array slot inserted: charge array slot memory.
                    self.mem.track_alloc(alloc_size::table_array_slot())?;
                }
            }
        }
        Ok(())
    }

    /// Push a new call frame and populate locals from args.
    fn push_call_frame(
        &mut self,
        program: &CompiledProgram,
        closure: LuaClosure,
        args: Vec<LuaValue>,
        expected_returns: u8,
    ) -> Result<(), VmError> {
        let proto = &program.prototypes[closure.proto_idx];
        self.mem
            .track_alloc(alloc_size::stack_frame(proto.local_count))?;

        let base = self.stack.len();

        // Build upvalue slots from the closure's Rc cells.
        let upvalues: Vec<UpvalueSlot> = closure.upvalues.into_iter().map(UpvalueSlot).collect();

        let frame = CallFrame {
            proto_idx: closure.proto_idx,
            pc: 0,
            base,
            upvalues,
            expected_returns,
        };
        self.frames.push(frame);

        // Allocate local slots.
        for _ in 0..proto.local_count {
            self.stack.push(StackSlot::Value(LuaValue::Nil));
        }

        // Bind args to params.
        for (i, arg) in args.into_iter().enumerate() {
            if i < proto.param_count as usize && i < proto.local_count as usize {
                self.stack[base + i] = StackSlot::Value(arg);
            }
        }

        Ok(())
    }

    /// Handle Ret(n): collect return values, pop frame, push results to parent.
    /// Returns Ok(Some(v)) if this was the last frame (done), Ok(None) to continue.
    fn do_return(&mut self, n: usize) -> Result<Option<LuaValue>, VmError> {
        // Collect return values.
        let mut ret_vals: Vec<LuaValue> = Vec::with_capacity(n);
        for _ in 0..n {
            ret_vals.push(self.pop_value()?);
        }
        ret_vals.reverse();

        let ret_val = ret_vals.into_iter().next().unwrap_or(LuaValue::Nil);

        let frame = self.frames.pop().unwrap();

        // Pop all locals/operands for this frame.
        self.stack.truncate(frame.base);

        if self.frames.is_empty() {
            // Top-level return: done.
            return Ok(Some(ret_val));
        }

        // Push return value(s) onto parent frame's operand stack.
        if frame.expected_returns >= 1 {
            self.stack.push(StackSlot::Value(ret_val));
        }

        Ok(None)
    }

    /// Run the inner execution loop until the current frame (and any it calls)
    /// returns. Used by pcall to capture the result or error.
    fn run_inner(&mut self, program: &CompiledProgram) -> Result<LuaValue, VmError> {
        let target_frame_depth = self.frames.len() - 1; // depth to unwind to

        loop {
            let current_depth = self.frames.len();
            if current_depth <= target_frame_depth {
                // The pcall-ed function has returned — but this shouldn't happen
                // here because do_return would have left its return value on stack.
                break;
            }

            let proto_idx = self.frames.last().unwrap().proto_idx;
            let pc = self.frames.last().unwrap().pc;
            let code_len = program.prototypes[proto_idx].code.len();

            if pc >= code_len {
                match self.do_return(0)? {
                    Some(v) => return Ok(v),
                    None => {}
                }
                if self.frames.len() <= target_frame_depth {
                    break;
                }
                continue;
            }

            let instr = program.prototypes[proto_idx].code[pc].clone();
            self.frames.last_mut().unwrap().pc += 1;

            match self.dispatch(program, instr)? {
                Some(v) => return Ok(v),
                None => {}
            }

            if self.frames.len() <= target_frame_depth {
                break;
            }
        }

        // The inner call returned normally; its return value is on the stack.
        self.pop_value()
    }

    fn pop_value(&mut self) -> Result<LuaValue, VmError> {
        self.stack.pop().ok_or_else(stack_underflow)?.into_value()
    }

    fn jump_by(&mut self, offset: i16) {
        let frame = self.frames.last_mut().unwrap();
        frame.pc = (frame.pc as isize + offset as isize) as usize;
    }

    /// If `v` is a sentinel string like `__tostring`, look it up in the globals
    /// table and return the resolved value. Otherwise return `v` unchanged.
    fn resolve_sentinel(&self, v: LuaValue) -> LuaValue {
        if let LuaValue::String(ref s) = v {
            if s.as_bytes().starts_with(b"__") {
                let key = LuaKey::String(s.clone());
                if let Some(resolved) = self.globals.get(&key) {
                    return resolved.clone();
                }
            }
        }
        v
    }

    /// Perform `table.sort` with optional Lua comparator (re-entrant dispatch).
    /// `args[0]` = table, `args[1]` = optional comparator.
    fn do_table_sort(
        &mut self,
        program: &CompiledProgram,
        args: &[LuaValue],
    ) -> Result<(), VmError> {
        let t = match args.first() {
            Some(LuaValue::Table(t)) => Rc::clone(t),
            Some(other) => {
                return Err(VmError::TypeError(format!(
                    "table.sort: expected table, got {}",
                    other.type_name()
                )));
            }
            None => {
                return Err(VmError::RuntimeError(LuaValue::String(
                    LuaString::from_str("table.sort: missing table argument"),
                )));
            }
        };

        let comp = args.get(1).cloned();

        let n = t.borrow().length() as usize;
        if n <= 1 {
            return Ok(());
        }

        // Charge gas: n * ceil_log2(n + 1)
        let sort_gas = n as u64 * ceil_log2(n + 1);
        self.gas.charge(sort_gas)?;

        // Extract array.
        let mut arr: Vec<LuaValue> = (1..=n as i64)
            .map(|k| {
                t.borrow()
                    .get(&LuaKey::Integer(k))
                    .cloned()
                    .unwrap_or(LuaValue::Nil)
            })
            .collect();

        // Sort using the appropriate comparator.
        let result = match comp {
            None | Some(LuaValue::Nil) => {
                // Default: standard Lua ordering (integers / strings).
                self.merge_sort_default(&mut arr)
            }
            Some(comp_val) => {
                // Custom comparator: call back into the VM.
                self.merge_sort_with_comp(program, &mut arr, comp_val)
            }
        };
        result?;

        // Write back.
        for (i, v) in arr.into_iter().enumerate() {
            t.borrow_mut()
                .rawset(LuaKey::Integer((i + 1) as i64), v)
                .map_err(VmError::from)?;
        }

        Ok(())
    }

    fn merge_sort_default(&self, arr: &mut Vec<LuaValue>) -> Result<(), VmError> {
        let n = arr.len();
        if n <= 1 {
            return Ok(());
        }
        let mid = n / 2;
        let mut left = arr[..mid].to_vec();
        let mut right = arr[mid..].to_vec();
        self.merge_sort_default(&mut left)?;
        self.merge_sort_default(&mut right)?;
        let mut i = 0;
        let mut j = 0;
        let mut k = 0;
        while i < left.len() && j < right.len() {
            let less = match left[i].lua_cmp(&right[j]) {
                Ok(ord) => ord.is_lt(),
                Err(_) => {
                    return Err(VmError::TypeError(
                        "table.sort: cannot compare mixed types".into(),
                    ));
                }
            };
            if less {
                arr[k] = left[i].clone();
                i += 1;
            } else {
                arr[k] = right[j].clone();
                j += 1;
            }
            k += 1;
        }
        while i < left.len() {
            arr[k] = left[i].clone();
            i += 1;
            k += 1;
        }
        while j < right.len() {
            arr[k] = right[j].clone();
            j += 1;
            k += 1;
        }
        Ok(())
    }

    fn merge_sort_with_comp(
        &mut self,
        program: &CompiledProgram,
        arr: &mut Vec<LuaValue>,
        comp: LuaValue,
    ) -> Result<(), VmError> {
        let n = arr.len();
        if n <= 1 {
            return Ok(());
        }
        let mid = n / 2;
        let mut left = arr[..mid].to_vec();
        let mut right = arr[mid..].to_vec();
        self.merge_sort_with_comp(program, &mut left, comp.clone())?;
        self.merge_sort_with_comp(program, &mut right, comp.clone())?;
        let mut i = 0;
        let mut j = 0;
        let mut k = 0;
        while i < left.len() && j < right.len() {
            let less = self.call_comparator(program, &comp, &left[i], &right[j])?;
            if less {
                arr[k] = left[i].clone();
                i += 1;
            } else {
                arr[k] = right[j].clone();
                j += 1;
            }
            k += 1;
        }
        while i < left.len() {
            arr[k] = left[i].clone();
            i += 1;
            k += 1;
        }
        while j < right.len() {
            arr[k] = right[j].clone();
            j += 1;
            k += 1;
        }
        Ok(())
    }

    /// Call a Lua comparator function `comp(a, b)` and return whether `a < b`.
    fn call_comparator(
        &mut self,
        program: &CompiledProgram,
        comp: &LuaValue,
        a: &LuaValue,
        b: &LuaValue,
    ) -> Result<bool, VmError> {
        let closure = comp.as_function().map_err(VmError::from)?.clone();
        let args = vec![a.clone(), b.clone()];
        self.push_call_frame(program, closure, args, 1)?;
        let result = self.run_inner(program)?;
        Ok(result.is_truthy())
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn stack_underflow() -> VmError {
    VmError::RuntimeError(LuaValue::String(LuaString::from_str("stack underflow")))
}

fn constant_to_value(c: &Constant) -> LuaValue {
    match c {
        Constant::Nil => LuaValue::Nil,
        Constant::Boolean(b) => LuaValue::Boolean(*b),
        Constant::Integer(n) => LuaValue::Integer(*n),
        Constant::String(bytes) => LuaValue::String(LuaString::from_bytes(bytes)),
        Constant::Proto(_) => LuaValue::Nil, // Handled separately by Closure instruction.
    }
}

fn constant_to_string_key(c: &Constant) -> Result<LuaKey, VmError> {
    match c {
        Constant::String(bytes) => Ok(LuaKey::String(LuaString::from_bytes(bytes))),
        _ => Err(VmError::TypeError(
            "GetField/SetField key must be a string constant".into(),
        )),
    }
}

fn error_to_lua_value(e: VmError) -> LuaValue {
    match e {
        VmError::RuntimeError(v) => v,
        VmError::TypeError(s) => LuaValue::String(LuaString::from_str(&s)),
        VmError::ToolError(s) => LuaValue::String(LuaString::from_str(&s)),
        VmError::CallDepthExceeded => LuaValue::String(LuaString::from_str("call depth exceeded")),
        VmError::GasExhausted => LuaValue::String(LuaString::from_str("gas exhausted")),
        VmError::MemoryExhausted => LuaValue::String(LuaString::from_str("memory exhausted")),
        VmError::OutputExceeded => LuaValue::String(LuaString::from_str("output exceeded")),
        VmError::WithLine(_, inner) => error_to_lua_value(*inner),
    }
}

// ── LuaError → VmError conversion ─────────────────────────────────────────────

impl From<LuaError> for VmError {
    fn from(e: LuaError) -> Self {
        match e {
            LuaError::Type => VmError::TypeError("type error".into()),
            LuaError::Memory => VmError::MemoryExhausted,
            LuaError::Runtime => {
                VmError::RuntimeError(LuaValue::String(LuaString::from_str("runtime error")))
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bytecode,
        compiler::{self, proto::CompiledProgram},
        parser,
    };

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn make_vm() -> Vm<NoopHost> {
        Vm::new(VmConfig::default(), NoopHost)
    }

    fn strip_line_info(e: VmError) -> VmError {
        match e {
            VmError::WithLine(_, inner) => *inner,
            other => other,
        }
    }

    /// Parse → compile → verify → execute a Lua source string.
    fn compile_and_run(source: &str) -> Result<LuaValue, VmError> {
        compile_and_run_with_config(source, VmConfig::default())
    }

    fn compile_and_run_with_config(source: &str, config: VmConfig) -> Result<LuaValue, VmError> {
        let ast = parser::parse(source).map_err(|e| {
            VmError::RuntimeError(LuaValue::String(LuaString::from_str(&format!(
                "parse error: {:?}",
                e
            ))))
        })?;
        let program = compiler::compile(&ast).map_err(|e| {
            VmError::RuntimeError(LuaValue::String(LuaString::from_str(&format!(
                "compile error: {:?}",
                e
            ))))
        })?;
        bytecode::verify(&program).map_err(|e| {
            VmError::RuntimeError(LuaValue::String(LuaString::from_str(&format!(
                "verify error: {:?}",
                e
            ))))
        })?;
        let mut vm = Vm::new(config, NoopHost);
        let output = vm
            .execute(&program, LuaValue::Nil)
            .map_err(strip_line_info)?;
        Ok(output.return_value)
    }

    fn make_simple_program(instrs: Vec<Instruction>, constants: Vec<Constant>) -> CompiledProgram {
        use crate::compiler::proto::FunctionProto;
        let mut proto = FunctionProto::new(0);
        proto.code = instrs;
        proto.constants = constants;
        proto.local_count = 0;
        CompiledProgram {
            prototypes: vec![proto],
            program_hash: [0u8; 32],
        }
    }

    // ── Basic execution ───────────────────────────────────────────────────────

    #[test]
    fn exec_pushk_ret() {
        // PushK(0); Ret(1) with constant 42
        let program = make_simple_program(
            vec![Instruction::PushK(0), Instruction::Ret(1)],
            vec![Constant::Integer(42)],
        );
        let mut vm = make_vm();
        let out = vm.execute(&program, LuaValue::Nil).unwrap();
        assert_eq!(out.return_value, LuaValue::Integer(42));
    }

    #[test]
    fn exec_add() {
        let result = compile_and_run("return 3 + 4").unwrap();
        assert_eq!(result, LuaValue::Integer(7));
    }

    #[test]
    fn exec_sub() {
        let result = compile_and_run("return 10 - 3").unwrap();
        assert_eq!(result, LuaValue::Integer(7));
    }

    #[test]
    fn exec_newtable_len() {
        let result = compile_and_run("local t = {} return t").unwrap();
        assert!(matches!(result, LuaValue::Table(_)));
    }

    #[test]
    fn exec_settable_gettable() {
        let result = compile_and_run(
            r#"
            local t = {}
            t["x"] = 10
            return t["x"]
        "#,
        )
        .unwrap();
        assert_eq!(result, LuaValue::Integer(10));
    }

    #[test]
    fn exec_call_simple() {
        let result = compile_and_run(
            r#"
            local function add1(n)
                return n + 1
            end
            return add1(5)
        "#,
        )
        .unwrap();
        assert_eq!(result, LuaValue::Integer(6));
    }

    #[test]
    fn exec_ret0() {
        let result = compile_and_run("return").unwrap();
        assert_eq!(result, LuaValue::Nil);
    }

    #[test]
    fn exec_jmp_forward() {
        // Jump over an assignment, verify the un-overwritten value is returned.
        let result = compile_and_run(
            r#"
            local x = 5
            do
                -- use a do-block to skip to a local
                if true then
                else
                    x = 99
                end
            end
            return x
        "#,
        )
        .unwrap();
        assert_eq!(result, LuaValue::Integer(5));
    }

    #[test]
    fn exec_jmpifnot() {
        let result = compile_and_run(
            r#"
            local x = 99
            if false then
                x = 0
            end
            return x
        "#,
        )
        .unwrap();
        assert_eq!(result, LuaValue::Integer(99));
    }

    #[test]
    fn exec_closure_upvalue() {
        let result = compile_and_run(
            r#"
            local x = 42
            local function get_x()
                return x
            end
            return get_x()
        "#,
        )
        .unwrap();
        assert_eq!(result, LuaValue::Integer(42));
    }

    // ── Metering integration ──────────────────────────────────────────────────

    #[test]
    fn gas_exhausted_halts_execution() {
        let config = VmConfig {
            gas_limit: 5,
            ..VmConfig::default()
        };
        let result = compile_and_run_with_config(
            r#"
            local i = 0
            while true do
                i = i + 1
            end
            return i
        "#,
            config,
        );
        assert_eq!(result, Err(VmError::GasExhausted));
    }

    #[test]
    fn mem_exhausted_on_table_alloc() {
        let config = VmConfig {
            memory_limit_bytes: 1, // tiny
            ..VmConfig::default()
        };
        let result = compile_and_run_with_config("local t = {} return t", config);
        assert_eq!(result, Err(VmError::MemoryExhausted));
    }

    #[test]
    fn gas_charged_for_call() {
        // We verify call uses more gas than just the instructions in the body.
        let config = VmConfig {
            gas_limit: gas_cost::FUNCTION_CALL + gas_cost::FUNCTION_RETURN + 10,
            ..VmConfig::default()
        };
        // A simple function call: needs BASE_INSTRUCTION costs plus CALL + RET
        // This should pass with enough gas.
        let _result = compile_and_run_with_config(
            r#"
            local function f() return 1 end
            return f()
        "#,
            config,
        );
        // With that budget it should succeed or exhaust — we just check gas is charged.
        // The important thing: if we set gas_limit too low, we get GasExhausted.
        let config_too_low = VmConfig {
            gas_limit: gas_cost::FUNCTION_CALL - 1,
            ..VmConfig::default()
        };
        let result2 = compile_and_run_with_config(
            r#"local function f() return 1 end return f()"#,
            config_too_low,
        );
        assert_eq!(result2, Err(VmError::GasExhausted));
    }

    #[test]
    fn gas_charged_for_ret() {
        // A function with return costs FUNCTION_RETURN gas.
        // With gas_limit = FUNCTION_RETURN - 1 after base instructions, it fails.
        let config = VmConfig {
            gas_limit: 2, // very tight
            ..VmConfig::default()
        };
        let result = compile_and_run_with_config("return 1", config);
        // With gas_limit=2: PushK costs 1, Ret costs 1+5=6, should exhaust.
        assert_eq!(result, Err(VmError::GasExhausted));
    }

    #[test]
    fn gas_charged_for_concat() {
        // Concat(2) of "hello"+"world" = 10 chars, gas = 10 (len).
        let result = compile_and_run(r#"return "hello" .. "world""#).unwrap();
        assert_eq!(result, LuaValue::String(LuaString::from_str("helloworld")));
    }

    #[test]
    fn mem_charged_for_string_concat() {
        // Concat charges 24 + len bytes.
        // 24 + 10 = 34 bytes for "helloworld".
        let config = VmConfig {
            memory_limit_bytes: 30, // too small for "helloworld" (34 bytes)
            ..VmConfig::default()
        };
        let result = compile_and_run_with_config(r#"return "hello" .. "world""#, config);
        assert_eq!(result, Err(VmError::MemoryExhausted));
    }

    // ── pcall tests ───────────────────────────────────────────────────────────

    #[test]
    fn pcall_catches_type_error() {
        let result = compile_and_run(
            r#"
            local ok, err = pcall(function()
                local x = 1 + "hello"
                return x
            end)
            if ok then return 1 else return 0 end
        "#,
        )
        .unwrap();
        assert_eq!(result, LuaValue::Integer(0));
    }

    #[test]
    fn pcall_catches_runtime_error() {
        let result = compile_and_run(
            r#"
            local ok, err = pcall(function()
                error("boom")
            end)
            if ok then return "ok" else return err end
        "#,
        )
        .unwrap();
        assert_eq!(result, LuaValue::String(LuaString::from_str("boom")));
    }

    #[test]
    fn pcall_success_returns_true_result() {
        let result = compile_and_run(
            r#"
            local ok, val = pcall(function()
                return 42
            end)
            if ok then return val else return -1 end
        "#,
        )
        .unwrap();
        assert_eq!(result, LuaValue::Integer(42));
    }

    #[test]
    fn pcall_does_not_catch_gas_error() {
        let config = VmConfig {
            gas_limit: 50,
            ..VmConfig::default()
        };
        let result = compile_and_run_with_config(
            r#"
            local ok, err = pcall(function()
                local i = 0
                while true do i = i + 1 end
            end)
            return ok
        "#,
            config,
        );
        assert_eq!(result, Err(VmError::GasExhausted));
    }

    #[test]
    fn pcall_unwind_cleans_stack() {
        // After pcall catches an error, we can still compute normally.
        let result = compile_and_run(
            r#"
            local ok, err = pcall(function()
                error("oops")
            end)
            return 99
        "#,
        )
        .unwrap();
        assert_eq!(result, LuaValue::Integer(99));
    }

    // ── Iterator tests ────────────────────────────────────────────────────────

    #[test]
    fn iter_sorted_empty_table() {
        // pairs on empty table: body never executes.
        let result = compile_and_run(
            r#"
            local t = {}
            local count = 0
            for k, v in pairs(t) do
                count = count + 1
            end
            return count
        "#,
        );
        // pairs() is a stdlib builtin (Phase 7) - not available yet.
        // Test using IterInitSorted directly via a minimal bytecode program.
        // We test this at the bytecode level instead.
        let _ = result; // May fail due to no stdlib

        // Direct bytecode test for IterInitSorted on empty table.
        use crate::compiler::proto::FunctionProto;
        // Code: NewTable, IterInitSorted(+2), <unreachable body>, Ret(0), Ret(0)
        // offset +2 from IterInitSorted means jump past the body.
        let mut proto = FunctionProto::new(0);
        // IterInitSorted at pc=1: pc after dispatch = 2.
        // Empty table → jump_by(offset) → new_pc = 2 + offset.
        // We want to land at pc=4 (Ret(0)), so offset = 4-2 = 2.
        proto.code = vec![
            Instruction::NewTable,          // 0: push empty table
            Instruction::IterInitSorted(2), // 1: if empty → pc 2+2=4
            // body (unreachable for empty table):
            Instruction::PushK(0), // 2: unreachable
            Instruction::Ret(1),   // 3: unreachable
            Instruction::Ret(0),   // 4: done - return nil
        ];
        proto.constants = vec![Constant::Integer(999)];
        let program = CompiledProgram {
            prototypes: vec![proto],
            program_hash: [0u8; 32],
        };
        let mut vm = make_vm();
        let out = vm.execute(&program, LuaValue::Nil).unwrap();
        assert_eq!(out.return_value, LuaValue::Nil);
    }

    #[test]
    fn iter_sorted_two_entries() {
        // Build a table with keys "a" and "b", iterate via IterInitSorted/IterNext.
        // We verify keys come in sorted order by collecting them.
        use crate::compiler::proto::FunctionProto;
        // Program:
        // NewTable → t (local 0)
        // StoreLocal 0
        // PushK "a", PushK 1, GetTable... use SetField instead:
        //   LoadLocal 0, PushK 1, SetField("a")  → t.a = 1
        //   LoadLocal 0, PushK 2, SetField("b")  → t.b = 2
        // local sum = 0 (local 1)
        // LoadLocal 0
        // IterInitSorted(+N) → if empty jump
        // loop_start:
        //   IterNext(+M) → if done jump past loop
        //   value on top (v), below that key, below that handle
        //   Pop v, Pop k (ignore them), sum += 1
        //   Jmp(-back)
        // end:
        // LoadLocal 1, Ret(1)

        // Let's do a simpler test: iterate and sum values.
        // table = {a=10, b=20}, expect sum = 30.
        let mut proto = FunctionProto::new(0);
        proto.local_count = 3; // local 0 = table, local 1 = sum, local 2 = unused
        proto.constants = vec![
            Constant::String(b"a".to_vec()), // 0
            Constant::Integer(10),           // 1
            Constant::String(b"b".to_vec()), // 2
            Constant::Integer(20),           // 3
            Constant::Integer(0),            // 4 (initial sum)
        ];

        // Index layout:
        // 0: NewTable
        // 1: StoreLocal 0
        // 2: LoadLocal 0, PushK(1), SetField(0)  → t.a = 10
        //    [LoadLocal, PushK, SetField] = 3 instrs → 2,3,4
        // 5: LoadLocal 0, PushK(3), SetField(2)  → t.b = 20
        //    = 5,6,7
        // 8: PushK(4), StoreLocal 1  → sum = 0
        //    = 8,9
        // 10: LoadLocal 0
        // 11: IterInitSorted(offset to end)
        // 12 (loop_start): IterNext(offset to end)
        // 13: pop value (Add, whatever)
        //   We want: sum = sum + value
        //   Pop value into local 2? Let's do:
        //   Stack after IterNext: [handle, key, value]
        //   We want to add value to sum:
        //     LoadLocal 1  → [handle, key, value, sum]
        //     Add          → [handle, key, sum+value]  (value + sum)
        //     wait, Add pops two and pushes one
        //     Actually stack: [handle, key, value]
        //     We want value + sum:
        //     LoadLocal 1  → [handle, key, value, sum]  -- sum under value
        //     Hmm, let me rethink
        //   After IterNext: stack top is value, below key, below handle.
        //   We need: sum = sum + value
        //     LoadLocal 1      → [..., handle, key, value, sum]
        //     Add              → [..., handle, key, value+sum]  -- WRONG order but Add is commutative for integers
        //     StoreLocal 1     → [..., handle, key]
        //     Pop              → [..., handle]  (pop key)
        //     Jmp(-back to loop_start)
        // end (after loop):
        //   LoadLocal 1, Ret(1)

        // Let's count:
        // 0:  NewTable
        // 1:  StoreLocal(0)
        // 2:  LoadLocal(0)
        // 3:  PushK(1)         -- 10
        // 4:  SetField(0)      -- .a = 10
        // 5:  LoadLocal(0)
        // 6:  PushK(3)         -- 20
        // 7:  SetField(2)      -- .b = 20
        // 8:  PushK(4)         -- 0
        // 9:  StoreLocal(1)
        // 10: LoadLocal(0)
        // 11: IterInitSorted(+5)  -- if empty jump to 17
        // -- loop_start = 12
        // 12: IterNext(+5)         -- if done jump to 18
        //                          -- stack: handle, key, value
        // 13: LoadLocal(1)         -- stack: handle, key, value, sum
        // 14: Add                  -- stack: handle, key, value+sum
        // 15: StoreLocal(1)        -- stack: handle, key
        // 16: Pop                  -- stack: handle (pop key)
        // 17: Jmp(-6)             -- back to IterNext at 12? offset from pc=18 → 18 + (-6) = 12 ✓
        //                          -- pc after Jmp is 18 (Jmp is at 17, pc increments to 18)
        //                          -- offset = 12 - 18 = -6
        // 18: LoadLocal(1)
        // 19: Ret(1)

        proto.code = vec![
            Instruction::NewTable,          // 0
            Instruction::StoreLocal(0),     // 1
            Instruction::LoadLocal(0),      // 2
            Instruction::PushK(1),          // 3 (10)
            Instruction::SetField(0),       // 4 (.a)
            Instruction::LoadLocal(0),      // 5
            Instruction::PushK(3),          // 6 (20)
            Instruction::SetField(2),       // 7 (.b)
            Instruction::PushK(4),          // 8 (0)
            Instruction::StoreLocal(1),     // 9
            Instruction::LoadLocal(0),      // 10
            Instruction::IterInitSorted(6), // 11: if empty, jump to 18
            // loop_start = 12
            Instruction::IterNext(5), // 12: if done, jump to 18
            //     pc after = 13, target = 13+5 = 18 ✓
            Instruction::LoadLocal(1),  // 13
            Instruction::Add,           // 14  (value + sum)
            Instruction::StoreLocal(1), // 15
            Instruction::Pop,           // 16 (pop key)
            Instruction::Jmp(-6),       // 17: pc after = 18, target = 18-6 = 12 ✓
            Instruction::LoadLocal(1),  // 18
            Instruction::Ret(1),        // 19
        ];

        let program = CompiledProgram {
            prototypes: vec![proto],
            program_hash: [0u8; 32],
        };
        let mut vm = make_vm();
        let out = vm.execute(&program, LuaValue::Nil).unwrap();
        assert_eq!(out.return_value, LuaValue::Integer(30));
    }

    #[test]
    fn iter_array_basic() {
        // table {10, 20, 30} → sum = 60
        use crate::compiler::proto::FunctionProto;

        let mut proto = FunctionProto::new(0);
        proto.local_count = 2; // local 0 = table, local 1 = sum
        proto.constants = vec![
            Constant::Integer(10), // 0
            Constant::Integer(20), // 1
            Constant::Integer(30), // 2
            Constant::Integer(0),  // 3 (initial sum)
        ];

        // 0:  NewTable
        // 1:  StoreLocal(0)
        // 2:  LoadLocal(0), PushK(0), PushK(-array-key=1)...
        //     Wait, SetTable needs: table, key, value on stack
        //     But SetTable pops value, key, table in that order (value first).
        //     Actually looking at dispatch: pop value, pop key, pop table_val.
        //     So push order: table first (deepest), then key, then value.
        //     Actually for SetTable, looking at the code:
        //       let value = self.pop_value()?;     <- top of stack
        //       let key = self.pop_value()?        <- next
        //       let table_val = self.pop_value()?  <- bottom
        //     So push order: table, key, value (table deepest).
        //
        // Let's use dup to keep table on stack:
        // Actually simpler: use LoadLocal(0) before each set.
        // t[1] = 10: LoadLocal(0), PushK(int 1), PushK(10)... but SetTable needs key as LuaValue
        // Actually the key needs to be a LuaValue that can become LuaKey.
        // PushK(0) = Integer(10) - but we need integer 1 as key.
        // Let me add Integer(1), Integer(2), Integer(3) as constants.

        proto.constants = vec![
            Constant::Integer(1),  // 0 - key 1
            Constant::Integer(10), // 1 - value 10
            Constant::Integer(2),  // 2 - key 2
            Constant::Integer(20), // 3 - value 20
            Constant::Integer(3),  // 4 - key 3
            Constant::Integer(30), // 5 - value 30
            Constant::Integer(0),  // 6 - initial sum
        ];

        // 0:  NewTable
        // 1:  StoreLocal(0)
        // 2:  LoadLocal(0), PushK(0), PushK(1), SetTable  → t[1]=10
        // 6:  LoadLocal(0), PushK(2), PushK(3), SetTable  → t[2]=20
        // 10: LoadLocal(0), PushK(4), PushK(5), SetTable  → t[3]=30
        // 14: PushK(6), StoreLocal(1)  → sum=0
        // 16: LoadLocal(0)
        // 17: IterInitArray(+5)  → if empty jump to 23
        // -- loop_start = 18
        // 18: IterNext(+4)       → if done jump to 23; pc after=19, target=19+4=23 ✓
        //                          stack: handle, key(int), value
        // 19: LoadLocal(1)
        // 20: Add
        // 21: StoreLocal(1)
        // 22: Pop                -- pop key
        // 23: Hmm we need to go back to 18.
        //     Actually let's put Jmp before the end label.
        //
        // Let me recount:
        // 18: IterNext(+4)   pc after=19, jump to 19+4=23
        // 19: LoadLocal(1)
        // 20: Add
        // 21: StoreLocal(1)
        // 22: Pop
        // 23: Jmp? No wait - after Pop we need to jump back to IterNext.
        //     Jmp at 23: pc after = 24, target = 18 → offset = 18-24 = -6
        // 23: Jmp(-6)    target = 24-6 = 18 ✓
        // 24: LoadLocal(1)
        // 25: Ret(1)

        // IterNext at 18, when done jumps to 19+4=23? But 23 is Jmp(-6) going back to 18 forever!
        // We need IterNext to jump to 24 (after the Jmp).
        // IterNext at 18: pc after=19, offset=+5 → target=19+5=24 ✓
        // Pop at 22, Jmp(-5) at 23: pc after=24, target=24-6=18? Let me recount.

        // 18: IterNext(+5)   pc after=19, jump to 19+5=24 (end)
        // 19: LoadLocal(1)
        // 20: Add
        // 21: StoreLocal(1)
        // 22: Pop
        // 23: Jmp(-6)       pc after=24, target=24-6=18 ✓
        // 24: LoadLocal(1)
        // 25: Ret(1)

        // IterInitArray at 17: pc after=18, offset to jump to 24 → +6
        // 17: IterInitArray(+6)  pc after=18, target=18+6=24 ✓

        proto.code = vec![
            Instruction::NewTable,         // 0
            Instruction::StoreLocal(0),    // 1
            Instruction::LoadLocal(0),     // 2
            Instruction::PushK(0),         // 3 (key 1)
            Instruction::PushK(1),         // 4 (val 10)
            Instruction::SetTable,         // 5
            Instruction::LoadLocal(0),     // 6
            Instruction::PushK(2),         // 7 (key 2)
            Instruction::PushK(3),         // 8 (val 20)
            Instruction::SetTable,         // 9
            Instruction::LoadLocal(0),     // 10
            Instruction::PushK(4),         // 11 (key 3)
            Instruction::PushK(5),         // 12 (val 30)
            Instruction::SetTable,         // 13
            Instruction::PushK(6),         // 14 (sum=0)
            Instruction::StoreLocal(1),    // 15
            Instruction::LoadLocal(0),     // 16
            Instruction::IterInitArray(7), // 17: if empty → 18+7=25; pc after=18
            // loop_start = 18
            Instruction::IterNext(6), // 18: if done → 19+6=25; pc after=19
            //     stack: handle, index, value
            Instruction::LoadLocal(1),  // 19
            Instruction::Add,           // 20
            Instruction::StoreLocal(1), // 21
            Instruction::Pop,           // 22 (pop index key)
            Instruction::Jmp(-6),       // 23: pc after=24, target=24-6=18 ✓
            // Hmm: Jmp(-6) at pc=23, pc after Jmp = 24, target = 24 + (-6) = 18. ✓
            // But IterNext at pc=18 jumps to 19+6=25 when done.
            // IterInitArray at pc=17 jumps to 18+7=25 if empty.
            Instruction::LoadLocal(1), // 24
            Instruction::Ret(1),       // 25 -- unreachable if we jump to 25 which is this.
                                       // Wait: jump targets 25 but code has index 24 and 25.
                                       // Let me re-examine: IterNext done → jump to index 25.
                                       // But LoadLocal(1) is at index 24, Ret(1) at 25.
                                       // We want to jump to 24, not 25!
        ];
        // Fix: IterNext offset should be 24-19 = 5, IterInitArray offset = 24-18 = 6.
        proto.code[17] = Instruction::IterInitArray(6); // pc after=18, target=18+6=24 ✓
        proto.code[18] = Instruction::IterNext(5); // pc after=19, target=19+5=24 ✓
        // Fix Jmp: pc=23, pc after=24, target=18 → offset = 18-24 = -6 ✓ (already correct)

        let program = CompiledProgram {
            prototypes: vec![proto],
            program_hash: [0u8; 32],
        };
        let mut vm = make_vm();
        let out = vm.execute(&program, LuaValue::Nil).unwrap();
        assert_eq!(out.return_value, LuaValue::Integer(60));
    }

    #[test]
    fn iter_array_stops_at_nil() {
        // table: t[1]=10, t[3]=30 (gap at 2) → ipairs-style stops at nil, yields only (1,10).
        use crate::compiler::proto::FunctionProto;

        let mut proto = FunctionProto::new(0);
        proto.local_count = 2;
        proto.constants = vec![
            Constant::Integer(1),  // 0 - key 1
            Constant::Integer(10), // 1 - value 10
            Constant::Integer(3),  // 2 - key 3
            Constant::Integer(30), // 3 - value 30
            Constant::Integer(0),  // 4 - sum init
        ];

        // Similar to iter_array_basic but only t[1] and t[3] set (gap at 2).
        proto.code = vec![
            Instruction::NewTable,         // 0
            Instruction::StoreLocal(0),    // 1
            Instruction::LoadLocal(0),     // 2
            Instruction::PushK(0),         // 3 (key 1)
            Instruction::PushK(1),         // 4 (val 10)
            Instruction::SetTable,         // 5
            Instruction::LoadLocal(0),     // 6
            Instruction::PushK(2),         // 7 (key 3)
            Instruction::PushK(3),         // 8 (val 30)
            Instruction::SetTable,         // 9
            Instruction::PushK(4),         // 10 (sum=0)
            Instruction::StoreLocal(1),    // 11
            Instruction::LoadLocal(0),     // 12
            Instruction::IterInitArray(6), // 13: pc after=14, empty → 14+6=20
            // loop = 14
            Instruction::IterNext(5),   // 14: pc after=15, done → 15+5=20
            Instruction::LoadLocal(1),  // 15
            Instruction::Add,           // 16
            Instruction::StoreLocal(1), // 17
            Instruction::Pop,           // 18 (pop key)
            Instruction::Jmp(-6),       // 19: pc after=20, target=20-6=14 ✓
            Instruction::LoadLocal(1),  // 20
            Instruction::Ret(1),        // 21
        ];

        let program = CompiledProgram {
            prototypes: vec![proto],
            program_hash: [0u8; 32],
        };
        let mut vm = make_vm();
        let out = vm.execute(&program, LuaValue::Nil).unwrap();
        // Should only sum 10 (t[2] is nil, stops).
        assert_eq!(out.return_value, LuaValue::Integer(10));
    }

    #[test]
    fn iter_gas_sorted_setup() {
        // IterInitSorted on 4-entry table charges n*ceil_log2(n+1) = 4*ceil_log2(5) = 4*3 = 12 gas.
        use crate::compiler::proto::FunctionProto;

        let mut proto = FunctionProto::new(0);
        proto.local_count = 1;
        proto.constants = vec![
            Constant::String(b"a".to_vec()), // 0
            Constant::Integer(1),            // 1
            Constant::String(b"b".to_vec()), // 2
            Constant::Integer(2),            // 3
            Constant::String(b"c".to_vec()), // 4
            Constant::Integer(3),            // 5
            Constant::String(b"d".to_vec()), // 6
            Constant::Integer(4),            // 7
        ];

        proto.code = vec![
            Instruction::NewTable,      // 0
            Instruction::StoreLocal(0), // 1
            Instruction::LoadLocal(0),
            Instruction::PushK(1),
            Instruction::SetField(0), // 2,3,4
            Instruction::LoadLocal(0),
            Instruction::PushK(3),
            Instruction::SetField(2), // 5,6,7
            Instruction::LoadLocal(0),
            Instruction::PushK(5),
            Instruction::SetField(4), // 8,9,10
            Instruction::LoadLocal(0),
            Instruction::PushK(7),
            Instruction::SetField(6),       // 11,12,13
            Instruction::LoadLocal(0),      // 14
            Instruction::IterInitSorted(1), // 15: if empty jump to 17
            // loop body (iterate once then handle exits)
            Instruction::IterNext(2), // 16: done → jump to 19
            Instruction::Pop,         // 17: pop value
            Instruction::Pop,         // 18: pop key  (then back to 16)
            // Hmm, we need a Jmp back after Pop
            // Let me fix: done → 17+2=19? pc after IterNext=17, target=17+2=19? No pc after 16 = 17.
            // IterNext at 16: pc after = 17, done → 17 + offset.
            // We want done to jump to end (say 20).
            // IterNext(+3): done → 17+3=20
            // body: Pop(value), Pop(key), Jmp(-4): pc after=20, target=20-4=16
            // 19: Jmp(-4): pc after=20, 20-4=16 ✓
            // 20: Ret(0)
            Instruction::Ret(0), // 19 placeholder
        ];

        // Rebuild properly:
        proto.code = vec![
            Instruction::NewTable,          // 0
            Instruction::StoreLocal(0),     // 1
            Instruction::LoadLocal(0),      // 2
            Instruction::PushK(1),          // 3
            Instruction::SetField(0),       // 4  t.a=1
            Instruction::LoadLocal(0),      // 5
            Instruction::PushK(3),          // 6
            Instruction::SetField(2),       // 7  t.b=2
            Instruction::LoadLocal(0),      // 8
            Instruction::PushK(5),          // 9
            Instruction::SetField(4),       // 10 t.c=3
            Instruction::LoadLocal(0),      // 11
            Instruction::PushK(7),          // 12
            Instruction::SetField(6),       // 13 t.d=4
            Instruction::LoadLocal(0),      // 14
            Instruction::IterInitSorted(5), // 15: pc after=16, empty→16+5=21
            // loop = 16
            Instruction::IterNext(4), // 16: pc after=17, done→17+4=21
            Instruction::Pop,         // 17 pop value
            Instruction::Pop,         // 18 pop key
            Instruction::Jmp(-4),     // 19: pc after=20, target=20-4=16 ✓
            Instruction::Nop,         // 20 padding
            Instruction::Ret(0),      // 21
        ];

        let program = CompiledProgram {
            prototypes: vec![proto],
            program_hash: [0u8; 32],
        };
        let mut vm = make_vm();
        let out = vm.execute(&program, LuaValue::Nil).unwrap();
        // n=4, ceil_log2(5)=3, sort_gas = 4*3 = 12
        // Total gas > 12 (includes all the base instruction costs).
        // Just verify it ran successfully and gas was consumed.
        assert!(out.gas_used > 12, "expected gas > 12, got {}", out.gas_used);
        assert_eq!(out.return_value, LuaValue::Nil);
    }
}

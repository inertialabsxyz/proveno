#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use super::error::CompileError;
use super::proto::{Constant, FunctionProto, Instruction, UpvalueDesc};
use crate::parser::ast::{
    AssignTarget, BinOpKind, Block, Call, Expr, FuncBody, FuncName, GenericFor, IfStmt, LocalDecl,
    MethodCall, NumericFor, ReturnStmt, Stmt, TableField, UnOpKind, WhileStmt,
};

// ---------------------------------------------------------------------------
// Internal scope types
// ---------------------------------------------------------------------------

struct LocalVar {
    name: String,
    slot: u8,
}

struct FunctionScope {
    proto: FunctionProto,
    /// Stack of block-level local variable lists (innermost last).
    blocks: Vec<Vec<LocalVar>>,
    /// Upvalue capture list: (name, descriptor).
    upvalues: Vec<(String, UpvalueDesc)>,
    /// The next free local slot.
    next_slot: u8,
    /// High-water mark for local slot usage.
    max_locals: u8,
    /// Break patch points per loop nesting level.
    /// Each entry is (extra_pops, patch_indices): extra_pops is the number of
    /// Pop instructions to emit before the break jump (1 for generic-for loops
    /// to clean up the iterator handle, 0 for while/numeric-for).
    break_patches: Vec<(usize, Vec<usize>)>,
}

impl FunctionScope {
    fn new(param_count: u8) -> Self {
        FunctionScope {
            proto: FunctionProto::new(param_count),
            blocks: Vec::new(),
            upvalues: Vec::new(),
            next_slot: param_count, // params occupy the first slots
            max_locals: param_count,
            break_patches: Vec::new(),
        }
    }
}

/// How a name resolves inside the current function.
enum VarRef {
    Local(u8),
    Upvalue(u8),
    Global,
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

pub struct Compiler {
    /// Function scope stack, innermost last.
    scopes: Vec<FunctionScope>,
    /// Accumulated prototype list (index 0 = top-level chunk after `compile`).
    pub prototypes: Vec<FunctionProto>,
}

impl Compiler {
    pub fn compile(block: &Block) -> Result<super::proto::CompiledProgram, CompileError> {
        let mut c = Compiler {
            scopes: vec![],
            prototypes: vec![],
        };
        // Reserve slot 0 for the top-level chunk; nested functions will occupy 1..N.
        c.prototypes.push(FunctionProto::new(0)); // placeholder
        c.enter_function(0);
        c.compile_block(block)?;
        // Always emit a trailing Ret(0) at the top level.
        let line = block.span.line;
        c.emit(Instruction::Ret(0), line);
        let proto = c.exit_function();
        // Overwrite the placeholder at index 0.
        c.prototypes[0] = proto;
        let program_hash = crate::noir::encoder::compute_program_hash(&c.prototypes);
        Ok(super::proto::CompiledProgram {
            prototypes: c.prototypes,
            program_hash,
        })
    }

    // -----------------------------------------------------------------------
    // Scope management
    // -----------------------------------------------------------------------

    fn enter_function(&mut self, param_count: u8) {
        self.scopes.push(FunctionScope::new(param_count));
        // Push an initial block for parameters.
        self.current_scope_mut().blocks.push(Vec::new());
    }

    /// Register a parameter name at a fixed slot (0..param_count) without
    /// advancing `next_slot`. Used by `compile_function_body`.
    fn register_param(&mut self, name: &str, slot: u8) {
        let scope = self.current_scope_mut();
        let block = scope.blocks.last_mut().expect("no block");
        block.push(LocalVar {
            name: name.to_string(),
            slot,
        });
    }

    fn exit_function(&mut self) -> FunctionProto {
        let mut scope = self.scopes.pop().expect("exit_function: no scope");
        scope.proto.local_count = scope.max_locals;
        scope.proto.upvalue_count = scope.upvalues.len() as u8;
        scope.proto.upvalues = scope.upvalues.into_iter().map(|(_, d)| d).collect();
        scope.proto
    }

    fn current_scope(&self) -> &FunctionScope {
        self.scopes.last().expect("no function scope")
    }

    fn current_scope_mut(&mut self) -> &mut FunctionScope {
        self.scopes.last_mut().expect("no function scope")
    }

    fn enter_block(&mut self) {
        self.current_scope_mut().blocks.push(Vec::new());
    }

    fn exit_block(&mut self) {
        let scope = self.current_scope_mut();
        if let Some(block) = scope.blocks.pop() {
            let freed = block.len() as u8;
            scope.next_slot = scope.next_slot.saturating_sub(freed);
        }
    }

    fn declare_local(&mut self, name: &str, line: u32) -> Result<u8, CompileError> {
        let scope = self.current_scope_mut();
        if scope.next_slot >= 200 {
            return Err(CompileError::TooManyLocals { line });
        }
        let slot = scope.next_slot;
        scope.next_slot += 1;
        if scope.next_slot > scope.max_locals {
            scope.max_locals = scope.next_slot;
        }
        let block = scope.blocks.last_mut().expect("no block");
        block.push(LocalVar {
            name: name.to_string(),
            slot,
        });
        Ok(slot)
    }

    /// Allocate a temporary slot above current next_slot (not visible as a named local).
    fn alloc_temp_slot(&mut self) -> u8 {
        let scope = self.current_scope_mut();
        let slot = scope.next_slot;
        scope.next_slot += 1;
        if scope.next_slot > scope.max_locals {
            scope.max_locals = scope.next_slot;
        }
        slot
    }

    fn free_temp_slot(&mut self) {
        let scope = self.current_scope_mut();
        if scope.next_slot > 0 {
            scope.next_slot -= 1;
        }
    }

    fn push_break_scope(&mut self, extra_pops: usize) {
        self.current_scope_mut()
            .break_patches
            .push((extra_pops, Vec::new()));
    }

    fn pop_break_scope(&mut self) -> Vec<usize> {
        self.current_scope_mut()
            .break_patches
            .pop()
            .map(|(_, patches)| patches)
            .unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // Variable resolution
    // -----------------------------------------------------------------------

    fn resolve_var(&mut self, name: &str) -> VarRef {
        // 1. Search current function's blocks (innermost first).
        let depth = self.scopes.len();
        {
            let scope = &self.scopes[depth - 1];
            for block in scope.blocks.iter().rev() {
                for local in block.iter().rev() {
                    if local.name == name {
                        return VarRef::Local(local.slot);
                    }
                }
            }
            // Also check already-registered upvalues in this scope.
            for (i, (uname, _)) in scope.upvalues.iter().enumerate() {
                if uname == name {
                    return VarRef::Upvalue(i as u8);
                }
            }
        }

        // 2. Search enclosing functions.
        if depth >= 2 {
            let upval_desc = self.find_upvalue_in_enclosing(name, depth - 2);
            if let Some(desc) = upval_desc {
                let scope = &mut self.scopes[depth - 1];
                let idx = scope.upvalues.len() as u8;
                scope.upvalues.push((name.to_string(), desc));
                return VarRef::Upvalue(idx);
            }
        }

        VarRef::Global
    }

    /// Recursively find `name` in enclosing scope at `scope_idx`, creating
    /// upvalue descriptors as we go.  Returns the `UpvalueDesc` to use in
    /// the *calling* function (one level deeper than `scope_idx`).
    fn find_upvalue_in_enclosing(&mut self, name: &str, scope_idx: usize) -> Option<UpvalueDesc> {
        // Check locals of scope at scope_idx.
        {
            let scope = &self.scopes[scope_idx];
            for block in scope.blocks.iter().rev() {
                for local in block.iter().rev() {
                    if local.name == name {
                        return Some(UpvalueDesc::Local(local.slot));
                    }
                }
            }
            // Check upvalues already registered in that scope.
            for (i, (uname, _)) in scope.upvalues.iter().enumerate() {
                if uname == name {
                    return Some(UpvalueDesc::Upvalue(i as u8));
                }
            }
        }
        // Try one level further up.
        if scope_idx > 0 {
            let desc = self.find_upvalue_in_enclosing(name, scope_idx - 1)?;
            // Register the upvalue in scope_idx.
            let scope = &mut self.scopes[scope_idx];
            let idx = scope.upvalues.len() as u8;
            scope.upvalues.push((name.to_string(), desc));
            return Some(UpvalueDesc::Upvalue(idx));
        }
        None
    }

    // -----------------------------------------------------------------------
    // Instruction emission
    // -----------------------------------------------------------------------

    fn emit(&mut self, instr: Instruction, line: u32) -> usize {
        let scope = self.current_scope_mut();
        let idx = scope.proto.code.len();
        scope.proto.code.push(instr);
        scope.proto.lines.push(line);
        idx
    }

    fn emit_placeholder(&mut self, line: u32) -> usize {
        self.emit(Instruction::Jmp(0), line)
    }

    /// Patch the jump at `idx` to point to the current end of code.
    fn patch_jump(&mut self, idx: usize) {
        let current_len = self.current_scope().proto.code.len();
        self.patch_jump_to(idx, current_len);
    }

    /// Patch the jump at `idx` to point to `target`.
    fn patch_jump_to(&mut self, idx: usize, target: usize) {
        let offset = (target as i64) - (idx as i64) - 1;
        let offset = offset as i16;
        let scope = self.current_scope_mut();
        match &mut scope.proto.code[idx] {
            Instruction::Jmp(o) => *o = offset,
            Instruction::JmpIf(o) => *o = offset,
            Instruction::JmpIfNot(o) => *o = offset,
            Instruction::And(o) => *o = offset,
            Instruction::Or(o) => *o = offset,
            Instruction::IterInitSorted(o) => *o = offset,
            Instruction::IterInitArray(o) => *o = offset,
            Instruction::IterNext(o) => *o = offset,
            other => panic!("patch_jump_to: not a jump: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Constant pool
    // -----------------------------------------------------------------------

    fn add_constant(&mut self, c: Constant, line: u32) -> Result<u16, CompileError> {
        let scope = self.current_scope_mut();
        // Deduplicate.
        for (i, existing) in scope.proto.constants.iter().enumerate() {
            if *existing == c {
                return Ok(i as u16);
            }
        }
        let idx = scope.proto.constants.len();
        if idx >= 65535 {
            return Err(CompileError::TooManyConstants { line });
        }
        scope.proto.constants.push(c);
        Ok(idx as u16)
    }

    fn add_string_constant(&mut self, s: &[u8], line: u32) -> Result<u16, CompileError> {
        self.add_constant(Constant::String(s.to_vec()), line)
    }

    fn add_int_constant(&mut self, n: i64, line: u32) -> Result<u16, CompileError> {
        self.add_constant(Constant::Integer(n), line)
    }

    fn push_proto(&mut self, proto: FunctionProto) -> Result<usize, CompileError> {
        let idx = self.prototypes.len();
        if idx >= 65535 {
            return Err(CompileError::TooManyPrototypes { line: 0 });
        }
        self.prototypes.push(proto);
        Ok(idx)
    }

    // -----------------------------------------------------------------------
    // Statement compilation
    // -----------------------------------------------------------------------

    pub fn compile_block(&mut self, block: &Block) -> Result<(), CompileError> {
        self.enter_block();
        for stmt in &block.stmts {
            self.compile_stmt(stmt)?;
        }
        if let Some(ret) = &block.ret {
            self.compile_return(ret)?;
        }
        self.exit_block();
        Ok(())
    }

    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompileError> {
        match stmt {
            Stmt::LocalDecl(d) => self.compile_local_decl(d),
            Stmt::Assign(a) => self.compile_assign(a),
            Stmt::If(i) => self.compile_if(i),
            Stmt::While(w) => self.compile_while(w),
            Stmt::NumericFor(f) => self.compile_numeric_for(f),
            Stmt::GenericFor(f) => self.compile_generic_for(f),
            Stmt::FunctionDecl(f) => self.compile_function_decl(f),
            Stmt::LocalFunctionDecl(lf) => self.compile_local_function_decl(lf),
            Stmt::ExprStmt(e) => self.compile_expr_stmt(e),
            Stmt::Break(span) => self.compile_break(span.line),
            Stmt::Do(d) => self.compile_block(&d.block),
        }
    }

    fn compile_local_decl(&mut self, decl: &LocalDecl) -> Result<(), CompileError> {
        let line = decl.span.line;
        let n_names = decl.names.len();

        // Special case: `local a, b = pcall(...)` — 2 names, 1 pcall expr.
        if n_names == 2 && decl.values.len() == 1 && is_pcall_expr(&decl.values[0]) {
            // Compile the pcall — pushes 2 values (ok, result).
            self.compile_pcall_expr(&decl.values[0])?;
            // Declare both locals; the stack has [ok, result] (ok pushed first,
            // result on top).  StoreLocal pops the top.
            let (name_b, b_span) = &decl.names[1];
            let (name_a, a_span) = &decl.names[0];
            let slot_a = self.declare_local(name_a, a_span.line)?;
            let slot_b = self.declare_local(name_b, b_span.line)?;
            // Stack top is result (index 1), then ok (index 0).
            self.emit(Instruction::StoreLocal(slot_b), line);
            self.emit(Instruction::StoreLocal(slot_a), line);
            return Ok(());
        }

        // General case: pair up names and values; extra names get nil.
        for (i, (name, name_span)) in decl.names.iter().enumerate() {
            if i < decl.values.len() {
                self.compile_expr(&decl.values[i])?;
            } else {
                self.emit(Instruction::PushNil, line);
            }
            let slot = self.declare_local(name, name_span.line)?;
            self.emit(Instruction::StoreLocal(slot), line);
        }
        Ok(())
    }

    fn compile_assign(&mut self, assign: &crate::parser::ast::Assign) -> Result<(), CompileError> {
        let line = assign.span.line;
        match &assign.target {
            AssignTarget::Name(name, name_span) => {
                let var = self.resolve_var(name);
                self.compile_expr(&assign.value)?;
                match var {
                    VarRef::Local(slot) => {
                        self.emit(Instruction::StoreLocal(slot), line);
                    }
                    VarRef::Upvalue(idx) => {
                        self.emit(Instruction::StoreUp(idx), line);
                    }
                    VarRef::Global => {
                        return Err(CompileError::UnknownGlobal {
                            name: name.clone(),
                            line: name_span.line,
                        });
                    }
                }
            }
            AssignTarget::Index(table_expr, key_expr, _span) => {
                self.compile_expr(table_expr)?;
                // Optimise: string literal key → SetField
                if let Expr::StringLit(bytes, _) = key_expr.as_ref() {
                    let idx = self.add_string_constant(bytes, line)?;
                    self.compile_expr(&assign.value)?;
                    self.emit(Instruction::SetField(idx), line);
                } else {
                    self.compile_expr(key_expr)?;
                    self.compile_expr(&assign.value)?;
                    self.emit(Instruction::SetTable, line);
                }
            }
        }
        Ok(())
    }

    fn compile_if(&mut self, stmt: &IfStmt) -> Result<(), CompileError> {
        let line = stmt.span.line;
        let has_else_or_elseif = !stmt.elseif_clauses.is_empty() || stmt.else_block.is_some();

        self.compile_expr(&stmt.condition)?;
        let jmp_false = self.emit(Instruction::JmpIfNot(0), line);

        self.compile_block(&stmt.then_block)?;

        let mut end_jumps: Vec<usize> = Vec::new();

        if has_else_or_elseif {
            let jmp_end = self.emit_placeholder(line);
            end_jumps.push(jmp_end);
        }
        self.patch_jump(jmp_false);

        for clause in &stmt.elseif_clauses {
            self.compile_expr(&clause.condition)?;
            let jmp_false2 = self.emit(Instruction::JmpIfNot(0), clause.span.line);
            self.compile_block(&clause.block)?;
            let jmp_end2 = self.emit_placeholder(clause.span.line);
            end_jumps.push(jmp_end2);
            self.patch_jump(jmp_false2);
        }

        if let Some(else_block) = &stmt.else_block {
            self.compile_block(else_block)?;
        }

        for idx in end_jumps {
            self.patch_jump(idx);
        }
        Ok(())
    }

    fn compile_while(&mut self, stmt: &WhileStmt) -> Result<(), CompileError> {
        let line = stmt.span.line;
        let loop_start = self.current_scope().proto.code.len();
        self.push_break_scope(0);

        self.compile_expr(&stmt.condition)?;
        let jmp_exit = self.emit(Instruction::JmpIfNot(0), line);

        self.compile_block(&stmt.block)?;

        // Back-edge jump.
        let back_offset = (loop_start as i64) - (self.current_scope().proto.code.len() as i64) - 1;
        self.emit(Instruction::Jmp(back_offset as i16), line);

        self.patch_jump(jmp_exit);
        let break_list = self.pop_break_scope();
        for idx in break_list {
            self.patch_jump(idx);
        }
        Ok(())
    }

    fn compile_numeric_for(&mut self, f: &NumericFor) -> Result<(), CompileError> {
        let line = f.span.line;

        // Enter an outer block for the hidden iteration vars + user var.
        self.enter_block();

        // Compile start → i_slot
        self.compile_expr(&f.start)?;
        let i_slot = self.declare_local("(for_i)", line)?;
        self.emit(Instruction::StoreLocal(i_slot), line);

        // Compile limit → lim_slot
        self.compile_expr(&f.limit)?;
        let lim_slot = self.declare_local("(for_lim)", line)?;
        self.emit(Instruction::StoreLocal(lim_slot), line);

        // Compile step (default 1) → step_slot
        if let Some(step_expr) = &f.step {
            self.compile_expr(step_expr)?;
        } else {
            let one_idx = self.add_int_constant(1, line)?;
            self.emit(Instruction::PushK(one_idx), line);
        }
        let step_slot = self.declare_local("(for_step)", line)?;
        self.emit(Instruction::StoreLocal(step_slot), line);

        // Declare the user-visible loop variable (uninitialised; will be set in loop body preamble).
        let var_slot = self.declare_local(&f.var, f.var_span.line)?;

        let loop_start = self.current_scope().proto.code.len();
        self.push_break_scope(0);

        // Loop condition: step >= 0 → i <= lim;  step < 0 → i >= lim
        // We emit a runtime check since step might not be a compile-time constant.
        //
        // Sequence:
        //   LoadLocal(step_slot)
        //   PushK(0)
        //   Lt          ; step < 0?
        //   JmpIfNot(positive_branch)  ; if NOT (step<0), go to positive check
        //   ; negative step: exit if i < lim
        //   LoadLocal(i_slot), LoadLocal(lim_slot), Lt
        //   JmpIf(exit)
        //   Jmp(continue_label)
        // positive_branch:
        //   LoadLocal(i_slot), LoadLocal(lim_slot), Gt
        //   JmpIf(exit)
        // continue_label:

        let zero_idx = self.add_int_constant(0, line)?;
        self.emit(Instruction::LoadLocal(step_slot), line);
        self.emit(Instruction::PushK(zero_idx), line);
        self.emit(Instruction::Lt, line);
        let jmp_positive = self.emit(Instruction::JmpIfNot(0), line);

        // Negative step branch: exit if i < lim
        self.emit(Instruction::LoadLocal(i_slot), line);
        self.emit(Instruction::LoadLocal(lim_slot), line);
        self.emit(Instruction::Lt, line);
        let jmp_exit_neg = self.emit(Instruction::JmpIf(0), line);
        let jmp_continue = self.emit_placeholder(line);

        // Positive step branch: exit if i > lim
        self.patch_jump(jmp_positive);
        self.emit(Instruction::LoadLocal(i_slot), line);
        self.emit(Instruction::LoadLocal(lim_slot), line);
        self.emit(Instruction::Gt, line);
        let jmp_exit_pos = self.emit(Instruction::JmpIf(0), line);

        self.patch_jump(jmp_continue);

        // Copy i → var_slot
        self.emit(Instruction::LoadLocal(i_slot), line);
        self.emit(Instruction::StoreLocal(var_slot), line);

        self.compile_block(&f.block)?;

        // Increment: i = i + step
        self.emit(Instruction::LoadLocal(i_slot), line);
        self.emit(Instruction::LoadLocal(step_slot), line);
        self.emit(Instruction::Add, line);
        self.emit(Instruction::StoreLocal(i_slot), line);

        // Back-edge
        let back_offset = (loop_start as i64) - (self.current_scope().proto.code.len() as i64) - 1;
        self.emit(Instruction::Jmp(back_offset as i16), line);

        // Patch exit jumps
        self.patch_jump(jmp_exit_neg);
        self.patch_jump(jmp_exit_pos);
        let break_list = self.pop_break_scope();
        for idx in break_list {
            self.patch_jump(idx);
        }
        self.exit_block();
        Ok(())
    }

    fn compile_generic_for(&mut self, f: &GenericFor) -> Result<(), CompileError> {
        let line = f.span.line;

        // Validate: exactly one iterator call to pairs_sorted/pairs/ipairs.
        if f.iterators.len() != 1 {
            return Err(CompileError::GenericForNotIterator { line });
        }
        let iter_expr = &f.iterators[0];
        let iter_kind =
            validate_iter_call(iter_expr).ok_or(CompileError::GenericForNotIterator { line })?;

        // Compile the table argument.
        let table_arg = extract_iter_table_arg(iter_expr)
            .ok_or(CompileError::GenericForNotIterator { line })?;
        self.compile_expr(table_arg)?;

        // extra_pops=1: the iterator handle must be popped before a break jump.
        self.push_break_scope(1);

        // Emit ITER_INIT_* with placeholder offset.
        let init_idx = match iter_kind {
            IterKind::Sorted => self.emit(Instruction::IterInitSorted(0), line),
            IterKind::Array => self.emit(Instruction::IterInitArray(0), line),
        };

        // ITER_NEXT is the loop top.
        let loop_top = self.current_scope().proto.code.len();
        let next_idx = self.emit(Instruction::IterNext(0), line);

        // Declare k and v as locals.
        self.enter_block();
        let n_vars = f.vars.len();
        // Always declare at least 2; pad with hidden names.
        let (key_name, key_span) = if n_vars >= 1 {
            f.vars[0].clone()
        } else {
            ("_".to_string(), f.span)
        };
        let (val_name, val_span) = if n_vars >= 2 {
            f.vars[1].clone()
        } else {
            ("_v".to_string(), f.span)
        };

        let k_slot = self.declare_local(&key_name, key_span.line)?;
        let v_slot = self.declare_local(&val_name, val_span.line)?;

        // IterNext pushes key then value (value on top).
        self.emit(Instruction::StoreLocal(v_slot), line); // pop value (top) → v
        self.emit(Instruction::StoreLocal(k_slot), line); // pop key → k

        self.compile_block(&f.block)?;

        self.exit_block();

        // Back-jump to loop_top (IterNext instruction).
        let back_offset = (loop_top as i64) - (self.current_scope().proto.code.len() as i64) - 1;
        self.emit(Instruction::Jmp(back_offset as i16), line);

        let loop_end = self.current_scope().proto.code.len();
        self.patch_jump_to(next_idx, loop_end);
        self.patch_jump_to(init_idx, loop_end);

        let break_list = self.pop_break_scope();
        for idx in break_list {
            self.patch_jump_to(idx, loop_end);
        }
        Ok(())
    }

    fn compile_function_decl(
        &mut self,
        decl: &crate::parser::ast::FunctionDecl,
    ) -> Result<(), CompileError> {
        let line = decl.span.line;
        let name = &decl.name;

        // Determine extra params (self for method syntax).
        let extra: &[&str] = if name.method.is_some() {
            &["self"]
        } else {
            &[]
        };
        let proto_idx = self.compile_function_body(&decl.func, extra)?;
        self.emit(Instruction::Closure(proto_idx), line);

        self.store_func_name(name, line)
    }

    fn store_func_name(&mut self, name: &FuncName, line: u32) -> Result<(), CompileError> {
        // parts = ["a", "b", "c"], method = Some("m")
        // → assign to a.b.c.m  (or a.b.c if no method)
        // Combined name is all parts + optional method.
        let mut all_parts: Vec<&str> = name.parts.iter().map(|(s, _)| s.as_str()).collect();
        if let Some((m, _)) = &name.method {
            all_parts.push(m.as_str());
        }

        if all_parts.len() == 1 {
            // Simple assignment: function f() end
            let varname = all_parts[0];
            let var = self.resolve_var(varname);
            match var {
                VarRef::Local(slot) => {
                    self.emit(Instruction::StoreLocal(slot), line);
                }
                VarRef::Upvalue(idx) => {
                    self.emit(Instruction::StoreUp(idx), line);
                }
                VarRef::Global => {
                    // Auto-declare as a local in the current function scope.
                    let slot = self.declare_local(varname, line)?;
                    self.emit(Instruction::StoreLocal(slot), line);
                }
            }
        } else {
            // Dotted: function a.b.c() end  → load a, then set field b on it, ...
            // First load the base object.
            let base = all_parts[0];
            let var = self.resolve_var(base);
            match var {
                VarRef::Local(slot) => {
                    self.emit(Instruction::LoadLocal(slot), line);
                }
                VarRef::Upvalue(idx) => {
                    self.emit(Instruction::LoadUp(idx), line);
                }
                VarRef::Global => {
                    return Err(CompileError::UnknownGlobal {
                        name: base.to_string(),
                        line,
                    });
                }
            }
            // Get intermediate fields.
            for part in &all_parts[1..all_parts.len() - 1] {
                let idx = self.add_string_constant(part.as_bytes(), line)?;
                self.emit(Instruction::GetField(idx), line);
            }
            // The closure is below the table on the stack.
            // Stack now: [table, closure]  but we need: [table] then SetField.
            // Actually: stack is [table] and closure was emitted before store_func_name.
            // We need to rotate: [closure] pushed, then load table, then swap.
            // Simpler: store closure in a temp, load table chain, load closure, SetField.
            //
            // The closure is already on the stack *before* we started loading the table.
            // Wait — let me re-examine.  compile_function_decl does:
            //   emit Closure(proto_idx)   → stack: [closure]
            //   store_func_name           → must store it into the table.
            //
            // For dotted name a.b.c:
            //   stack: [closure]
            //   need:  load a, get b, set c = closure
            //
            // Use a temp slot to hold the closure.
            let tmp = self.alloc_temp_slot();
            // Stack is [closure]; store it in tmp.
            // But we need to reverse: emit StoreLocal first to save closure, then load table.
            // Actually the Closure instruction was emitted *before* we call store_func_name,
            // so the stack has [closure] right now.
            self.emit(Instruction::StoreLocal(tmp), line); // save closure; stack: []

            // Reload base.
            match var {
                VarRef::Local(slot) => {
                    self.emit(Instruction::LoadLocal(slot), line);
                }
                VarRef::Upvalue(idx) => {
                    self.emit(Instruction::LoadUp(idx), line);
                }
                VarRef::Global => unreachable!(),
            }
            // Navigate intermediate fields again.
            for part in &all_parts[1..all_parts.len() - 1] {
                let idx = self.add_string_constant(part.as_bytes(), line)?;
                self.emit(Instruction::GetField(idx), line);
            }
            // Stack: [table].  Load closure back.
            self.emit(Instruction::LoadLocal(tmp), line); // stack: [table, closure]
            self.free_temp_slot();

            // SetField(last_part)
            let last = all_parts[all_parts.len() - 1];
            let idx = self.add_string_constant(last.as_bytes(), line)?;
            self.emit(Instruction::SetField(idx), line);
        }
        Ok(())
    }

    fn compile_local_function_decl(
        &mut self,
        decl: &crate::parser::ast::LocalFunctionDecl,
    ) -> Result<(), CompileError> {
        let line = decl.span.line;
        // Declare the local first so the body can refer to itself.
        let slot = self.declare_local(&decl.name, decl.name_span.line)?;
        self.emit(Instruction::PushNil, line);
        self.emit(Instruction::StoreLocal(slot), line);

        let proto_idx = self.compile_function_body(&decl.func, &[])?;
        self.emit(Instruction::Closure(proto_idx), line);
        self.emit(Instruction::StoreLocal(slot), line);
        Ok(())
    }

    fn compile_expr_stmt(
        &mut self,
        stmt: &crate::parser::ast::ExprStmt,
    ) -> Result<(), CompileError> {
        let line = stmt.span.line;
        match &stmt.expr {
            Expr::Call(call) => {
                self.compile_call(call)?;
                self.emit(Instruction::Pop, line);
            }
            Expr::MethodCall(mc) => {
                self.compile_method_call(mc)?;
                self.emit(Instruction::Pop, line);
            }
            _ => return Err(CompileError::ExprStmtNotCall { line }),
        }
        Ok(())
    }

    fn compile_break(&mut self, line: u32) -> Result<(), CompileError> {
        let extra_pops = {
            let scope = self.current_scope();
            if scope.break_patches.is_empty() {
                return Err(CompileError::BreakOutsideLoop { line });
            }
            scope.break_patches.last().unwrap().0
        };
        // Clean up any loop-specific stack slots (e.g. iterator handle in generic-for).
        for _ in 0..extra_pops {
            self.emit(Instruction::Pop, line);
        }
        let idx = self.emit_placeholder(line);
        let scope = self.current_scope_mut();
        scope.break_patches.last_mut().unwrap().1.push(idx);
        Ok(())
    }

    fn compile_return(&mut self, ret: &ReturnStmt) -> Result<(), CompileError> {
        let line = ret.span.line;
        match &ret.value {
            None => {
                self.emit(Instruction::Ret(0), line);
            }
            Some(expr) => {
                self.compile_expr(expr)?;
                self.emit(Instruction::Ret(1), line);
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Expression compilation
    // -----------------------------------------------------------------------

    pub fn compile_expr(&mut self, expr: &Expr) -> Result<(), CompileError> {
        let line = expr.span().line;
        match expr {
            Expr::Nil(_) => {
                self.emit(Instruction::PushNil, line);
            }
            Expr::True(_) => {
                self.emit(Instruction::PushTrue, line);
            }
            Expr::False(_) => {
                self.emit(Instruction::PushFalse, line);
            }
            Expr::Integer(n, _) => {
                let idx = self.add_int_constant(*n, line)?;
                self.emit(Instruction::PushK(idx), line);
            }
            Expr::StringLit(b, _) => {
                let idx = self.add_string_constant(b, line)?;
                self.emit(Instruction::PushK(idx), line);
            }
            Expr::Vararg(_) => {
                return Err(CompileError::VariadicNotAllowed { line });
            }
            Expr::Name(name, span) => {
                self.compile_name(name, span.line)?;
            }
            Expr::Field(table, field_name, _) => {
                // Check for tool.call used as a value.
                if is_tool_ref(table) && field_name == "call" {
                    return Err(CompileError::ToolAsValue { line });
                }
                self.compile_expr(table)?;
                let idx = self.add_string_constant(field_name.as_bytes(), line)?;
                self.emit(Instruction::GetField(idx), line);
            }
            Expr::Index(table, key, _) => {
                self.compile_expr(table)?;
                self.compile_expr(key)?;
                self.emit(Instruction::GetTable, line);
            }
            Expr::TableConstructor(tc) => {
                self.compile_table_constructor(tc)?;
            }
            Expr::BinOp(b) => {
                self.compile_binop(b)?;
            }
            Expr::UnOp(u) => {
                self.compile_expr(&u.operand)?;
                match u.op {
                    UnOpKind::Neg => {
                        self.emit(Instruction::Neg, line);
                    }
                    UnOpKind::Not => {
                        self.emit(Instruction::Not, line);
                    }
                    UnOpKind::Len => {
                        self.emit(Instruction::Len, line);
                    }
                }
            }
            Expr::Call(call) => {
                self.compile_call(call)?;
            }
            Expr::MethodCall(mc) => {
                self.compile_method_call(mc)?;
            }
            Expr::FuncDef(body, _) => {
                let proto_idx = self.compile_function_body(body, &[])?;
                self.emit(Instruction::Closure(proto_idx), line);
            }
        }
        Ok(())
    }

    fn compile_name(&mut self, name: &str, line: u32) -> Result<(), CompileError> {
        // Reject bare `tool` in expression position.
        if name == "tool" {
            return Err(CompileError::ToolAsValue { line });
        }
        // Special globals that are only valid in specific call positions are
        // handled by compile_call.  If we encounter them here they are being
        // used as a value — error out.
        match name {
            "pairs_sorted" | "pairs" | "ipairs" => {
                return Err(CompileError::ToolAsValue { line });
            }
            _ => {}
        }
        match self.resolve_var(name) {
            VarRef::Local(slot) => {
                self.emit(Instruction::LoadLocal(slot), line);
            }
            VarRef::Upvalue(idx) => {
                self.emit(Instruction::LoadUp(idx), line);
            }
            VarRef::Global => {
                // Known builtin globals: emit sentinel string constant.
                match name {
                    "string" => {
                        let idx = self.add_string_constant(b"__string", line)?;
                        self.emit(Instruction::PushK(idx), line);
                    }
                    "math" => {
                        let idx = self.add_string_constant(b"__math", line)?;
                        self.emit(Instruction::PushK(idx), line);
                    }
                    "table" => {
                        let idx = self.add_string_constant(b"__table", line)?;
                        self.emit(Instruction::PushK(idx), line);
                    }
                    "json" => {
                        let idx = self.add_string_constant(b"__json", line)?;
                        self.emit(Instruction::PushK(idx), line);
                    }
                    "tostring" | "tonumber" | "type" | "select" | "unpack" => {
                        // Treated as regular globals resolved by the VM via sentinel key.
                        let idx =
                            self.add_string_constant(format!("__{}", name).as_bytes(), line)?;
                        self.emit(Instruction::PushK(idx), line);
                    }
                    _ => {
                        return Err(CompileError::UnknownGlobal {
                            name: name.to_string(),
                            line,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn compile_table_constructor(
        &mut self,
        tc: &crate::parser::ast::TableConstructor,
    ) -> Result<(), CompileError> {
        let line = tc.span.line;
        self.emit(Instruction::NewTable, line);
        let mut auto_idx: i64 = 1;
        for field in &tc.fields {
            match field {
                TableField::NamedKey {
                    name, value, span, ..
                } => {
                    let fline = span.line;
                    self.emit(Instruction::Dup, fline);
                    let idx = self.add_string_constant(name.as_bytes(), fline)?;
                    self.compile_expr(value)?;
                    self.emit(Instruction::SetField(idx), fline);
                }
                TableField::ExplicitKey { key, value, span } => {
                    let fline = span.line;
                    self.emit(Instruction::Dup, fline);
                    self.compile_expr(key)?;
                    self.compile_expr(value)?;
                    self.emit(Instruction::SetTable, fline);
                }
                TableField::Positional { value, span } => {
                    let fline = span.line;
                    self.emit(Instruction::Dup, fline);
                    let kidx = self.add_int_constant(auto_idx, fline)?;
                    self.emit(Instruction::PushK(kidx), fline);
                    self.compile_expr(value)?;
                    self.emit(Instruction::SetTable, fline);
                    auto_idx += 1;
                }
            }
        }
        Ok(())
    }

    fn compile_binop(&mut self, b: &crate::parser::ast::BinOp) -> Result<(), CompileError> {
        let line = b.span.line;
        match b.op {
            BinOpKind::And => {
                self.compile_expr(&b.left)?;
                let and_idx = self.emit(Instruction::And(0), line);
                self.emit(Instruction::Pop, line);
                self.compile_expr(&b.right)?;
                self.patch_jump(and_idx);
            }
            BinOpKind::Or => {
                self.compile_expr(&b.left)?;
                let or_idx = self.emit(Instruction::Or(0), line);
                self.emit(Instruction::Pop, line);
                self.compile_expr(&b.right)?;
                self.patch_jump(or_idx);
            }
            BinOpKind::Concat => {
                self.compile_concat_expr(&Expr::BinOp(b.clone()))?;
            }
            _ => {
                self.compile_expr(&b.left)?;
                self.compile_expr(&b.right)?;
                let instr = match b.op {
                    BinOpKind::Add => Instruction::Add,
                    BinOpKind::Sub => Instruction::Sub,
                    BinOpKind::Mul => Instruction::Mul,
                    BinOpKind::IDiv => Instruction::IDiv,
                    BinOpKind::Mod => Instruction::Mod,
                    BinOpKind::Eq => Instruction::Eq,
                    BinOpKind::Ne => Instruction::Ne,
                    BinOpKind::Lt => Instruction::Lt,
                    BinOpKind::Le => Instruction::Le,
                    BinOpKind::Gt => Instruction::Gt,
                    BinOpKind::Ge => Instruction::Ge,
                    _ => unreachable!(),
                };
                self.emit(instr, line);
            }
        }
        Ok(())
    }

    /// Flatten a right-associative `..` chain into a single `Concat(n)`.
    fn compile_concat_expr(&mut self, expr: &Expr) -> Result<(), CompileError> {
        let args = collect_concat_args(expr);
        let n = args.len() as u8;
        for arg in args {
            self.compile_expr(arg)?;
        }
        self.emit(Instruction::Concat(n), expr.span().line);
        Ok(())
    }

    fn compile_call(&mut self, call: &Call) -> Result<(), CompileError> {
        let line = call.span.line;

        // tool.call(name, args)
        if is_tool_call(call) {
            if call.args.len() != 2 {
                return Err(CompileError::ToolAsValue { line });
            }
            self.compile_expr(&call.args[0])?;
            self.compile_expr(&call.args[1])?;
            self.emit(Instruction::ToolCall, line);
            return Ok(());
        }

        // Detect use of `tool` name directly as a call target.
        if let Expr::Name(name, span) = call.func.as_ref() {
            if name == "tool" {
                return Err(CompileError::ToolAsValue { line: span.line });
            }
            // Special built-in calls.
            match name.as_str() {
                "pcall" => return self.compile_pcall(call),
                "error" => {
                    if let Some(arg) = call.args.first() {
                        self.compile_expr(arg)?;
                    } else {
                        self.emit(Instruction::PushNil, line);
                    }
                    self.emit(Instruction::Error, line);
                    return Ok(());
                }
                "print" | "log" => {
                    if let Some(arg) = call.args.first() {
                        self.compile_expr(arg)?;
                    } else {
                        self.emit(Instruction::PushNil, line);
                    }
                    self.emit(Instruction::Log, line);
                    // Log pops its argument; push nil so that the statement-level
                    // Pop (emitted by compile_expr_stmt) has something to consume.
                    self.emit(Instruction::PushNil, line);
                    return Ok(());
                }
                _ => {}
            }
        }

        // Check for indirect tool.call used as a regular call target.
        if let Expr::Field(inner, field_name, span) = call.func.as_ref() {
            if is_tool_ref(inner) && field_name == "call" {
                // tool.call being called as a function reference — this is the
                // direct tool.call() form but without being caught by is_tool_call
                // (which would have returned true already).  Shouldn't reach here.
                return Err(CompileError::IndirectToolCall { line: span.line });
            }
        }

        // Normal call.
        self.compile_expr(&call.func)?;
        for arg in &call.args {
            self.compile_expr(arg)?;
        }
        self.emit(Instruction::Call(call.args.len() as u8), line);
        Ok(())
    }

    fn compile_pcall(&mut self, call: &Call) -> Result<(), CompileError> {
        let line = call.span.line;
        if call.args.is_empty() {
            // pcall() with no args — push nil as the function.
            self.emit(Instruction::PushNil, line);
            self.emit(Instruction::PCall(0), line);
            return Ok(());
        }
        self.compile_expr(&call.args[0])?;
        for arg in &call.args[1..] {
            self.compile_expr(arg)?;
        }
        self.emit(Instruction::PCall((call.args.len() - 1) as u8), line);
        Ok(())
    }

    /// Compile a pcall expression (for use in local declarations).
    fn compile_pcall_expr(&mut self, expr: &Expr) -> Result<(), CompileError> {
        match expr {
            Expr::Call(call) => self.compile_pcall(call),
            _ => Err(CompileError::MultiReturnNotAllowed {
                line: expr.span().line,
            }),
        }
    }

    fn compile_method_call(&mut self, mc: &MethodCall) -> Result<(), CompileError> {
        let line = mc.span.line;
        // Compile object, save a copy as self.
        self.compile_expr(&mc.object)?;
        let tmp = self.alloc_temp_slot();
        self.emit(Instruction::Dup, line);
        self.emit(Instruction::StoreLocal(tmp), line); // save self

        let idx = self.add_string_constant(mc.method.as_bytes(), line)?;
        self.emit(Instruction::GetField(idx), line); // [obj.method]
        self.emit(Instruction::LoadLocal(tmp), line); // [obj.method, self]
        self.free_temp_slot();

        for arg in &mc.args {
            self.compile_expr(arg)?;
        }
        self.emit(Instruction::Call(1 + mc.args.len() as u8), line);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Function body compilation
    // -----------------------------------------------------------------------

    pub fn compile_function_body(
        &mut self,
        body: &FuncBody,
        extra_params: &[&str],
    ) -> Result<u16, CompileError> {
        let total_params = (extra_params.len() + body.params.len()) as u8;
        self.enter_function(total_params);

        // Register params at their pre-assigned slots 0..param_count.
        // We use register_param (not declare_local) to avoid advancing next_slot.
        let param_line = body.span.line;
        let mut param_slot: u8 = 0;
        for name in extra_params {
            self.register_param(name, param_slot);
            param_slot += 1;
        }
        for (name, _span) in &body.params {
            self.register_param(name, param_slot);
            param_slot += 1;
        }
        let _ = param_line; // silence warning

        self.compile_block(&body.block)?;

        // Ensure function ends with a return.
        let needs_ret = self
            .current_scope()
            .proto
            .code
            .last()
            .map(|i| !matches!(i, Instruction::Ret(_)))
            .unwrap_or(true);
        if needs_ret {
            self.emit(Instruction::Ret(0), body.span.line);
        }

        let proto = self.exit_function();
        let idx = self.push_proto(proto)?;
        Ok(idx as u16)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Returns true if `expr` is `Expr::Name("tool")`.
fn is_tool_ref(expr: &Expr) -> bool {
    matches!(expr, Expr::Name(n, _) if n == "tool")
}

/// Returns true if `call` is `tool.call(e1, e2)`.
fn is_tool_call(call: &Call) -> bool {
    match call.func.as_ref() {
        Expr::Field(inner, field_name, _) => is_tool_ref(inner) && field_name == "call",
        _ => false,
    }
}

/// Returns true if `expr` is a `pcall(...)` call.
fn is_pcall_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(c) if matches!(c.func.as_ref(), Expr::Name(n, _) if n == "pcall"))
}

enum IterKind {
    Sorted,
    Array,
}

/// Validates that `expr` is a call to pairs_sorted/pairs/ipairs and returns the kind.
fn validate_iter_call(expr: &Expr) -> Option<IterKind> {
    match expr {
        Expr::Call(call) => {
            if let Expr::Name(name, _) = call.func.as_ref() {
                match name.as_str() {
                    "pairs_sorted" | "pairs" => Some(IterKind::Sorted),
                    "ipairs" => Some(IterKind::Array),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extracts the table argument from an iterator call.
fn extract_iter_table_arg(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::Call(call) if !call.args.is_empty() => Some(&call.args[0]),
        _ => None,
    }
}

/// Flatten a right-associative `..` chain into a list of leaf expressions.
fn collect_concat_args(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::BinOp(b) if b.op == BinOpKind::Concat => {
            let mut args = collect_concat_args(&b.left);
            args.extend(collect_concat_args(&b.right));
            args
        }
        _ => vec![expr],
    }
}

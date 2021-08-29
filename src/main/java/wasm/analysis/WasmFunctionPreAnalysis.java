package wasm.analysis;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import wasm.format.Leb128;
import wasm.format.WasmEnums.ValType;
import wasm.format.sections.structures.WasmFuncType;

/**
 * This preanalysis pass is partially patterned after the validation algorithm
 * described in the Appendix:
 * https://webassembly.github.io/spec/core/appendix/algorithm.html
 */
public class WasmFunctionPreAnalysis {

	WasmFuncSignature func;
	BinaryReader reader;
	/* null in the value stack means Unknown */
	List<ValType> valueStack = new ArrayList<>();
	List<ControlFrame> controlStack = new ArrayList<>();

	public WasmFunctionPreAnalysis(WasmFuncSignature func, BinaryReader reader) {
		this.func = func;
		this.reader = reader;
	}

	private static class ProgramContext {
		/* These labels must be synced with WebAssembly.slaspec */
		private static final String REG_ISOP64 = "is_op64";
		private static final String REG_SPADJ = "SPAdjust";
		private static final String REG_BRTARGET = "BRTarget";

		private static void setRegister(Program program, Address address, String name, long value) {
			Register register = program.getRegister(name);

			if (register == null) {
				throw new RuntimeException("Failed to find register " + name);
			}

			try {
				program.getProgramContext().setValue(register, address, address, BigInteger.valueOf(value));
			} catch (ContextChangeException e) {
				Msg.error(ProgramContext.class, "Failed to set context register", e);
			}
		}

		public static void setIsOp64(Program program, Address address, ValType type) {
			int value;
			if (type == null || type == ValType.i32 || type == ValType.f32) {
				/* 32-bit operand */
				value = 0;
			} else {
				/* 64-bit operand */
				value = 1;
			}
			setRegister(program, address, REG_ISOP64, value);
		}

		public static void setBranchTarget(Program program, Address address, Address target) {
			setRegister(program, address, REG_BRTARGET, target.getOffset());
		}

		public static void setStackAdjust(Program program, Address address, long value) {
			setRegister(program, address, REG_SPADJ, value);
		}
	}

	private static class BlockType {
		ValType[] params;
		ValType[] returns;

		public BlockType(Program program, WasmFuncSignature func) {
			/* A function's parameters are in local variables rather than the stack */
			params = new ValType[0];
			returns = func.getReturns();
		}

		public BlockType(Program program, long blocktype) {
			WasmAnalysis analysis = WasmAnalysis.getState(program);
			if (blocktype == -0x40) {
				params = new ValType[0];
				returns = new ValType[0];
			} else if (blocktype < 0) {
				params = new ValType[0];
				returns = new ValType[] { ValType.fromByte((int) blocktype + 0x80) };
			} else {
				WasmFuncType type = analysis.getType((int) blocktype);
				params = ValType.fromBytes(type.getParamTypes());
				returns = ValType.fromBytes(type.getReturnTypes());
			}
		}
	}

	private enum BlockKind {
		FUNCTION,
		BLOCK,
		IF,
		LOOP;

		public static BlockKind fromOpcode(int opcode) {
			switch (opcode) {
			case 0x02: /* block bt */
				return BLOCK;
			case 0x03: /* loop bt */
				return LOOP;
			case 0x04: /* if bt */
				return IF;
			}
			return null;
		}
	}

	private static class ControlFrame {
		Address startAddress;
		BlockKind blockKind;
		BlockType blockType;
		List<ValType> initialStack;
		/** A list of instruction address which branch to this block. */
		List<Address> branchAddresses = new ArrayList<>();
		boolean unreachable = false;
		boolean hasElse = false;

		public ControlFrame(Program program, Address address, BlockType blockType) {
			this.startAddress = address;
			this.blockKind = BlockKind.FUNCTION;
			this.blockType = blockType;
			this.initialStack = new ArrayList<>();
		}

		public ControlFrame(Program program, Address address, BlockKind blockKind, BlockType blockType, List<ValType> stack) {
			this.startAddress = address;
			this.blockKind = blockKind;
			this.blockType = blockType;
			this.initialStack = new ArrayList<>(stack);
		}

		public ValType[] getBranchArguments() {
			if (blockKind == BlockKind.LOOP) {
				return blockType.params;
			} else {
				return blockType.returns;
			}
		}

		public void addBranch(Program program, List<ValType> stack, Address address) {
			ProgramContext.setStackAdjust(program, address, stack.size() - initialStack.size());
			branchAddresses.add(address);
		}

		public void setElse(Program program, Address address) {
			hasElse = true;
			if (blockKind != BlockKind.IF) {
				throw new ValidationException(address, "else without corresponding if");
			}
			ProgramContext.setBranchTarget(program, startAddress, address.add(1));
		}

		public void setEnd(Program program, Address address) {
			if (blockKind == BlockKind.IF && !hasElse) {
				ProgramContext.setBranchTarget(program, startAddress, address);
			}

			Address branchTarget;
			if (blockKind == BlockKind.LOOP) {
				branchTarget = startAddress;
			} else {
				branchTarget = address;
			}
			for (Address branch : branchAddresses) {
				ProgramContext.setBranchTarget(program, branch, branchTarget);
			}
		}

		@Override
		public String toString() {
			return blockKind + "@" + startAddress;
		}
	}

	private static long readLeb128(BinaryReader reader) throws IOException {
		return new Leb128(reader).getValue();
	}

	private static long readSignedLeb128(BinaryReader reader) throws IOException {
		return new Leb128(reader).getSignedValue();
	}

	private void pushValue(Address instAddress, ValType type) {
		valueStack.add(type);
	}

	private ValType popValue(Address instAddress) {
		ControlFrame curBlock = getBlock(instAddress, 0);
		if (valueStack.size() <= curBlock.initialStack.size()) {
			/* If our stack is polymorphic, popping off an empty stack is ok */
			if (curBlock.unreachable)
				return null;
			throw new ValidationException(instAddress, "pop from empty stack");
		}
		return valueStack.remove(valueStack.size() - 1);
	}

	private ValType popValue(Address instAddress, ValType type) {
		ValType top = popValue(instAddress);
		if (type == null) {
			return top;
		}
		if (top == null) {
			return type;
		}
		if (top != type) {
			throw new ValidationException(instAddress, "pop type mismatch: got " + top + ", expected " + type);
		}
		return top;
	}

	private void pushValues(Address instAddress, ValType[] types) {
		for (int i = 0; i < types.length; i++) {
			pushValue(instAddress, types[i]);
		}
	}

	private void popValues(Address instAddress, ValType[] types) {
		for (int i = types.length - 1; i >= 0; i--) {
			popValue(instAddress, types[i]);
		}
	}

	private void pushBlock(Address instAddress, ControlFrame block) {
		controlStack.add(block);
		pushValues(instAddress, block.blockType.params);
	}

	private ControlFrame popBlock(Address instAddress) {
		if (controlStack.isEmpty()) {
			throw new ValidationException(instAddress, "pop from empty block stack");
		}
		ControlFrame block = getBlock(instAddress, 0);
		popValues(instAddress, block.blockType.returns);
		if (valueStack.size() != block.initialStack.size()) {
			throw new ValidationException(instAddress, "block end has wrong number of parameters");
		}
		controlStack.remove(controlStack.size() - 1);
		return block;
	}

	private ControlFrame getBlock(Address instAddress, long labelidx) {
		if (labelidx >= controlStack.size()) {
			throw new ValidationException(instAddress, "invalid label index " + labelidx);
		}
		return controlStack.get(controlStack.size() - 1 - (int) labelidx);
	}

	/** Mark stack as polymorphic from this point to the end of the block */
	private void markUnreachable(Address instAddress) {
		ControlFrame curBlock = getBlock(instAddress, 0);
		valueStack = new ArrayList<>(curBlock.initialStack);
		curBlock.unreachable = true;
	}

	private void analyzeOpcode(Program program, Address instAddress) throws IOException {
		int opcode = reader.readNextUnsignedByte();
		Msg.info(this, func.getName() + "@" + instAddress + ": " + String.format("0x%02x", opcode) + " blocks=" + controlStack + " stack=" + valueStack);
		switch (opcode) {
		case 0x00: /* unreachable */
			markUnreachable(instAddress);
			break;
		case 0x01: /* nop */
			break;
		case 0x02: /* block bt */ {
			BlockType blocktype = new BlockType(program, readSignedLeb128(reader));
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, new ControlFrame(program, instAddress, BlockKind.BLOCK, blocktype, valueStack));
			break;
		}
		case 0x03: /* loop bt */ {
			BlockType blocktype = new BlockType(program, readSignedLeb128(reader));
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, new ControlFrame(program, instAddress, BlockKind.LOOP, blocktype, valueStack));
			break;
		}
		case 0x04: /* if bt */ {
			BlockType blocktype = new BlockType(program, readSignedLeb128(reader));
			popValue(instAddress, ValType.i32);
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, new ControlFrame(program, instAddress, BlockKind.IF, blocktype, valueStack));
			break;
		}
		case 0x05: /* else */ {
			ControlFrame block = popBlock(instAddress);
			if (block.blockKind != BlockKind.IF) {
				throw new ValidationException(instAddress, "else without matching if");
			}

			// block.addBranch(program, valueStack, instAddress);
			// block.setElse(program, instAddress);

			block.unreachable = false;
			pushBlock(instAddress, block);
			break;
		}
		case 0x0B: /* end */ {
			ControlFrame block = popBlock(instAddress);
			pushValues(instAddress, block.blockType.returns);
			// block.setEnd(program, instAddress);
			break;
		}
		case 0x0C: /* br l */ {
			long labelidx = readLeb128(reader);
			ControlFrame block = getBlock(instAddress, labelidx);
			popValues(instAddress, block.getBranchArguments());
			// block.addBranch(program, valueStack, instAddress);
			markUnreachable(instAddress);
			break;
		}
		case 0x0D: /* br_if l */ {
			long labelidx = readLeb128(reader);
			ControlFrame block = getBlock(instAddress, labelidx);
			popValue(instAddress, ValType.i32);
			popValues(instAddress, block.getBranchArguments());
			pushValues(instAddress, block.getBranchArguments());
			// block.addBranch(program, valueStack, instAddress);
			break;
		}
		case 0x0E: /* br_table l* l */ {
			long count = readLeb128(reader);
			popValue(instAddress, ValType.i32);
			for (int i = 0; i < count; i++) {
				long case_labelidx = readLeb128(reader);
				ControlFrame case_block = getBlock(instAddress, case_labelidx);
				// block.addBranch(program, valueStack, instAddress);
				popValues(instAddress, case_block.getBranchArguments());
				pushValues(instAddress, case_block.getBranchArguments());
			}
			long default_labelidx = readLeb128(reader);
			ControlFrame default_block = getBlock(instAddress, default_labelidx);
			// block.addBranch(program, valueStack, instAddress);
			popValues(instAddress, default_block.getBranchArguments());
			markUnreachable(instAddress);
			break;
		}
		case 0x0F: /* return */ {
			popValues(instAddress, func.getReturns());
			ProgramContext.setStackAdjust(program, instAddress, valueStack.size());
			markUnreachable(instAddress);
			break;
		}
		case 0x10: /* call x */ {
			long funcidx = readLeb128(reader);
			WasmAnalysis analysis = WasmAnalysis.getState(program);
			WasmFuncSignature targetFunc = analysis.getFuncSignature((int) funcidx);
			popValues(instAddress, targetFunc.getParams());
			/* TODO: Set a call type override? */
			ProgramContext.setBranchTarget(program, instAddress, targetFunc.getStartAddr());
			pushValues(instAddress, targetFunc.getReturns());
			break;
		}
		case 0x11: /* call_indirect x y */ {
			long typeidx = readLeb128(reader);
			long tableidx = readLeb128(reader);
			WasmAnalysis analysis = WasmAnalysis.getState(program);
			WasmFuncType type = analysis.getType((int) typeidx);
			popValues(instAddress, ValType.fromBytes(type.getParamTypes()));
			/* TODO: Set a call type override? */
			pushValues(instAddress, ValType.fromBytes(type.getReturnTypes()));
			break;
		}
		case 0x1A: /* drop */ {
			popValue(instAddress);
			break;
		}
		case 0x1B: /* select */ {
			popValue(instAddress, ValType.i32);
			ValType t1 = popValue(instAddress);
			ValType t2 = popValue(instAddress);
			if (t1 != null && t2 != null && t1 != t2) {
				throw new ValidationException(instAddress, "inconsistent types in select");
			}
			ValType resultType = (t1 != null) ? t1 : t2;
			ProgramContext.setIsOp64(program, instAddress, resultType);
			pushValue(instAddress, resultType);
			break;
		}
		case 0x1C: /* select t */ {
			long count = readLeb128(reader);
			if (count != 1) {
				throw new ValidationException(instAddress, "only select t is supported");
			}
			ValType t = ValType.fromByte(reader.readNextUnsignedByte());
			popValue(instAddress, ValType.i32);
			popValue(instAddress, t);
			popValue(instAddress, t);
			pushValue(instAddress, t);
			break;
		}
		case 0x20: /* local.get x */ {
			long localidx = readLeb128(reader);
			ValType type = func.getLocals()[(int) localidx];
			ProgramContext.setIsOp64(program, instAddress, type);
			pushValue(instAddress, type);
			break;
		}
		case 0x21: /* local.set x */ {
			long localidx = readLeb128(reader);
			ValType type = func.getLocals()[(int) localidx];
			ProgramContext.setIsOp64(program, instAddress, type);
			popValue(instAddress, type);
			break;
		}
		case 0x22: /* local.tee x */ {
			long localidx = readLeb128(reader);
			ValType type = func.getLocals()[(int) localidx];
			ProgramContext.setIsOp64(program, instAddress, type);
			popValue(instAddress, type);
			pushValue(instAddress, type);
			break;
		}
		case 0x23: /* global.get x */ {
			long globalidx = readLeb128(reader);
			ValType type = WasmAnalysis.getState(program).getGlobalType((int) globalidx);
			ProgramContext.setIsOp64(program, instAddress, type);
			pushValue(instAddress, type);
			break;
		}
		case 0x24: /* global.set x */ {
			long globalidx = readLeb128(reader);
			ValType type = WasmAnalysis.getState(program).getGlobalType((int) globalidx);
			ProgramContext.setIsOp64(program, instAddress, type);
			popValue(instAddress, type);
			break;
		}
		/* 			
		*/
		case 0x25: /* table.get x */
		case 0x26: /* table.set x */ {
			long tableidx = readLeb128(reader);
			break;
		}
		case 0x28: /* i32.load memarg */
		case 0x2A: /* f32.load memarg */
		case 0x2C: /* i32.load8_s memarg */
		case 0x2D: /* i32.load8_u memarg */
		case 0x2E: /* i32.load16_s memarg */
		case 0x2F: /* i32.load16_u memarg */ {
			long align = readLeb128(reader);
			long offset = readLeb128(reader);
			break;
		}
		case 0x29: /* i64.load memarg */
		case 0x2B: /* f64.load memarg */
		case 0x30: /* i64.load8_s memarg */
		case 0x31: /* i64.load8_u memarg */
		case 0x32: /* i64.load16_s memarg */
		case 0x33: /* i64.load16_u memarg */
		case 0x34: /* i64.load32_s memarg */
		case 0x35: /* i64.load32_u memarg */ {
			long align = readLeb128(reader);
			long offset = readLeb128(reader);
			break;
		}
		case 0x36: /* i32.store memarg */
		case 0x38: /* f32.store memarg */
		case 0x3A: /* i32.store8 memarg */
		case 0x3B: /* i32.store16 memarg */ {
			long align = readLeb128(reader);
			long offset = readLeb128(reader);
			break;
		}
		case 0x37: /* i64.store memarg */
		case 0x39: /* f64.store memarg */
		case 0x3C: /* i64.store8 memarg */
		case 0x3D: /* i64.store16 memarg */
		case 0x3E: /* i64.store32 memarg */ {
			long align = readLeb128(reader);
			long offset = readLeb128(reader);
			break;
		}
		case 0x3F: /* memory.size */
		case 0x40: /* memory.grow */ {
			long memidx = readLeb128(reader);
			break;
		}
		case 0x41: /* i32.const i32 */ {
			long value = readLeb128(reader);
			break;
		}
		case 0x42: /* i64.const i64 */ {
			long value = readLeb128(reader);
			break;
		}
		case 0x43: /* f32.const f32 */ {
			byte[] value = reader.readNextByteArray(4);
			break;
		}
		case 0x44: /* f64.const f64 */ {
			byte[] value = reader.readNextByteArray(4);
			break;
		}
		case 0x45: /* i32.eqz */
		case 0x46: /* i32.eq */
		case 0x47: /* i32.ne */
		case 0x48: /* i32.lt_s */
		case 0x49: /* i32.lt_u */
		case 0x4A: /* i32.gt_s */
		case 0x4B: /* i32.gt_u */
		case 0x4C: /* i32.le_s */
		case 0x4D: /* i32.le_u */
		case 0x4E: /* i32.ge_s */
		case 0x4F: /* i32.ge_u */
		case 0x50: /* i64.eqz */
		case 0x51: /* i64.eq */
		case 0x52: /* i64.ne */
		case 0x53: /* i64.lt_s */
		case 0x54: /* i64.lt_u */
		case 0x55: /* i64.gt_s */
		case 0x56: /* i64.gt_u */
		case 0x57: /* i64.le_s */
		case 0x58: /* i64.le_u */
		case 0x59: /* i64.ge_s */
		case 0x5A: /* i64.ge_u */
		case 0x5B: /* f32.eq */
		case 0x5C: /* f32.ne */
		case 0x5D: /* f32.lt */
		case 0x5E: /* f32.gt */
		case 0x5F: /* f32.le */
		case 0x60: /* f32.ge */
		case 0x61: /* f64.eq */
		case 0x62: /* f64.ne */
		case 0x63: /* f64.lt */
		case 0x64: /* f64.gt */
		case 0x65: /* f64.le */
		case 0x66: /* f64.ge */
		case 0x67: /* i32.clz */
		case 0x68: /* i32.ctz */
		case 0x69: /* i32.popcnt */
		case 0x6A: /* i32.add */
		case 0x6B: /* i32.sub */
		case 0x6C: /* i32.mul */
		case 0x6D: /* i32.div_s */
		case 0x6E: /* i32.div_u */
		case 0x6F: /* i32.rem_s */
		case 0x70: /* i32.rem_u */
		case 0x71: /* i32.and */
		case 0x72: /* i32.or */
		case 0x73: /* i32.xor */
		case 0x74: /* i32.shl */
		case 0x75: /* i32.shr_s */
		case 0x76: /* i32.shr_u */
		case 0x77: /* i32.rotl */
		case 0x78: /* i32.rotr */
		case 0x79: /* i64.clz */
		case 0x7A: /* i64.ctz */
		case 0x7B: /* i64.popcnt */
		case 0x7C: /* i64.add */
		case 0x7D: /* i64.sub */
		case 0x7E: /* i64.mul */
		case 0x7F: /* i64.div_s */
		case 0x80: /* i64.div_u */
		case 0x81: /* i64.rem_s */
		case 0x82: /* i64.rem_u */
		case 0x83: /* i64.and */
		case 0x84: /* i64.or */
		case 0x85: /* i64.xor */
		case 0x86: /* i64.shl */
		case 0x87: /* i64.shr_s */
		case 0x88: /* i64.shr_u */
		case 0x89: /* i64.rotl */
		case 0x8A: /* i64.rotr */
		case 0x8B: /* f32.abs */
		case 0x8C: /* f32.neg */
		case 0x8D: /* f32.ceil */
		case 0x8E: /* f32.floor */
		case 0x8F: /* f32.trunc */
		case 0x90: /* f32.nearest */
		case 0x91: /* f32.sqrt */
		case 0x92: /* f32.add */
		case 0x93: /* f32.sub */
		case 0x94: /* f32.mul */
		case 0x95: /* f32.div */
		case 0x96: /* f32.min */
		case 0x97: /* f32.max */
		case 0x98: /* f32.copysign */
		case 0x99: /* f64.abs */
		case 0x9A: /* f64.neg */
		case 0x9B: /* f64.ceil */
		case 0x9C: /* f64.floor */
		case 0x9D: /* f64.trunc */
		case 0x9E: /* f64.nearest */
		case 0x9F: /* f64.sqrt */
		case 0xA0: /* f64.add */
		case 0xA1: /* f64.sub */
		case 0xA2: /* f64.mul */
		case 0xA3: /* f64.div */
		case 0xA4: /* f64.min */
		case 0xA5: /* f64.max */
		case 0xA6: /* f64.copysign */
		case 0xA7: /* i32.wrap_i64 */
		case 0xA8: /* i32.trunc_f32_s */
		case 0xA9: /* i32.trunc_f32_u */
		case 0xAA: /* i32.trunc_f64_s */
		case 0xAB: /* i32.trunc_f64_u */
		case 0xAC: /* i64.extend_i32_s */
		case 0xAD: /* i64.extend_i32_u */
		case 0xAE: /* i64.trunc_f32_s */
		case 0xAF: /* i64.trunc_f32_u */
		case 0xB0: /* i64.trunc_f64_s */
		case 0xB1: /* i64.trunc_f64_u */
		case 0xB2: /* f32.convert_i32_s */
		case 0xB3: /* f32.convert_i32_u */
		case 0xB4: /* f32.convert_i64_s */
		case 0xB5: /* f32.convert_i64_u */
		case 0xB6: /* f32.demote_f64 */
		case 0xB7: /* f64.convert_i32_s */
		case 0xB8: /* f64.convert_i32_u */
		case 0xB9: /* f64.convert_i64_s */
		case 0xBA: /* f64.convert_i64_u */
		case 0xBB: /* f64.promote_f32 */
		case 0xBC: /* i32.reinterpret_f32 */
		case 0xBD: /* i64.reinterpret_f64 */
		case 0xBE: /* f32.reinterpret_i32 */
		case 0xBF: /* f64.reinterpret_i64 */
		case 0xC0: /* i32.extend8_s */
		case 0xC1: /* i32.extend16_s */
		case 0xC2: /* i64.extend8_s */
		case 0xC3: /* i64.extend16_s */
		case 0xC4: /* i64.extend32_s */ {
			break;
		}
		case 0xD0: /* ref.null t */ {
			int reftype = reader.readNextUnsignedByte();
			break;
		}
		case 0xD1: /* ref.is_null */ {
			break;
		}
		case 0xD2: /* ref.func x */ {
			long funcidx = readLeb128(reader);
		}
		case 0xFC: {
			int opcode2 = reader.readNextUnsignedByte();
			switch (opcode2) {
			case 0x00: /* i32.trunc_sat_f32_s */
			case 0x01: /* i32.trunc_sat_f32_u */
			case 0x02: /* i32.trunc_sat_f64_s */
			case 0x03: /* i32.trunc_sat_f64_u */
			case 0x04: /* i64.trunc_sat_f32_s */
			case 0x05: /* i64.trunc_sat_f32_u */
			case 0x06: /* i64.trunc_sat_f64_s */
			case 0x07: /* i64.trunc_sat_f64_u */ {
				break;
			}
			case 0x08: /* memory.init x */ {
				long dataidx = readLeb128(reader);
				long memidx = readLeb128(reader);
				break;
			}
			case 0x09: /* data.drop x */ {
				long dataidx = readLeb128(reader);
				break;
			}
			case 0x0A: /* memory.copy */ {
				long memidx = readLeb128(reader);
				long memidx2 = readLeb128(reader);
				break;
			}
			case 0x0B: /* memory.fill */ {
				long memidx = readLeb128(reader);
				break;
			}
			case 0x0C: /* table.init x y */ {
				long elemidx = readLeb128(reader);
				long tableidx = readLeb128(reader);
				break;
			}
			case 0x0D: /* elem.drop x */ {
				long elemidx = readLeb128(reader);
				break;
			}
			case 0x0E: /* table.copy x y */ {
				long tableidx = readLeb128(reader);
				long tableidx2 = readLeb128(reader);
				break;
			}
			case 0x0F: /* table.grow x */ {
				long tableidx = readLeb128(reader);
				break;
			}
			case 0x10: /* table.size x */ {
				long tableidx = readLeb128(reader);
				break;
			}
			case 0x11: /* table.fill x */ {
				long tableidx = readLeb128(reader);
				break;
			}
			default:
				Msg.warn(this, "Illegal opcode: 0xfc " + String.format("0x%02x", opcode2));
				break;
			}
			break;
		}
		default:
			Msg.warn(this, "Illegal opcode: " + String.format("0x%02x", opcode));
			break;
		}
	}

	public void analyzeFunction(Program program, TaskMonitor monitor) throws IOException {
		Address startAddress = func.getStartAddr();
		long functionLength = func.getEndAddr().subtract(func.getStartAddr());

		Msg.info(this, "Analyzing " + func.getName() + "@" + startAddress);
		pushBlock(startAddress, new ControlFrame(program, startAddress, new BlockType(program, func)));
		while (reader.getPointerIndex() < functionLength) {
			if (monitor.isCancelled()) {
				break;
			}
			Address instAddress = startAddress.add(reader.getPointerIndex());
			analyzeOpcode(program, instAddress);
		}
	}
}

package wasm.analysis.flow;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import wasm.analysis.WasmModuleData;
import wasm.analysis.flow.MetaInstruction.Type;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.structures.WasmFuncType;
import wasm.pcodeInject.PcodeInjectLibraryWasm;
import wasm.util.Initializable;
import wasm.util.WasmInstructionUtil;
import wasm.util.WasmInstructionUtil.OPCODES;

public class WasmFunctionFlowAnalysis implements Initializable<Function> {

	public final static Map<String, Type> callOtherMapping = new HashMap<>();

	static {
		callOtherMapping.put(PcodeInjectLibraryWasm.POP, MetaInstruction.Type.POP);
		callOtherMapping.put(PcodeInjectLibraryWasm.PUSH, MetaInstruction.Type.PUSH);
		callOtherMapping.put(PcodeInjectLibraryWasm.BR, MetaInstruction.Type.BR);
		callOtherMapping.put(PcodeInjectLibraryWasm.BEGIN_LOOP, MetaInstruction.Type.BEGIN_LOOP);
		callOtherMapping.put(PcodeInjectLibraryWasm.BEGIN_BLOCK, MetaInstruction.Type.BEGIN_BLOCK);
		callOtherMapping.put(PcodeInjectLibraryWasm.END, MetaInstruction.Type.END);
		callOtherMapping.put(PcodeInjectLibraryWasm.IF, MetaInstruction.Type.IF);
		callOtherMapping.put(PcodeInjectLibraryWasm.ELSE, MetaInstruction.Type.ELSE);
		callOtherMapping.put(PcodeInjectLibraryWasm.RETURN, MetaInstruction.Type.RETURN);
		callOtherMapping.put(PcodeInjectLibraryWasm.CALL, MetaInstruction.Type.CALL);
		callOtherMapping.put(PcodeInjectLibraryWasm.CALL_INDIRECT, MetaInstruction.Type.CALL_INDIRECT);
		callOtherMapping.put(PcodeInjectLibraryWasm.BR_TABLE, MetaInstruction.Type.BR_TABLE);

	}

	public static class MetaKey {
		protected Address address;
		protected Type kind;

		public MetaKey(Address address, Type kind) {
			super();
			this.address = address;
			this.kind = kind;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((address == null) ? 0 : address.hashCode());
			result = prime * result + ((kind == null) ? 0 : kind.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			MetaKey other = (MetaKey) obj;
			if (address == null) {
				if (other.address != null)
					return false;
			} else if (!address.equals(other.address))
				return false;
			if (kind != other.kind)
				return false;
			return true;
		}
	}

	private Program program;
	private Function function;
	private Map<MetaKey, MetaInstruction> metaInstrsMap = new HashMap<>();
	private GlobalStack globalStack;

	public MetaInstruction getMetaInstruction(Address address, Type kind) {
		return metaInstrsMap.get(new MetaKey(address, kind));
	}

	public GlobalStack getGlobalStack() {
		return globalStack;
	}

	@Override
	public boolean needReset(Function param) {
		// TODO add some logic to restart analysis if:
		// * some function bytes changed
		// * we failed to get instruction before and the instruction is present now
		return false;
	}

	@Override
	public void init(Function function) {
		program = function.getProgram();
		this.function = function;

		detectGlobalStack();

		// -- recover instruction and flow here

		// recover MetaInstructions using the listing
		List<MetaInstruction> metaInstrs = collectMetaInstructions();
		// compute flow
		performResolution(metaInstrs);
		// store MetaInstructions so that they can be retrieved during pcode injection.
		for (MetaInstruction mi : metaInstrs) {
			metaInstrsMap.put(new MetaKey(mi.location, mi.getType()), mi);
		}

	}

	private List<MetaInstruction> collectMetaInstructions() {
		List<MetaInstruction> res = new ArrayList<>();
		InstructionIterator iter = program.getListing().getInstructions(function.getBody(), true);
		while (iter.hasNext()) {
			Instruction instr = iter.next();
			for (PcodeOp op : instr.getPcode()) {
				if (op.getOpcode() == PcodeOp.CALLOTHER) {
					String name = program.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset());
					Type opKind = callOtherMapping.get(name);
					if (opKind != null) {
						res.add(MetaInstruction.create(opKind, instr, program));
					}
				}
			}
		}
		return res;
	}

	public static class GlobalStack {
		/**
		 * Size of the stack in memory
		 */
		private int stackSize;
		/**
		 * Index in globals used to retrieve the stack index
		 */
		private int globalIndex;

		/**
		 * Index of the local used to store the top of the stack
		 */
		private int localIndex;

		public GlobalStack(int stackSize, int globalIndex, int localIndex) {
			this.stackSize = stackSize;
			this.globalIndex = globalIndex;
			this.localIndex = localIndex;
		}

		public int getStackSize() {
			return stackSize;
		}

		public void setStackSize(int stackSize) {
			this.stackSize = stackSize;
		}

		public int getGlobalIndex() {
			return globalIndex;
		}

		public void setGlobalIndex(int globalIndex) {
			this.globalIndex = globalIndex;
		}

		public int getLocalIndex() {
			return localIndex;
		}

		public void setLocalIndex(int localIndex) {
			this.localIndex = localIndex;
		}

	}

	/**
	 * Detect cases where the function use an external stack variable passed using a
	 * global variable.
	 * 
	 * @param instrs
	 * @return
	 */
	protected GlobalStack getGlobalStack(List<Instruction> instrs) {
		// supported global stack setups :
		// 1)
		// global.get {globalIndex}
		// i32.const {stackSize}
		// i32.sub
		// local.set {localIndex}
		// 2)
		// global.get {globalIndex}
		// i32.const {stackSize}
		// i32.sub
		// local.tee {localIndex}
		// 3)
		// global.get {globalIndex}
		// local.set {tmp1}
		// i32.const {stackSize}
		// local.set {tmp2}
		// local.get {tmp1}
		// local.get {tmp2}
		// i32.sub
		// local.set {localIndex}

		int globalIndex;
		int stackSize = -1;
		int localIndex;

		try {
			if (instrs.size() < 7) {
				return null;
			}

			int instrIndex = 0;

			// check that first instruction is a global.get
			Instruction instr = instrs.get(instrIndex);
			if (instr.getByte(0) != OPCODES.GLOBAL_GET) {
				return null;
			}
			globalIndex = (int) WasmInstructionUtil.getFirstInstrOperand(instr);

			// search for first i32.const instruction
			while (instrIndex < instrs.size() - 2) {
				instr = instrs.get(instrIndex);
				if (instr.getByte(0) == OPCODES.I32_CONST) {
					stackSize = (int) WasmInstructionUtil.getFirstInstrOperand(instr);
					instrIndex += 1;
					break;
				}
				instrIndex += 1;
			}
			if (stackSize == -1) {
				return null;
			}

			// search for first i32.sub instruction
			boolean found = false;
			while (instrIndex < instrs.size() - 1) {
				instr = instrs.get(instrIndex);
				if (instr.getByte(0) == OPCODES.I32_SUB) {
					instrIndex += 1;
					found = true;
					break;
				}
				instrIndex += 1;
			}

			if (!found) {
				return null;
			}

			// check that next instruction is either local.set or local.tee
			instr = instrs.get(instrIndex);
			if (instr.getByte(0) != OPCODES.LOCAL_SET && instr.getByte(0) != OPCODES.LOCAL_TEE) {
				return null;
			}
			localIndex = (int) WasmInstructionUtil.getFirstInstrOperand(instr);

			return new GlobalStack(stackSize, globalIndex, localIndex);
		} catch (MemoryAccessException | IOException e) {
			return null;
		}
	}

	private void detectGlobalStack() {
		InstructionIterator iter = program.getListing().getInstructions(function.getBody(), true);
		List<Instruction> instrs = new ArrayList<>();
		for (int i = 0; i < 10; i++) {
			if (!iter.hasNext()) {
				break;
			}
			instrs.add(iter.next());
		}
		globalStack = getGlobalStack(instrs);
	}

	public void performResolution(List<MetaInstruction> metaInstrs) {
		ArrayList<MetaInstruction> controlStack = new ArrayList<>();
		int valueStackDepth = 0; // number of items on the value stack

		for (MetaInstruction instr : metaInstrs) {
			switch (instr.getType()) {
			case PUSH:
				valueStackDepth++;
				break;
			case POP:
				valueStackDepth--;
				break;
			case BEGIN_LOOP:
				BeginLoopMetaInstruction beginLoop = (BeginLoopMetaInstruction) instr;
				beginLoop.stackDepthAtStart = valueStackDepth;
				controlStack.add(beginLoop);
				break;
			case BEGIN_BLOCK:
				controlStack.add(instr);
				break;
			case BR:
				BrMetaInstruction br = (BrMetaInstruction) instr;
				br.target = getTarget(br.level, controlStack, valueStackDepth);
				break;
			case ELSE:
				IfMetaInstruction ifStmt = (IfMetaInstruction) controlStack.get(controlStack.size() - 1);
				ElseMetaInstruction elseStmt = (ElseMetaInstruction) instr;
				ifStmt.elseInstr = elseStmt;
				elseStmt.ifInstr = ifStmt;
				break;
			case END:
				MetaInstruction begin = controlStack.remove(controlStack.size() - 1);
				switch (begin.getType()) {
				case BEGIN_BLOCK:
					BeginBlockMetaInstruction beginBlock = (BeginBlockMetaInstruction) begin;
					beginBlock.endLocation = instr.location;
					break;
				case IF:
					IfMetaInstruction ifInstr = (IfMetaInstruction) begin;
					ifInstr.endLocation = instr.location;
					break;
				case BEGIN_LOOP:
					BeginLoopMetaInstruction loop = (BeginLoopMetaInstruction) begin;
					loop.endLocation = instr.location;
					break;
				default:
					throw new RuntimeException("Invalid item on control stack " + begin);
				}
				break;
			case IF:
				controlStack.add(instr);
				break;
			case RETURN:
				if (valueStackDepth != 0) {
					if (valueStackDepth != 1) {
						throw new RuntimeException("Too many items on stack at return (at " + instr.location + ")");
					}
					ReturnMetaInstruction ret = (ReturnMetaInstruction) instr;
					ret.returnsVal = true;
					valueStackDepth--;
				}
				break;
			case CALL:
				CallMetaInstruction callInstr = (CallMetaInstruction) instr;
				int funcidx = callInstr.funcIdx;
				WasmFuncSignature func = WasmModuleData.get(program).getFunctionSignature(funcidx);
				callInstr.signature = func;
				// if we have a global stack make sure to back/restore the corresponding local
				callInstr.extraLocalSaveIndex= globalStack==null ? -1:globalStack.getLocalIndex();
				valueStackDepth -= func.getParams().length;
				valueStackDepth += func.getReturns().length;
				break;
			case CALL_INDIRECT:
				CallIndirectMetaInstruction callIndirect = (CallIndirectMetaInstruction) instr;
				int typeIdx = callIndirect.typeIdx;
				WasmFuncType type = WasmModuleData.get(program).getTypeSection().getType(typeIdx);
				callIndirect.signature = type;
				// if we have a global stack make sure to back/restore the corresponding local
				callIndirect.extraLocalSaveIndex= globalStack==null ? -1:globalStack.getLocalIndex();
				valueStackDepth--;
				valueStackDepth -= type.getParamTypes().length;
				valueStackDepth += type.getReturnTypes().length;
				break;
			case BR_TABLE:
				BrTableMetaInstruction brTableInstr = (BrTableMetaInstruction) instr;
				valueStackDepth--;
				brTableInstr.table = getBrTable(brTableInstr.rawCases, controlStack, valueStackDepth);
				break;
			}
		}
	}

	private static BrTarget getTarget(int level, ArrayList<MetaInstruction> controlStack, int valueStackDepth) {
		MetaInstruction targetInstr = controlStack.get(controlStack.size() - 1 - level);
		BranchDest target;
		int implicitPops;

		switch (targetInstr.getType()) {
		case BEGIN_BLOCK:
		case IF:
			// jump to the end of the corresponding block
			target = (BranchDest) targetInstr;
			implicitPops = 0;
			break;
		case BEGIN_LOOP:
			// jump back to the beginning of the loop and pop everything that's been pushed
			// since the start
			target = (BranchDest) targetInstr;
			BeginLoopMetaInstruction loop = (BeginLoopMetaInstruction) target;
			implicitPops = valueStackDepth - loop.stackDepthAtStart;
			break;
		default:
			throw new RuntimeException("Invalid item on control stack " + targetInstr);
		}

		return new BrTarget(target, implicitPops);
	}

	private static BrTable getBrTable(long[] rawCases, ArrayList<MetaInstruction> controlStack, int valueStackDepth) {
		BrTarget[] cases = new BrTarget[rawCases.length];
		for (int i = 0; i < rawCases.length; i++) {
			cases[i] = getTarget((int) rawCases[i], controlStack, valueStackDepth);
		}
		return new BrTable(cases);
	}

}

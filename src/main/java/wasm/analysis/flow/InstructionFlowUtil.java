package wasm.analysis.flow;

import java.io.IOException;

import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import wasm.analysis.WasmModuleData;
import wasm.analysis.flow.WasmFunctionFlowAnalysis.FlowContext;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.structures.WasmFuncType;
import wasm.pcodeInject.PcodeInjectLibraryWasm;
import wasm.pcodeInject.PcodeOpEmitter;
import wasm.util.WasmInstructionUtil;

public class InstructionFlowUtil {

	public static InstructionGenerator buildCallother(String callotherName, Program propgram, Instruction instr,
			FlowContext context) {
		try {
			InstructionGenerator res = null;

			switch (callotherName) {
			case PcodeInjectLibraryWasm.BR:
				res = new BrInstruction(instr, context);
				break;
			case PcodeInjectLibraryWasm.IF:
				res = new IfBlock(instr);
				break;
			case PcodeInjectLibraryWasm.ELSE:
				res = new ElseBlock(instr, context);
				break;
			case PcodeInjectLibraryWasm.RETURN:
				res = new ReturnInstruction(instr, context);
				break;
			case PcodeInjectLibraryWasm.CALL:
				res = new CallInstruction(propgram, instr, context);
				break;
			case PcodeInjectLibraryWasm.CALL_INDIRECT:
				res = new CallIndirectInstruction(propgram, instr, context);
				break;
			case PcodeInjectLibraryWasm.BR_TABLE:
				res = new BrTableInstruction(instr, context);
				break;
			}

			return res;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static BrTarget getTarget(int level, FlowContext context) {
		FlowBlock targetInstr = context.getFlowBlockFromEnd(level);
		int implicitPops;

		if (targetInstr instanceof IfBlock || targetInstr instanceof BeginBlock) {
			implicitPops = 0;
		} else if (targetInstr instanceof BeginLoopBlock) {
			implicitPops = context.valueStackDepth - ((BeginLoopBlock) targetInstr).stackDepthAtStart;
		} else {
			throw new RuntimeException("Invalid item on control stack " + targetInstr);
		}

		return new BrTarget(targetInstr, implicitPops);
	}

	public static BrTable getBrTable(Instruction instr, FlowContext context) throws IOException {
		// parse instruction to retrieve block identifiers
		int offset = 1;
		LEB128 numCases = WasmInstructionUtil.getLeb128Operand(instr, offset);
		offset += numCases.getLength();
		long[] rawCases = WasmInstructionUtil.getLeb128Operands(instr, (int) (numCases.asLong() + 1), offset);

		// Generate jump locations from block ids
		BrTarget[] cases = new BrTarget[rawCases.length];
		for (int i = 0; i < rawCases.length; i++) {
			cases[i] = getTarget((int) rawCases[i], context);
		}
		return new BrTable(cases);
	}

	/**
	 * Base interface for callother payloads used to generate pcode.
	 */
	public static interface InstructionGenerator {
		/**
		 * Get the name of the callother this generator coresponds to.
		 * 
		 * @return the callother name.
		 */
		public String getCallotherName();

		/**
		 * Generate the pcode instruction using a PcodeOpEmitter.
		 * 
		 * @param pcode
		 */
		public void synthesize(PcodeOpEmitter pcode);

		/**
		 * The Address of the instruction where this InstructionGenerator instance is
		 * used by the callother.
		 * 
		 * @return
		 */
		public Address getLocation();

	}

	/**
	 * Base class for InstructionGenerator that aren't flow blocks.
	 */
	public static abstract class BaseInstruction implements InstructionGenerator {
		protected Address location;

		protected BaseInstruction(Instruction instr) {
			location = instr.getAddress();
		}

		public Address getLocation() {
			return this.location;
		}
	}

	/**
	 * Base class for flow blocks.
	 */
	public static abstract class FlowBlock {
		protected Address location;
		protected Address endLocation;

		public FlowBlock(Instruction instr) {
			location = instr.getAddress();
		}

		public Address getEndLocation() {
			return endLocation;
		}

		public Address getLocation() {
			return this.location;
		}

		public abstract Address getBranchDest();

	}

	public static class BeginLoopBlock extends FlowBlock {
		int stackDepthAtStart = 0;

		public BeginLoopBlock(Instruction instr) {
			super(instr);
		}

		@Override
		public Address getBranchDest() {
			return location;
		}
	}

	public static class BeginBlock extends FlowBlock {

		public BeginBlock(Instruction instr) {
			super(instr);
		}

		@Override
		public Address getBranchDest() {
			return endLocation;
		}
	}

	public static class IfBlock extends FlowBlock implements InstructionGenerator {

		ElseBlock elseBlock = null;

		public IfBlock(Instruction instr) {
			super(instr);
		}

		@Override
		public String getCallotherName() {
			return PcodeInjectLibraryWasm.IF;
		}

		@Override
		public void synthesize(PcodeOpEmitter pcode) {
			// the slaspec jumps to inst_next on the positive edge, we only need to emit the
			// negative branch
			Address dest;
			if (elseBlock != null) {
				// jump to the instruction following the else byte
				dest = elseBlock.location.add(1);
			} else {
				// jump to the corresponding end
				dest = endLocation;
			}

			pcode.emitJump(dest);
		}

		@Override
		public Address getBranchDest() {
			return endLocation;
		}
	}

	public static class ElseBlock extends FlowBlock implements InstructionGenerator {
		IfBlock ifBlock = null;

		public ElseBlock(Instruction instr, FlowContext context) {
			super(instr);
			IfBlock ifStmt = (IfBlock) context.getLastFlowBlock();
			ifStmt.elseBlock = this;
			ifBlock = ifStmt;
		}

		@Override
		public void synthesize(PcodeOpEmitter pcode) {
			Address end = ifBlock.endLocation;
			// if we come across an else in normal control flow, simply jump to the end of
			// the if..else..end
			pcode.emitJump(end);
		}

		@Override
		public String getCallotherName() {
			return PcodeInjectLibraryWasm.ELSE;
		}

		@Override
		public Address getBranchDest() {
			// it seems that we can't jump to an else
			return null;
		}
	}

	public static class ReturnInstruction extends BaseInstruction {
		boolean returnsVal = false;

		public ReturnInstruction(Instruction instr, FlowContext context) {
			super(instr);
			if (context.valueStackDepth != 0) {
				if (context.valueStackDepth != 1) {
					throw new RuntimeException("Too many items on stack at return (at " + location + ")");
				}
				returnsVal = true;
				context.valueStackDepth--;
			}
		}

		@Override
		public String getCallotherName() {
			return PcodeInjectLibraryWasm.RETURN;
		}

		@Override
		public void synthesize(PcodeOpEmitter pcode) {
			if (returnsVal) {
				pcode.emitPop64("ret0");
			}
			pcode.emitRet();
		}
	}

	public static class BrInstruction extends BaseInstruction {
		BrTarget target;
		int level;

		public BrInstruction(Instruction instr, FlowContext context) throws IOException {
			super(instr);
			this.level = (int) WasmInstructionUtil.getFirstInstrOperand(instr);
			target = getTarget(level, context);
		}

		@Override
		public String getCallotherName() {
			return PcodeInjectLibraryWasm.BR;
		}

		@Override
		public void synthesize(PcodeOpEmitter pcode) {
			if (target.implicitPops != 0) {
				pcode.emitPopn(target.implicitPops);
			}

			pcode.emitJump(target.getDest());
		}
	}

	public static class CallInstruction extends BaseInstruction {
		int funcIdx;
		WasmFuncSignature signature;
		int extraLocalSaveIndex = -1;

		public CallInstruction(Program program, Instruction instr, FlowContext context) throws IOException {
			super(instr);
			this.funcIdx = (int) WasmInstructionUtil.getFirstInstrOperand(instr);

			WasmFuncSignature func = WasmModuleData.get(program).getFunctionSignature(funcIdx);
			signature = func;
			// if we have a global stack make sure to back/restore the corresponding local
			extraLocalSaveIndex = context.getStackLocalIndex();
			context.valueStackDepth -= func.getParams().length;
			context.valueStackDepth += func.getReturns().length;
		}

		@Override
		public String getCallotherName() {
			return PcodeInjectLibraryWasm.CALL;
		}

		@Override
		public void synthesize(PcodeOpEmitter pcode) {

			pcode.emitCall(signature, extraLocalSaveIndex);
		}
	}

	public static class CallIndirectInstruction extends BaseInstruction {
		int typeIdx;
		WasmFuncType signature;
		int extraLocalSaveIndex = -1;

		public CallIndirectInstruction(Program program, Instruction instr, FlowContext context) throws IOException {
			super(instr);
			typeIdx = (int) WasmInstructionUtil.getFirstInstrOperand(instr);

			WasmFuncType type = WasmModuleData.get(program).getTypeSection().getType(typeIdx);
			signature = type;
			// if we have a global stack make sure to back/restore the corresponding local
			extraLocalSaveIndex = context.getStackLocalIndex();
			context.valueStackDepth--;
			context.valueStackDepth -= type.getParamTypes().length;
			context.valueStackDepth += type.getReturnTypes().length;
		}

		@Override
		public String getCallotherName() {
			return PcodeInjectLibraryWasm.CALL_INDIRECT;
		}

		@Override
		public void synthesize(PcodeOpEmitter pcode) {
			pcode.emitCallIndirect(signature, extraLocalSaveIndex);
		}
	}

	public static class BrTableInstruction extends BaseInstruction {
		BrTable table;

		public BrTableInstruction(Instruction instr, FlowContext context) throws IOException {
			super(instr);
			context.valueStackDepth--;
			table = getBrTable(instr, context);
		}

		@Override
		public String getCallotherName() {
			return PcodeInjectLibraryWasm.BR_TABLE;
		}

		@Override
		public void synthesize(PcodeOpEmitter pcode) {
			pcode.emitBrTable(table);
		}

	}

	public static class BrTarget {
		FlowBlock target = null;
		int implicitPops;

		public BrTarget(FlowBlock target, int pops) {
			this.implicitPops = pops;
			this.target = target;
		}

		@Override
		public String toString() {
			return target + " (pops " + implicitPops + ")";
		}

		public Address getDest() {
			return target.getBranchDest();
		}

		public int getNumPops() {
			return implicitPops;
		}
	}

	public static class BrTable {
		private BrTarget[] cases;

		public BrTable(BrTarget[] cases) {
			this.cases = cases;
		}

		public int numCases() {
			return cases.length - 1; // default case
		}

		public BrTarget[] getCases() {
			return cases;
		}
	}
}

package wasm.analysis.flow;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.MD5Utilities;
import wasm.analysis.flow.InstructionFlowUtil.BeginBlock;
import wasm.analysis.flow.InstructionFlowUtil.BeginLoopBlock;
import wasm.analysis.flow.InstructionFlowUtil.FlowBlock;
import wasm.analysis.flow.InstructionFlowUtil.InstructionGenerator;
import wasm.util.Initializable;
import wasm.util.WasmInstructionUtil;
import wasm.util.WasmInstructionUtil.OPCODES;

public class WasmFunctionFlowAnalysis implements Initializable<Function> {

	/**
	 * Duration in milliseconds between two reset checks
	 */
	private static long RESET_CHECK_INTERVAL = TimeUnit.SECONDS.toMillis(3);

	public static class MetaKey {
		protected Address address;
		protected String callotherName;

		public MetaKey(Address address, String callotherName) {
			super();
			this.address = address;
			this.callotherName = callotherName;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((address == null) ? 0 : address.hashCode());
			result = prime * result + ((callotherName == null) ? 0 : callotherName.hashCode());
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
			if (callotherName == null) {
				if (other.callotherName != null)
					return false;
			} else if (!callotherName.equals(other.callotherName))
				return false;
			return true;
		}

	}

	private Program program;
	private Function function;
	private Map<MetaKey, InstructionGenerator> metaInstrsMap = new HashMap<>();
	private GlobalStack globalStack;
	private long lastResetCheck = 0;
	private String bodyHash;
	private long spOffset;

	public InstructionGenerator getMetaInstruction(Address address, String callotherName) {
		return metaInstrsMap.get(new MetaKey(address, callotherName));
	}

	public GlobalStack getGlobalStack() {
		return globalStack;
	}

	@Override
	public boolean needReset(Function param) {

		// don't check too often as this blocks all thread from accessing this instance
		// and hash computation can be expensive for big functions
		if (System.currentTimeMillis() < lastResetCheck + RESET_CHECK_INTERVAL) {
			return false;
		}
		lastResetCheck = System.currentTimeMillis();

		if (!Objects.areEqual(bodyHash, computeBodyHash(param))) {
			return true;
		}

		return false;
	}

	@Override
	public void init(Function func) {
		program = func.getProgram();
		this.function = func;

		spOffset = program.getLanguage().getRegister("SP").getOffset();

		detectGlobalStack();

		analyzeFLow();

		lastResetCheck = System.currentTimeMillis();
		bodyHash = computeBodyHash(func);
	}

	// --- global stack analysis ---

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

	// --- flow analysis ---

	/**
	 * Storage that holds flow analysis contextual information.
	 */
	public static class FlowContext {

		/**
		 * The number of element stored on the stack (an element is considered to be 8
		 * bits long)
		 */
		public int valueStackDepth = 0;

		/**
		 * The stack containing all currently opened blocks in the order from wich they
		 * were opened.
		 */
		protected ArrayList<FlowBlock> controlStack = new ArrayList<>();

		/**
		 * Index of the local register used to store the pointer to the stack (-1
		 * meaning no local).
		 */
		protected int stackLocalIndex = -1;

		public FlowBlock popFlowBlock() {
			return controlStack.remove(controlStack.size() - 1);
		}

		public FlowBlock getLastFlowBlock() {
			return controlStack.get(controlStack.size() - 1);
		}

		public FlowBlock getFlowBlockFromEnd(int level) {
			return controlStack.get(controlStack.size() - 1 - level);
		}

		public void addFlowBlock(FlowBlock block) {
			controlStack.add(block);
		}

		public int getStackLocalIndex() {
			return stackLocalIndex;
		}
	}

	/**
	 * Analyzes the functions instructions to recover block and overall flow to
	 * generate InstructionGenerators that will used to inject pcode in their
	 * corresponding callothers.
	 */
	private void analyzeFLow() {
		FlowContext context = new FlowContext();
		if (globalStack != null) {
			context.stackLocalIndex = globalStack.localIndex;
		}
		List<InstructionGenerator> res = new ArrayList<>();
		InstructionIterator iter = program.getListing().getInstructions(function.getBody(), true);
		boolean flowEnded = false;
		while (iter.hasNext() && !flowEnded) {
			Instruction instr = iter.next();
			// process special instruction that modify the flow
			// but don't require pcode injection
			processSpecialFlowInstruction(context, instr);

			for (PcodeOp op : instr.getPcode()) {

				// apply stack shift
				context.valueStackDepth += getStackShift(op);

				if (op.getOpcode() == PcodeOp.CALLOTHER) {
					String name = program.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset());
					InstructionGenerator callother = InstructionFlowUtil.buildCallother(name, program, instr, context);
					// ignore trap callothers
					if (callother != null) {
						res.add(callother);
						if (callother instanceof FlowBlock) {
							context.addFlowBlock((FlowBlock) callother);
						}
					}
				}
			}
		}

		for (InstructionGenerator ig : res) {
			metaInstrsMap.put(new MetaKey(ig.getLocation(), ig.getCallotherName()), ig);
		}
	}

	/**
	 * Checks if the instruction is a control flow instruction that doesn't
	 * correspond to a callother and apply it to the context.
	 * 
	 * @param context The current flow context at the instruction location.
	 * @param instr   The instruction being checked.
	 */
	private void processSpecialFlowInstruction(FlowContext context, Instruction instr) {
		try {
			switch (instr.getByte(0)) {
			case OPCODES.END:
				// make sure that this is a basic end not the return
				if (instr.getPcode().length == 0) {
					FlowBlock begin = context.popFlowBlock();
					begin.endLocation = instr.getAddress();
				}
				break;
			case OPCODES.LOOP:
				BeginLoopBlock beginLoop = new BeginLoopBlock(instr);
				beginLoop.stackDepthAtStart = context.valueStackDepth;
				context.addFlowBlock(beginLoop);
				break;
			case OPCODES.BLOCK:
				context.addFlowBlock(new BeginBlock(instr));
				break;
			}
		} catch (MemoryAccessException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Compute the stack shift in number of elements represented by op pcode
	 * operation.
	 * 
	 * @param op The pcode operation beeing checked
	 * @return An integer representing the number of element (an element is
	 *         considered to be 8 bits long) added or removed form the stack.
	 */
	private int getStackShift(PcodeOp op) {
		if (op.getOpcode() != PcodeOp.INT_SUB && op.getOpcode() != PcodeOp.INT_ADD) {
			return 0;
		}
		Varnode i0 = op.getInputs()[0];
		// input[0] should be SP
		if (!i0.isRegister() || i0.getOffset() != spOffset) {
			return 0;
		}
		// input[1] should be a constant
		Varnode i1 = op.getInputs()[1];
		if (!i1.isConstant()) {
			return 0;
		}
		int shift = (int) (i1.getOffset()) / 8;
		Varnode out = op.getOutput();
		// output should be SP
		if (!out.isRegister() || out.getOffset() != spOffset) {
			return 0;
		}
		return op.getOpcode() == PcodeOp.INT_SUB ? shift : -shift;
	}

	// --- function hash ---

	/**
	 * Generate the function bytecode's MD5 hash.
	 * 
	 * @param func
	 * @return the MD5 hash digest
	 */
	private String computeBodyHash(Function func) {
		byte[] bodyBytes = getFunctionBytes(func);
		try {
			return MD5Utilities.getMD5Hash(new ByteArrayInputStream(bodyBytes));
		} catch (IOException e) {
			return null;
		}
	}

	/**
	 * Recover all the functions bytes.
	 * 
	 * @param func
	 * @return
	 */
	private byte[] getFunctionBytes(Function func) {
		AddressSetView body = func.getBody();

		// first resolve the total bit size
		long bitSize = 0;
		for (AddressRange addrRange : body.getAddressRanges()) {
			bitSize += addrRange.getMaxAddress().getOffset() - addrRange.getMinAddress().getOffset();
		}

		byte[] funcBytes = new byte[(int) bitSize];
		long index = 0;
		for (AddressRange addrRange : body.getAddressRanges()) {
			Address start = addrRange.getMinAddress();
			long size = addrRange.getMaxAddress().getOffset() - start.getOffset();
			try {
				program.getMemory().getBytes(start, funcBytes, (int) index, (int) size);
			} catch (MemoryAccessException e) {
				// we ignore read failure here.
				// the bytes will remain unitialized for this range
			}
			index += size;
		}
		return funcBytes;
	}
}

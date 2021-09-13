package wasm.analysis.flow;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import wasm.analysis.flow.InstructionFlowUtil.InstructionGenerator;
import wasm.analysis.flow.WasmFunctionFlowAnalysis.GlobalStack;
import wasm.util.ConcurrentInitStore;
import wasm.util.Initializable;
import wasm.util.ProgramSingleton;

public class WasmFlowAnalysis implements Initializable<Program> {
	private static final ProgramSingleton<WasmFlowAnalysis> SINGLETON = new ProgramSingleton<WasmFlowAnalysis>() {

		@Override
		protected WasmFlowAnalysis create() {
			return new WasmFlowAnalysis();
		}
	};

	public static WasmFlowAnalysis get(Program program) {
		return SINGLETON.get(program);
	}

	protected ConcurrentInitStore<Function, WasmFunctionFlowAnalysis> functionFlowStorage = new ConcurrentInitStore<Function, WasmFunctionFlowAnalysis>() {

		@Override
		protected WasmFunctionFlowAnalysis create() {
			return new WasmFunctionFlowAnalysis();
		}

		// use entry point address as key for storage
		protected Object toStorageKey(Function param) {
			if (param == null) {
				return null;
			}
			return param.getEntryPoint();
		}

	};

	@Override
	public void init(Program param) {
		// nothing to do here
	}

	public static InstructionGenerator getMetaInstruction(Program program, Address address, String callotherName) {
		WasmFlowAnalysis flowAnalysis = SINGLETON.get(program);
		if (flowAnalysis == null) {
			return null;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return null;
		}
		WasmFunctionFlowAnalysis functionAnalysis = flowAnalysis.functionFlowStorage.get(function);
		if (functionAnalysis == null) {
			return null;
		}
		return functionAnalysis.getMetaInstruction(address, callotherName);
	}

	public static GlobalStack getGlobalStack(Program program, Address address) {
		WasmFlowAnalysis flowAnalysis = SINGLETON.get(program);
		if (flowAnalysis == null) {
			return null;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return null;
		}
		WasmFunctionFlowAnalysis functionAnalysis = flowAnalysis.functionFlowStorage.get(function);
		if (functionAnalysis == null) {
			return null;
		}
		return functionAnalysis.getGlobalStack();
	}

}

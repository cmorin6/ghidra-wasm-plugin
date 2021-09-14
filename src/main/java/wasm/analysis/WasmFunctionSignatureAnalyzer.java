package wasm.analysis;

import java.util.Map;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import wasm.WasmLoader;
import wasm.format.sections.WasmNameSection;

public class WasmFunctionSignatureAnalyzer extends AbstractAnalyzer {

	private static String DESCRIPTION = "Apply function signature retieved from '.type' and '.name'.";

	public WasmFunctionSignatureAnalyzer() {
		super(WasmLoader.WEBASSEMBLY + " function signature Analyzer", DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		
		// Make sure to execute after the ApplyDataArchiveAnalyzer.
		// This is safe as we merge FunctionSignature so this will Analyzer will
		// make sure that the FunctionSignature applied by the ApplyDataArchiveAnalyzer
		// is valid or provide a default one if none was found.
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return WasmLoader.WEBASSEMBLY.equals(program.getExecutableFormat());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		WasmModuleData wmd = WasmModuleData.get(program);
		WasmNameSection mameSec = wmd.getNameSection();
		FunctionIterator iter = program.getFunctionManager().getFunctions(set, true);
		while (iter.hasNext()) {
			Function func = iter.next();
			WasmFunctionData funcData = wmd.getFunctionByEntryPoint(func.getEntryPoint());
			if (funcData == null) {
				// this should never happen
				continue;
			}
			setupFunctionSignature(program, func, funcData, mameSec);

		}
		return true;
	}

	protected void setupFunctionSignature(Program program, Function function, WasmFunctionData functionData,
			WasmNameSection section) {
		// force calling convention
		if (Function.DEFAULT_CALLING_CONVENTION_STRING.contentEquals(function.getCallingConventionName())
				|| Function.UNKNOWN_CALLING_CONVENTION_STRING.contentEquals(function.getCallingConventionName())) {
			try {
				function.setCallingConvention("__asmA");
			} catch (InvalidInputException e) {

			}
		}

		// set function signature
		Map<Integer, String> paramNames = null;
		if (section != null) {
			paramNames = section.getFunctionLocalNames(functionData.getIndex());
		}
		FunctionSignatureImpl fsig = new FunctionSignatureImpl(function.getName(), functionData.getFuncType(),
				paramNames);
		if (fsig.merge(function.getSignature(true))) {
			ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(function.getEntryPoint(), fsig,
					SourceType.ANALYSIS, false, false);
			cmd.applyTo(program);
		}
	}
}

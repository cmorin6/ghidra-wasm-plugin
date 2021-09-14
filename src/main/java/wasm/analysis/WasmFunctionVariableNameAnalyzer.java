package wasm.analysis;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import wasm.WasmLoader;
import wasm.format.WasmEnums.ValType;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.structures.WasmNameSegment.NAME_TYPES;

public class WasmFunctionVariableNameAnalyzer extends AbstractAnalyzer {

	private static String DESCRIPTION = "Extract and apply names contained in the '.name' section to function's locals.";

	private DecompInterface dif;

	public WasmFunctionVariableNameAnalyzer() {
		super(WasmLoader.WEBASSEMBLY + " function local name Analyzer", DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		// only for WEBASSEMBLY executables
		if (!WasmLoader.WEBASSEMBLY.equals(program.getExecutableFormat())) {
			return false;
		}
		// name section must exist
		return program.getMemory().getBlock(WasmNameSection.SECTION_NAME) != null;
	}

	protected DecompInterface getInitializedDecompInterface(Program prog) {
		if (dif == null) {
			dif = new DecompInterface();
			dif.openProgram(prog);
		}
		return dif;
	}

	protected void cleanup() {
		if (dif != null) {
			dif.dispose();
			dif = null;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		WasmModuleData wmd = WasmModuleData.get(program);
		WasmNameSection mameSec = wmd.getNameSection();

		// skip if the name section doesn't contain a LOCAL_NAMES entry.
		if (mameSec.getNamePayload(NAME_TYPES.LOCAL_NAMES) == null) {
			return true;
		}

		try {
			FunctionIterator iter = program.getFunctionManager().getFunctions(set, true);
			while (iter.hasNext()) {
				Function func = iter.next();
				WasmFunctionData funcData = wmd.getFunctionByEntryPoint(func.getEntryPoint());
				if (funcData == null) {
					// this should never happen
					continue;
				}
				Map<Integer, String> localNames = mameSec.getFunctionLocalNames(funcData.getIndex());
				if (localNames == null || localNames.isEmpty()) {
					continue;
				}

				Map<Integer, String> filteredLocalNames = filterNewVariables(func, funcData, localNames);
				if (filteredLocalNames.isEmpty()) {
					// skip if there is no name to apply after filtering
					continue;
				}
				applyLocalNames(program, func, funcData, filteredLocalNames);
			}
		} finally {
			cleanup();
		}
		return true;
	}

	protected Map<Integer, String> filterNewVariables(Function func, WasmFunctionData funcData,
			Map<Integer, String> localNames) {
		// compute variable names and local indexes that are already assigned
		Set<String> usedVarNames = new HashSet<>();
		Set<Integer> usedLocalIndexes = new HashSet<>();
		for (Variable var : func.getLocalVariables()) {
			usedVarNames.add(var.getName());
			Varnode vn = var.getFirstStorageVarnode();
			if (vn.isRegister()) {
				usedLocalIndexes.add((int) (vn.getOffset() / 8));
			}
		}

		int paramsCount = funcData.getFuncSignature().getParams().length;

		Map<Integer, String> filteredLocalNames = new HashMap<>();
		for (Entry<Integer, String> entry : localNames.entrySet()) {
			int localIndex = entry.getKey();
			String localName = entry.getValue();
			// skip if this entry corresponds to a function parameter
			if (localIndex < paramsCount) {
				continue;
			}

			// only the first 63 locals are defined as registers
			// TODO: create variables with offsets in register space instead ?
			if (localIndex > 63) {
				continue;
			}

			// skip if there is already a variable defined for this local
			if (usedLocalIndexes.contains(localIndex)) {
				continue;
			}

			// skip if there is already a variable with the same name
			if (usedVarNames.contains(localName)) {
				continue;
			}
			filteredLocalNames.put(localIndex, localName);
		}

		return filteredLocalNames;
	}

	protected void applyLocalNames(Program program, Function function, WasmFunctionData funcData,
			Map<Integer, String> localNames) {
		Map<Integer, Integer> localsFirstUse = getLocalFirstUses(program, function);

		List<ValType> localsTypes = funcData.getBody().getLocalTypes();

		int paramCount = funcData.getFuncSignature().getParams().length;

		for (Entry<Integer, String> entry : localNames.entrySet()) {
			int localIndex = entry.getKey();
			String varName = entry.getValue();
			int firstUse = localsFirstUse.getOrDefault(localIndex, 0);
			DataType dt = localsTypes.get(localIndex - paramCount).toDatatType();
			Register reg = program.getLanguage().getRegister("l" + localIndex);

			try {
				LocalVariableImpl var = new LocalVariableImpl(varName, firstUse, dt, reg, program);
				function.addLocalVariable(var, SourceType.ANALYSIS);
			} catch (InvalidInputException | DuplicateNameException e) {
				e.printStackTrace();
			}
		}
	}

	protected Map<Integer, Integer> getLocalFirstUses(Program prog, Function func) {
		// Note:
		// We retrieve first uses of local using the decompiler to make sure
		// that it picks up the new variable name. Otherwise, the variable name is only
		// shown in listing.

		Map<Integer, Integer> res = new HashMap<>();
		// create or reuse existing DecompInterface
		DecompInterface decomp = getInitializedDecompInterface(prog);
		// decompile the function
		HighFunction hf = decomp.decompileFunction(func, 10, null).getHighFunction();

		// loop through HighSymbol to retrieve variable corresponding to a local
		Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
		while (it.hasNext()) {
			HighSymbol hs = it.next();
			HighVariable hv = hs.getHighVariable();
			if (hv == null) {
				continue;
			}
			Varnode vn = hv.getRepresentative();
			if (vn.isRegister() && hv instanceof HighLocal) {
				int localIndex = (int) (vn.getOffset() / 8);
				if (res.get(localIndex) == null) {
					HighLocal hl = (HighLocal) hv;
					long useOffset = hl.getPCAddress().getOffset() - func.getEntryPoint().getOffset();
					res.put(localIndex, (int) useOffset);
				}

			}
		}
		return res;
	}
}

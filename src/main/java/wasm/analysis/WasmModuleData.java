package wasm.analysis;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import wasm.file.WasmModule;
import wasm.format.Utils;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmExportSection;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.WasmTypeSection;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.util.Initializable;
import wasm.util.ProgramSingleton;

/**
 * Singleton to reuse metadata parse from module file across analysis tasks.
 * 
 * @author cedric
 *
 */
public class WasmModuleData implements Initializable<Program> {

	private static final ProgramSingleton<WasmModuleData> SINGLETON = new ProgramSingleton<WasmModuleData>() {

		@Override
		protected WasmModuleData create() {
			return new WasmModuleData();
		}

	};

	public static WasmModuleData get(Program program) {
		return SINGLETON.get(program);
	}

	protected Program program;
	protected WasmModule module;
	// TODO: initialized flag

	/**
	 * List of WasmFunctionData corresponding to all functions defined in this
	 * module stored in the function index order.
	 */
	protected List<WasmFunctionData> functions = new ArrayList<>();

	protected List<WasmFunctionData> importedFunctions = new ArrayList<>();

	protected List<WasmFunctionData> realFunctions = new ArrayList<>();

	public WasmModuleData() {
		// needed for singleton
	}

	// Only use this from WasmLoader. Use WasmModuleData.get() in analysis.
	public WasmModuleData(Program prog, WasmModule module) {
		initInternal(prog, module);
	}

	public void init(Program prog) {
		Memory mem = prog.getMemory();
		Address moduleStart = mem.getBlock(".module").getStart();
		ByteProvider memByteProvider = new MemoryByteProvider(mem, moduleStart);
		BinaryReader memBinaryReader = new BinaryReader(memByteProvider, true);
		try {
			initInternal(prog, new WasmModule(memBinaryReader));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	protected void initInternal(Program prog, WasmModule mod) {
		this.program = prog;
		this.module = mod;
		retrieveFunctions();
		retrieveFunctionTypes();
		retrieveFunctionNames();
		retrieveFunctionExportName();
	}

	public WasmModule getModule() {
		return module;
	}

	public WasmFuncSignature getFunctionSignature(int index) {
		if (index >= functions.size()) {
			return null;
		}
		return functions.get(index).getFuncSignature();
	}

	public WasmTypeSection getTypeSection() {
		return (WasmTypeSection) module.getSection(WasmSectionId.SEC_TYPE).getPayload();
	}

	public List<WasmFunctionData> getFunctions() {
		return functions;
	}

	public List<WasmFunctionData> getImportedFunctions() {
		return importedFunctions;
	}

	public List<WasmFunctionData> getRealFunctions() {
		return realFunctions;
	}

	protected void retrieveFunctions() {
		// functions index start with imported functions
		WasmSection importSec = module.getSection(WasmSectionId.SEC_IMPORT);
		if (importSec != null) {
			WasmImportSection importSection = (WasmImportSection) importSec.getPayload();
			for (WasmImportEntry entry : importSection.getEntries()) {
				if (entry.getKind() == WasmExternalKind.EXT_FUNCTION) {
					int index = functions.size();
					Address entrypoint = Utils.toAddr(program, Utils.IMPORTS_BASE + index * Utils.IMPORT_STUB_LEN);
					WasmFunctionData func = WasmFunctionData.fromImport(index, entry, entrypoint);
					functions.add(func);
					importedFunctions.add(func);
				}
			}
		}

		// then function defined in the function section
		WasmFunctionSection funcSec = (WasmFunctionSection) module.getSection(WasmSectionId.SEC_FUNCTION).getPayload();
		WasmSection codeSec = module.getSection(WasmSectionId.SEC_CODE);
		WasmCodeSection codeSection = (WasmCodeSection) codeSec.getPayload();
		long code_offset = codeSec.getPayloadOffset();
		for (int i = 0; i < codeSection.getFunctions().size(); ++i) {
			int index = functions.size();
			WasmFunctionBody body = codeSection.getFunctions().get(i);
			// TODO: make sure funcSec and type sec always have the same size
			int typeId = funcSec.getTypeIdx(i);
			long method_offset = code_offset + body.getOffset();
			Address entrypoint = Utils.toAddr(program, Utils.METHOD_ADDRESS + method_offset);
			WasmFunctionData func = WasmFunctionData.fromBody(index, body, entrypoint, typeId);
			functions.add(func);
			realFunctions.add(func);
		}

	}

	public void retrieveFunctionTypes() {
		WasmSection typeSection = module.getSection(WasmSectionId.SEC_TYPE);
		if (typeSection == null) {
			return;
		}
		WasmTypeSection typeSec = (WasmTypeSection) typeSection.getPayload();
		for (WasmFunctionData func : functions) {
			func.funcType = typeSec.getType(func.typeIndex);
		}
	}

	public void retrieveFunctionNames() {
		WasmNameSection nameSection = module.getNameSection();
		if (nameSection == null) {
			return;
		}
		for (WasmFunctionData func : functions) {
			func.name = nameSection.getFunctionName(func.index);
		}
	}

	public void retrieveFunctionExportName() {
		WasmSection exports = module.getSection(WasmSectionId.SEC_EXPORT);
		if (exports == null) {
			return;
		}
		WasmExportSection exportSection = (WasmExportSection) exports.getPayload();
		for (WasmFunctionData func : functions) {
			WasmExportEntry entry = exportSection.findMethod(func.index);
			if (entry != null) {
				func.exportName = entry.getName();
			}
		}
	}

}

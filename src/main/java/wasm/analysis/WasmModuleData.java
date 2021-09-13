package wasm.analysis;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import wasm.file.WasmModule;
import wasm.file.WasmModule.WasmSectionKey;
import wasm.format.Utils;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmExportSection;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmPayload;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmTypeSection;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.util.Initializable;
import wasm.util.ProgramSingleton;

/**
 * Singleton to reuse metadata parse from module file across analysis tasks.
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

	protected WasmNameSection nameSection;
	protected WasmTypeSection typeSection;
	protected WasmFunctionSection funcSection;
	protected WasmImportSection importSection;
	protected WasmCodeSection codeSection;
	protected WasmExportSection exportSection;

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
		program = prog;
		initSections(module);
		initInternal();
	}

	public void init(Program prog) {
		program = prog;
		initSections();
		initInternal();
	}

	public WasmFuncSignature getFunctionSignature(int index) {
		if (index >= functions.size()) {
			return null;
		}
		return functions.get(index).getFuncSignature();
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

	public WasmNameSection getNameSection() {
		return nameSection;
	}

	public WasmTypeSection getTypeSection() {
		return typeSection;
	}

	public WasmFunctionSection getFuncSection() {
		return funcSection;
	}

	public WasmImportSection getImportSection() {
		return importSection;
	}

	public WasmCodeSection getCodeSection() {
		return codeSection;
	}

	public WasmExportSection getExportSection() {
		return exportSection;
	}

	protected void initSections() {
		nameSection = loadSectionFromBlock(WasmNameSection.SECTION_NAME, WasmNameSection.class);
		typeSection = loadSectionFromBlock(WasmTypeSection.SECTION_NAME, WasmTypeSection.class);
		funcSection = loadSectionFromBlock(WasmFunctionSection.SECTION_NAME, WasmFunctionSection.class);
		importSection = loadSectionFromBlock(WasmImportSection.SECTION_NAME, WasmImportSection.class);
		codeSection = loadSectionFromBlock(WasmCodeSection.SECTION_NAME, WasmCodeSection.class);
		exportSection = loadSectionFromBlock(WasmExportSection.SECTION_NAME, WasmExportSection.class);
	}

	protected void initSections(WasmModule module) {
		nameSection = module.getNameSection();
		typeSection = module.getSectionPayload(WasmSectionKey.TYPE);
		funcSection = module.getSectionPayload(WasmSectionKey.FUNCTION);
		importSection = module.getSectionPayload(WasmSectionKey.IMPORT);
		codeSection = module.getSectionPayload(WasmSectionKey.CODE);
		exportSection = module.getSectionPayload(WasmSectionKey.EXPORT);
	}

	protected void initInternal() {
		retrieveFunctions();
		retrieveFunctionTypes();
		retrieveFunctionNames();
		retrieveFunctionExportName();
	}

	protected void retrieveFunctions() {
		// functions index start with imported functions
		if (importSection != null) {
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
		for (int i = 0; i < codeSection.getFunctions().size(); ++i) {
			int index = functions.size();
			WasmFunctionBody body = codeSection.getFunctions().get(i);
			// TODO: make sure funcSec and type sec always have the same size
			int typeId = funcSection.getTypeIdx(i);
			long method_offset = body.getOffset();
			Address entrypoint = Utils.toAddr(program, Utils.METHOD_ADDRESS + method_offset);
			WasmFunctionData func = WasmFunctionData.fromBody(index, body, entrypoint, typeId);
			functions.add(func);
			realFunctions.add(func);
		}

	}

	public void retrieveFunctionTypes() {
		if (typeSection == null) {
			return;
		}
		for (WasmFunctionData func : functions) {
			func.funcType = typeSection.getType(func.typeIndex);
		}
	}

	public void retrieveFunctionNames() {
		if (nameSection == null) {
			return;
		}
		for (WasmFunctionData func : functions) {
			func.name = nameSection.getFunctionName(func.index);
		}
	}

	public void retrieveFunctionExportName() {
		if (exportSection == null) {
			return;
		}
		for (WasmFunctionData func : functions) {
			WasmExportEntry entry = exportSection.findMethod(func.index);
			if (entry != null) {
				func.exportName = entry.getName();
			}
		}
	}

	@SuppressWarnings("unchecked")
	protected <T extends WasmPayload> T loadSectionFromBlock(String blockName, Class<T> clazz) {
		MemoryBlock block = program.getMemory().getBlock(blockName);
		if (block == null) {
			return null;
		}

		try (ByteProvider bp = new InputStreamByteProvider(block.getData(), block.getSize())) {
			WasmSection section = new WasmSection(new BinaryReader(bp, true));
			WasmPayload res = section.getPayload();
			if (res == null) {
				return null;
			}
			if (!clazz.isInstance(res)) {
				return null;
			}
			return (T) res;
		} catch (IOException e) {
			return null;
		}
	}

}

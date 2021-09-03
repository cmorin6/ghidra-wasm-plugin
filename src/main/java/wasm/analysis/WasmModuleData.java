package wasm.analysis;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import wasm.file.WasmModule;
import wasm.format.Utils;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.WasmTypeSection;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.util.ConcurrentInitStore;
import wasm.util.Initializable;

/**
 * Singleton to reuse metadata parse from module file across analysis tasks.
 * 
 * @author cedric
 *
 */
public class WasmModuleData implements Initializable<Program> {

	private static final ConcurrentInitStore<Program, WasmModuleData> SINGLETON = new ConcurrentInitStore<Program, WasmModuleData>() {

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
	private ArrayList<WasmFuncSignature> functionSigs = null;

	public WasmModuleData() {

	}

	public void init(Program param) {
		this.program = param;
		Memory mem = program.getMemory();
		Address moduleStart = mem.getBlock(".module").getStart();
		ByteProvider memByteProvider = new MemoryByteProvider(mem, moduleStart);
		BinaryReader memBinaryReader = new BinaryReader(memByteProvider, true);
		module = null;
		try {
			module = new WasmModule(memBinaryReader);
			findFunctionSignatures();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public WasmModule getModule() {
		return module;
	}

	public WasmFuncSignature getFunctionSignature(int index) {
		return functionSigs.get(index);
	}

	public WasmTypeSection getTypeSection() {
		return (WasmTypeSection) module.getSection(WasmSectionId.SEC_TYPE).getPayload();
	}

	public void findFunctionSignatures() {
		functionSigs = new ArrayList<>();
		WasmSection importSection = module.getSection(WasmSectionId.SEC_IMPORT);
		WasmImportSection importSec = (WasmImportSection) (importSection == null ? null : importSection.getPayload());
		WasmTypeSection typeSec = (WasmTypeSection) module.getSection(WasmSectionId.SEC_TYPE).getPayload();
		if (importSec != null) {
			List<WasmImportEntry> imports = importSec.getEntries();
			int funcIdx = 0;
			for (WasmImportEntry entry : imports) {
				if (entry.getKind() != WasmExternalKind.EXT_FUNCTION)
					continue;
				int typeIdx = entry.getFunctionType();
				WasmFuncType funcType = typeSec.getType(typeIdx);
				Address addr = Utils.toAddr(program, Utils.IMPORTS_BASE + Utils.IMPORT_STUB_LEN * funcIdx);

				functionSigs.add(new WasmFuncSignature(funcType.getParamTypes(), funcType.getReturnTypes(),
						entry.getName(), addr));
				funcIdx++;
			}
		}

		WasmFunctionSection funcSec = (WasmFunctionSection) module.getSection(WasmSectionId.SEC_FUNCTION).getPayload();
		if (funcSec != null) {
			FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
			int i = 0;
			// non-imported functions will show up first and in order since we are iterating
			// by entry point
			for (Function func : funcIter) {
				if (i >= funcSec.getTypeCount())
					break;
				int typeidx = funcSec.getTypeIdx(i);
				WasmFuncType funcType = typeSec.getType(typeidx);

				functionSigs.add(new WasmFuncSignature(funcType.getParamTypes(), funcType.getReturnTypes(), null,
						func.getEntryPoint()));
				i++;
			}
		}
	}
}

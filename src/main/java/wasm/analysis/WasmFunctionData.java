package wasm.analysis;

import ghidra.program.model.address.Address;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmFunctionData {

	/** global index of this function (the one used for calls) */
	protected int index;

	/** index of this functions's type in the .type section */
	protected int typeIndex = -1;

	/** start address for the function body */
	protected Address entryPoint;

	/** name defined in .name section */
	protected String name;

	/** the actual function type for thie function */
	protected WasmFuncType funcType;

	protected boolean imported;

	protected String importModuleName;

	protected String importFunctionName;

	protected String exportName;

	protected WasmFunctionBody body;

	protected WasmFuncSignature signature;

	public static WasmFunctionData fromImport(int index, WasmImportEntry importEntry, Address address) {
		WasmFunctionData res = new WasmFunctionData();
		res.index = index;
		res.entryPoint = address;
		res.imported = true;
		res.importModuleName = importEntry.getModuleName();
		res.importFunctionName = importEntry.getFunctionName();
		res.typeIndex = importEntry.getFunctionType();
		return res;
	}

	public static WasmFunctionData fromBody(int index, WasmFunctionBody body, Address address, int typeId) {
		WasmFunctionData res = new WasmFunctionData();
		res.index = index;
		res.entryPoint = address;
		res.imported = false;
		res.typeIndex = typeId;
		res.body = body;
		return res;
	}

	public WasmFunctionData() {

	}

	public int getIndex() {
		return index;
	}

	public int getTypeIndex() {
		return typeIndex;
	}

	public Address getEntryPoint() {
		return entryPoint;
	}

	public String getName() {
		return name;
	}

	public WasmFuncType getFuncType() {
		return funcType;
	}

	public boolean isImported() {
		return imported;
	}

	public String getImportModuleName() {
		return importModuleName;
	}

	public String getImportFunctionName() {
		return importFunctionName;
	}

	public String getFullImportName() {
		return importModuleName + "." + importFunctionName;
	}

	public String getExportName() {
		return exportName;
	}

	public WasmFunctionBody getBody() {
		return body;
	}

	public WasmFuncSignature getFuncSignature() {
		if (signature == null && funcType != null) {
			signature = new WasmFuncSignature(funcType.getParamTypes(), funcType.getReturnTypes(), entryPoint);
		}
		return signature;
	}

}

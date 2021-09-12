package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.commons.WasmList.ListItem;
import wasm.format.commons.WasmString;

public class WasmImportEntry implements ListItem {

	WasmString moduleName;
	WasmString fieldName;
	WasmExternalKind kind;

	LEB128 function_type;
	WasmResizableLimits memory_type;
	WasmTableType table_type;
	WasmGlobalType global_type;

	public WasmImportEntry(BinaryReader reader) throws IOException {
		moduleName = new WasmString("module_name", reader);
		fieldName = new WasmString("field_name", reader);
		kind = WasmExternalKind.values()[reader.readNextByte()];
		switch (kind) {
		case EXT_FUNCTION:
			function_type = LEB128.readUnsignedValue(reader);
			break;
		case EXT_MEMORY:
			memory_type = new WasmResizableLimits(reader);
			break;
		case EXT_GLOBAL:
			global_type = new WasmGlobalType(reader);
			break;
		case EXT_TABLE:
			table_type = new WasmTableType(reader);
			break;
		default:
			break;

		}
	}

	public WasmExternalKind getKind() {
		return kind;
	}

	public int getFunctionType() {
		if (kind != WasmExternalKind.EXT_FUNCTION) {
			throw new RuntimeException("Cannot get function type of non-function import");
		}
		return (int) function_type.asLong();
	}

	public WasmResizableLimits getMemoryDefinition() {
		return memory_type;
	}

	public String getModuleName() {
		return moduleName.getValue();
	}

	public String getFunctionName() {
		return fieldName.getValue();
	}

	public String getName() {
		return moduleName.getValue() + "__" + fieldName.getValue();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(getStructName(), 0);
		moduleName.addToStructure(structure);
		fieldName.addToStructure(structure);
		structure.add(BYTE, 1, "kind", null);
		switch (kind) {
		case EXT_FUNCTION:
			structure.add(new ArrayDataType(BYTE, function_type.getLength(), BYTE.getLength()), "type", null);
			break;
		case EXT_MEMORY:
			structure.add(memory_type.toDataType(), memory_type.toDataType().getLength(), "type", null);
			break;
		case EXT_GLOBAL:
			structure.add(global_type.toDataType(), global_type.toDataType().getLength(), "type", null);
			break;
		case EXT_TABLE:
			structure.add(table_type.toDataType(), table_type.toDataType().getLength(), "type", null);
			break;
		default:
			break;
		}
		return structure;
	}

	@Override
	public String getStructName() {
		return "import_" + moduleName.getValue() + "_" + fieldName.getValue();
	}

}

package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import wasm.format.commons.WasmList.ListItem;
import wasm.format.commons.WasmString;

public class WasmExportEntry implements ListItem {

	protected int arrayIndex;
	protected WasmString name;
	protected WasmExternalKind kind;
	protected LEB128 index;

	public enum WasmExternalKind {
		KIND_FUNCTION, KIND_TABLE, KIND_MEMORY, KIND_GLOBAL
	}

	public WasmExportEntry(int arrayIndex, BinaryReader reader) throws IOException {
		this.arrayIndex = arrayIndex;
		name = new WasmString(reader);
		kind = WasmExternalKind.values()[reader.readNextByte()];
		index = LEB128.readUnsignedValue(reader);
	}

	public String getName() {
		return name.getValue();
	}

	public int getIndex() {
		return (int) index.asLong();
	}

	public WasmExternalKind getType() {
		return kind;
	}

	public DataType toDataType() {
		Structure structure = new StructureDataType("export_" + arrayIndex, 0);
		name.addToStructure(structure);
		structure.add(BYTE, 1, "kind", null);
		structure.add(new ArrayDataType(BYTE, index.getLength(), BYTE.getLength()), "index", null);
		return structure;
	}

	@Override
	public String getStructName() {
		return "export_" + arrayIndex;
	}

}

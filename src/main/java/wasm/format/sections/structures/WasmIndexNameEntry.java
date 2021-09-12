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

public class WasmIndexNameEntry implements ListItem {

	protected String structName;
	protected int arrayIndex;

	protected LEB128 idx;
	protected WasmString name;

	public WasmIndexNameEntry(int index, String structName, BinaryReader reader) throws IOException {
		arrayIndex = index;
		this.structName = structName;
		idx = LEB128.readUnsignedValue(reader);
		name = new WasmString(reader);
	}

	public DataType toDataType() {
		Structure structure = new StructureDataType(getStructName(), 0);
		structure.add(new ArrayDataType(BYTE, idx.getLength(), BYTE.getLength()), structName + "_idx", null);
		name.addToStructure(structure);
		return structure;
	}

	public int getIndex() {
		return (int) idx.asLong();
	}

	public String getName() {
		return name.getValue();
	}

	@Override
	public String getStructName() {
		return structName + "_name_" + arrayIndex;
	}

}

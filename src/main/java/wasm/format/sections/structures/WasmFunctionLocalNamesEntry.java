package wasm.format.sections.structures;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmList;
import wasm.format.commons.WasmList.ListItem;

public class WasmFunctionLocalNamesEntry implements ListItem {

	protected int index;
	protected LEB128 funcIndex;
	protected WasmList<WasmIndexNameEntry> localEntries;
	protected Map<Integer, String> localNames = new HashMap<>();

	public WasmFunctionLocalNamesEntry(int index, BinaryReader reader) throws IOException {
		this.index = index;
		funcIndex = LEB128.readUnsignedValue(reader);
		localEntries = new WasmList<>(reader, (i, br) -> new WasmIndexNameEntry(i, "local", br));
		for (WasmIndexNameEntry entry : localEntries) {
			localNames.put(entry.getIndex(), entry.getName());
		}
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(getStructName(), 0);
		structure.add(new ArrayDataType(BYTE, funcIndex.getLength(), BYTE.getLength()), "func_index", null);
		localEntries.addToStructure(structure);
		return structure;
	}

	public int getFuncIndex() {
		return (int) funcIndex.asLong();
	}

	public List<WasmIndexNameEntry> getLocalEntries() {
		return localEntries;
	}

	public Map<Integer, String> getLocalNames() {
		return localNames;
	}

	@Override
	public String getStructName() {
		return "func_locals_" + index;
	}
}

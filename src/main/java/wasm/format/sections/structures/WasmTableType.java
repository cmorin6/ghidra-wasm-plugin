package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmList.ListItem;

public class WasmTableType implements ListItem {

	int index;
	byte element_type;
	WasmResizableLimits limits;

	public WasmTableType(BinaryReader reader) throws IOException {
		this(-1, reader);
	}

	public WasmTableType(int index, BinaryReader reader) throws IOException {
		this.index = index;
		element_type = reader.readNextByte();
		limits = new WasmResizableLimits(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(getStructName(), 0);
		structure.add(BYTE, 1, "element_type", null);
		structure.add(limits.toDataType(), limits.toDataType().getLength(), "limits", null);
		return structure;
	}

	@Override
	public String getStructName() {
		if (index == -1) {
			return "table_type";
		}
		return "table_type" + index;
	}

}

package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmInstrBlock;
import wasm.format.commons.WasmList.ListItem;

public class WasmElementSegment implements ListItem {

	private LEB128 index;
	private WasmInstrBlock offset;
	private LEB128 size;
	private List<LEB128> data = new ArrayList<>();

	public WasmElementSegment(BinaryReader reader) throws IOException {
		index = LEB128.readUnsignedValue(reader);
		offset = new WasmInstrBlock(reader);
		size = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < size.asUInt32(); i++) {
			data.add(LEB128.readUnsignedValue(reader));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(getStructName(), 0);
		structure.add(new ArrayDataType(BYTE, index.getLength(), BYTE.getLength()), "index", null);
		structure.add(offset.toDataType(), "offset", null);
		structure.add(new ArrayDataType(BYTE, size.getLength(), BYTE.getLength()), "size", null);
		for (int i = 0; i < size.asUInt32(); i++) {
			structure.add(new ArrayDataType(BYTE, data.get(i).getLength(), BYTE.getLength()), "element_" + i, null);
		}
		return structure;
	}

	@Override
	public String getStructName() {
		return "element_segment_" + index.asLong();
	}
}

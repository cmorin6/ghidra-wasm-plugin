package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmInstrBlock;
import wasm.format.commons.WasmList.ListItem;

public class WasmDataSegment implements ListItem {

	private int arrayIndex;
	private LEB128 index;
	private WasmInstrBlock offset;
	private LEB128 size;
	private byte[] data;

	public WasmDataSegment(int arrayIndex, BinaryReader reader) throws IOException {
		this.arrayIndex = arrayIndex;
		index = LEB128.readUnsignedValue(reader);
		offset = new WasmInstrBlock(reader);
		size = LEB128.readUnsignedValue(reader);
		data = reader.readNextByteArray(size.asInt32());
	}

	public long getIndex() {
		return index.asLong();
	}

	public long getOffset() {
		return offset.getReturnValue();
	}

	public long getSize() {
		return size.asLong();
	}

	public byte[] getData() {
		return data;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(getStructName(), 0);
		structure.add(new ArrayDataType(BYTE, index.getLength(), BYTE.getLength()), "count", null);
		structure.add(offset.toDataType(), "offset", null);
		structure.add(new ArrayDataType(BYTE, size.getLength(), BYTE.getLength()), "size", null);
		if (data.length != 0) {
			structure.add(new ArrayDataType(BYTE, data.length, BYTE.getLength()), "data", null);
		}
		return structure;
	}

	@Override
	public String getStructName() {
		return "data_segment_" + arrayIndex;
	}

}

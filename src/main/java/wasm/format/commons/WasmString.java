package wasm.format.commons;

import static ghidra.app.util.bin.StructConverter.BYTE;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

/**
 * Wrapper object for parsing a string stored as a Leb128 for the size followed
 * by the corresponding number of bytes for the string content.
 */
public class WasmString {

	protected String fieldName;
	protected LEB128 size;
	protected String content;

	public WasmString(BinaryReader reader) throws IOException {
		this("name", reader);
	}

	public WasmString(String fieldName, BinaryReader reader) throws IOException {
		this.fieldName = fieldName;
		size = LEB128.readUnsignedValue(reader);
		content = new String(reader.readNextByteArray(size.asUInt32()));
	}

	public void addToStructure(Structure structure) {
		structure.add(new ArrayDataType(BYTE, size.getLength(), BYTE.getLength()), fieldName + "_len", null);
		structure.add(new ArrayDataType(CharDataType.dataType, (int) size.asLong(), 1), fieldName, null);
	}

	public DataType toDataType(String structName) {
		Structure structure = new StructureDataType(structName, 0);
		addToStructure(structure);
		return structure;
	}

	public String getValue() {
		return content;
	}
}

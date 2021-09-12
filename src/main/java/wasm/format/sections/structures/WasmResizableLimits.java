package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmList.ListItem;

public class WasmResizableLimits implements ListItem {

	int arrayIndex;
	String entityName;
	byte flags;
	LEB128 initial;
	LEB128 maximum;

	public WasmResizableLimits(BinaryReader reader) throws IOException {
		this(-1, "limits", reader);
	}

	public WasmResizableLimits(int arrayIndex, String entityName, BinaryReader reader) throws IOException {
		this.arrayIndex = arrayIndex;
		this.entityName = entityName;
		flags = reader.readNextByte();
		initial = LEB128.readUnsignedValue(reader);
		if (flags == 1) {
			maximum = LEB128.readUnsignedValue(reader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(getStructName(), 0);
		structure.add(BYTE, 1, "flags", null);
		structure.add(new ArrayDataType(BYTE, initial.getLength(), BYTE.getLength()), "initial", null);
		if (flags == 1) {
			structure.add(new ArrayDataType(BYTE, maximum.getLength(), BYTE.getLength()), "maximum", null);
		}
		return structure;
	}

	public byte getFlags() {
		return flags;
	}

	public long getInitial() {
		return initial.asLong();
	}

	public long getMaximum() {
		if (maximum == null) {
			return -1;
		}
		return maximum.asLong();
	}

	public long getAllocSize() {
		return Math.max(getInitial(), getMaximum());
	}

	@Override
	public String toString() {
		return "(initial=" + getInitial() + ", max=" + getMaximum() + ")";
	}

	@Override
	public String getStructName() {
		if (arrayIndex == -1) {
			return entityName;
		}
		return entityName + " " + arrayIndex;
	}

}

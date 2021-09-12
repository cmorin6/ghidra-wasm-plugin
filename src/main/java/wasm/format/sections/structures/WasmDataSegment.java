package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmList.ListItem;

public class WasmDataSegment implements ListItem {

	private int arrayIndex;
	private LEB128 index;
	private LEB128 offset;
	private long fileOffset;
	private long offsetCodeSize;
	private LEB128 size;
	private byte[] data;

	public WasmDataSegment(int arrayIndex, BinaryReader reader) throws IOException {
		this.arrayIndex = arrayIndex;
		index = LEB128.readUnsignedValue(reader);
		parseOffset(reader);
		size = LEB128.readUnsignedValue(reader);
		data = reader.readNextByteArray(size.asInt32());
	}

	public long getIndex() {
		return index.asLong();
	}

	public long getFileOffset() {
		return fileOffset;
	}

	public long getOffset() {
		return (offset == null) ? -1 : offset.asLong();
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
		structure.add(new ArrayDataType(BYTE, (int) offsetCodeSize, BYTE.getLength()), "offset", null);
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

	protected void parseOffset(BinaryReader reader) throws IOException {
		long start = reader.getPointerIndex();

		byte offsetOpcode = reader.readNextByte();
		/*
		 * Offset expression is an expr, which must be a constant expression evaluating
		 * to an i32. For this datatype, there are only two possibilities: i32.const
		 * (0x41) or global.get (0x23).
		 */
		if (offsetOpcode == 0x41) {
			/* i32.const */
			offset = LEB128.readUnsignedValue(reader);
			byte endByte = reader.readNextByte();
			if (endByte != 0x0b) {
				Msg.warn(this, "Data segment at file offset " + reader.getPointerIndex() + " does not look normal!");
			}
		} else if (offsetOpcode == 0x23) {
			/* global.get: offset is left as null */
			// skip globalidx
			offset = LEB128.readUnsignedValue(reader);
			byte endByte = reader.readNextByte();
			if (endByte != 0x0b) {
				Msg.warn(this, "Data segment at file offset " + reader.getPointerIndex() + " does not look normal!");
			}
		} else {
			Msg.warn(this, "Unhandled data segment offset: opcode " + offsetOpcode + " at file offset "
					+ reader.getPointerIndex());
			while (true) {
				byte endByte = reader.readNextByte();
				if (endByte == 0x0b)
					break;
			}
		}
		offsetCodeSize = reader.getPointerIndex() - start;
	}

}

package wasm.format.commons;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * Structure for parsing a sequence of instruction that evaluates to a constant
 * value.
 */
public class WasmInstrBlock implements StructConverter {

	/**
	 * Value returned from this code.
	 */
	private long returnValue;

	/**
	 * Number of bytes for this instruction sequence
	 */
	private long consumedSize;

	public WasmInstrBlock(BinaryReader reader) throws IOException {
		long start = reader.getPointerIndex();

		byte offsetOpcode = reader.readNextByte();
		/*
		 * Offset expression is an expr, which must be a constant expression evaluating
		 * to an i32. For this datatype, there are only two possibilities: i32.const
		 * (0x41) or global.get (0x23).
		 */
		if (offsetOpcode == 0x41) {
			/* i32.const */
			returnValue = LEB128.readUnsignedValue(reader).asLong();
			byte endByte = reader.readNextByte();
			if (endByte != 0x0b) {
				Msg.warn(this, "Data segment at file offset " + reader.getPointerIndex() + " does not look normal!");
			}
		} else if (offsetOpcode == 0x23) {
			/* global.get: offset is left as null */
			// skip globalidx
			returnValue = LEB128.readUnsignedValue(reader).asLong();
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
		consumedSize = reader.getPointerIndex() - start;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return new ArrayDataType(BYTE, (int) consumedSize, BYTE.getLength());
	}

	public long getReturnValue() {
		return returnValue;
	}

}

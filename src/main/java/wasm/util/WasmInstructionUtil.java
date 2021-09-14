package wasm.util;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.listing.Instruction;

public class WasmInstructionUtil {

	public static interface OPCODES {
		public final static byte BLOCK = 0x02;
		public final static byte LOOP = 0x03;
		public final static byte IF = 0x04;
		public final static byte ELSE = 0x05;
		
		public final static byte CALL = 0x10;

		public final static byte END = 0xB;

		public final static byte LOCAL_GET = 0x20;
		public final static byte LOCAL_SET = 0x21;
		public final static byte LOCAL_TEE = 0x22;

		public final static byte GLOBAL_GET = 0x23;

		public final static byte I32_CONST = 0x41;

		public final static byte I32_SUB = 0x6B;

	}

	public static LEB128 getLeb128Operand(Instruction instr, int offset) throws IOException {
		byte[] buf = new byte[16];
		instr.getBytes(buf, offset);
		return LEB128.readUnsignedValue(new BinaryReader(new ByteArrayProvider(buf), true));
	}

	public static long[] getLeb128Operands(Instruction instr, int count) throws IOException {
		return getLeb128Operands(instr, count, 1);
	}

	public static long[] getLeb128Operands(Instruction instr, int count, int offset) throws IOException {
		long[] res = new long[count];
		for (int i = 0; i < count; i++) {
			LEB128 leb128 = getLeb128Operand(instr, offset);
			offset += leb128.getLength();
			res[i] = leb128.asLong();
		}
		return res;
	}

	public static long getFirstInstrOperand(Instruction instr) throws IOException {
		return getLeb128Operand(instr, 1).asLong();
	}

}

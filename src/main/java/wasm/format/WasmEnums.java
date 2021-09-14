package wasm.format;

import java.util.HashMap;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.Float4DataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.Undefined4DataType;

public class WasmEnums {
	public enum WasmExternalKind {
		EXT_FUNCTION, EXT_TABLE, EXT_MEMORY, EXT_GLOBAL
	}

	public enum ValType {
		i32(0x7f), i64(0x7e), f32(0x7d), f64(0x7c),

		funcref(0x70), externref(0x6f);

		private static final HashMap<Integer, ValType> BY_BYTE = new HashMap<>();
		public final int typeByte;

		static {
			for (ValType t : ValType.values()) {
				BY_BYTE.put(t.typeByte, t);
			}
		}

		private ValType(int v) {
			this.typeByte = v;
		}

		public static ValType fromByte(int b) {
			return BY_BYTE.get(b);
		}

		public DataType toDatatType() {
			switch (this) {
			case f32:
				return Float4DataType.dataType;
			case f64:
				return DoubleDataType.dataType;
			case i32:
				return Undefined4DataType.dataType;
			case i64:
				return LongDataType.dataType;
			default:
				return Undefined4DataType.dataType;
			}
		}
	}
}

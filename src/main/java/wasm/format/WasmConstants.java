package wasm.format;

public class WasmConstants {
	public final static String WASM_MAGIC_BASE = new String(new byte[] { 0, 0x61, 0x73, 0x6D });
	public final static int WASM_VERSION_LENGTH = 4;
	public final static String MACHINE = "1";
	public final static int WASM_MEM_BLOCK_SIZE = 0x10000;

}

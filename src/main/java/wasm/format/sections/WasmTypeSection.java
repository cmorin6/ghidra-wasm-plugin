package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.commons.WasmList;
import wasm.format.sections.structures.WasmFuncType;

public class WasmTypeSection extends WasmList<WasmFuncType> implements WasmPayload {

	public static final String SECTION_NAME = ".type";

	public WasmTypeSection(BinaryReader reader) throws IOException {
		super(reader, (i, r) -> new WasmFuncType(i, r));
	}

	public WasmFuncType getType(int typeidx) {
		return get(typeidx);
	}

	public int getNumTypes() {
		return size();
	}

	@Override
	public String getName() {
		return SECTION_NAME;
	}
}

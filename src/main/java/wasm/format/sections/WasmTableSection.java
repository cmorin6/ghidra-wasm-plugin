package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.commons.WasmList;
import wasm.format.sections.structures.WasmTableType;

public class WasmTableSection extends WasmList<WasmTableType> implements WasmPayload {

	public WasmTableSection(BinaryReader reader) throws IOException {
		super(reader, (i, r) -> new WasmTableType(i, r));
	}

	@Override
	public String getName() {
		return ".table";
	}

}

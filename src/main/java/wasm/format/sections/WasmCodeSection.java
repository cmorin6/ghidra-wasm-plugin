package wasm.format.sections;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.commons.WasmList;
import wasm.format.sections.structures.WasmFunctionBody;

public class WasmCodeSection extends WasmList<WasmFunctionBody> implements WasmPayload {

	public WasmCodeSection(BinaryReader reader) throws IOException {
		super(reader, (i, r) -> new WasmFunctionBody(r));
	}

	public List<WasmFunctionBody> getFunctions() {
		return this;
	}

	@Override
	public String getName() {
		return ".code";
	}

}

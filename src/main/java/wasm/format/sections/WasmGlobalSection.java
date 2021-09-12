package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.commons.WasmList;
import wasm.format.sections.structures.WasmGlobalSegment;

public class WasmGlobalSection extends WasmList<WasmGlobalSegment> implements WasmPayload {

	public WasmGlobalSection(BinaryReader reader) throws IOException {
		super(reader, (i, r) -> new WasmGlobalSegment(i, r));
	}

	@Override
	public String getName() {
		return ".global";
	}

}

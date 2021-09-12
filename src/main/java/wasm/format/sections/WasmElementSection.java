package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.commons.WasmList;
import wasm.format.sections.structures.WasmElementSegment;

public class WasmElementSection extends WasmList<WasmElementSegment> implements WasmPayload {

	public WasmElementSection(BinaryReader reader) throws IOException {
		super(reader, (i, r) -> new WasmElementSegment(r));
	}

	@Override
	public String getName() {
		return ".element";
	}

}

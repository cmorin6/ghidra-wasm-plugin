package wasm.format.sections;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.commons.WasmList;
import wasm.format.sections.structures.WasmDataSegment;

public class WasmDataSection extends WasmList<WasmDataSegment> implements WasmPayload {

	public WasmDataSection(BinaryReader reader) throws IOException {
		super(reader, (i, r) -> new WasmDataSegment(i,r));

	}

	public List<WasmDataSegment> getSegments() {
		return Collections.unmodifiableList(this);
	}

	@Override
	public String getName() {
		return ".data";
	}

}

package wasm.format.sections;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.commons.WasmList;
import wasm.format.sections.structures.WasmResizableLimits;

public class WasmLinearMemorySection extends WasmList<WasmResizableLimits> implements WasmPayload {

	public WasmLinearMemorySection(BinaryReader reader) throws IOException {
		super(reader, (i, r) -> new WasmResizableLimits(i, "mem_limits", r));
	}

	@Override
	public String getName() {
		return ".linearMemory";
	}

	public List<WasmResizableLimits> getMemoryDefinitions() {
		return this;
	}

}

package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.commons.WasmList;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmExportEntry.WasmExternalKind;

public class WasmExportSection extends WasmList<WasmExportEntry> implements WasmPayload {

	public WasmExportSection(BinaryReader reader) throws IOException {
		super(reader, (i, r) -> new WasmExportEntry(i, r));
	}

	public WasmExportEntry findMethod(int id) {
		for (WasmExportEntry entry : this) {
			if (entry.getType() == WasmExternalKind.KIND_FUNCTION && entry.getIndex() == id) {
				return entry;
			}
		}
		return null;
	}

	@Override
	public String getName() {
		return ".export";
	}

}

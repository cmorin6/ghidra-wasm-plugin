package wasm.format.sections;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.commons.WasmList;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmImportSection extends WasmList<WasmImportEntry> implements WasmPayload {

	public WasmImportSection(BinaryReader reader) throws IOException {
		super(reader, (i, r) -> new WasmImportEntry(r));
	}

	public int getCount() {
		return size();
	}

	public List<WasmImportEntry> getEntries() {
		return this;
	}

	@Override
	public String getName() {
		return ".import";
	}

	public int getImportedFunctionCount() {
		int res = 0;
		for (WasmImportEntry entry : this) {
			if (entry.getKind() == WasmExternalKind.EXT_FUNCTION) {
				res += 1;
			}
		}
		return res;
	}
}

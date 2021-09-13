package wasm.file;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.WasmHeader;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmCustomSection;
import wasm.format.sections.WasmDataSection;
import wasm.format.sections.WasmElementSection;
import wasm.format.sections.WasmExportSection;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmGlobalSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmLinearMemorySection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmPayload;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.WasmStartSection;
import wasm.format.sections.WasmTableSection;
import wasm.format.sections.WasmTypeSection;

public class WasmModule {

	private WasmHeader header;
	private List<WasmSection> sections = new ArrayList<WasmSection>();

	public WasmModule(BinaryReader reader) throws IOException {
		header = new WasmHeader(reader);
		while (reader.getPointerIndex() < reader.length()) {
			sections.add(new WasmSection(reader));
		}
	}

	public WasmNameSection getNameSection() {
		for (WasmSection section : sections) {
			if (section.getId() == WasmSection.WasmSectionId.SEC_CUSTOM
					&& section.getPayload() instanceof WasmNameSection) {
				return (WasmNameSection) section.getPayload();
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public <T extends WasmPayload> T getSectionPayload(WasmSectionKey<T> key) {
		for (WasmSection section : sections) {
			if (section.getId() == key.getSectionId()) {
				return (T) section.getPayload();
			}
		}
		return null;
	}

	public WasmTypeSection getTypeSection() {
		for (WasmSection section : sections) {
			if (section.getId() == WasmSection.WasmSectionId.SEC_TYPE) {
				return (WasmTypeSection) section.getPayload();
			}
		}
		return null;
	}

	/* TODO: put sections to map */
	public WasmSection getSection(WasmSection.WasmSectionId id) {
		for (WasmSection section : sections) {
			if (section.getId() == id) {
				return section;
			}
		}
		return null;
	}

	public WasmHeader getHeader() {
		return header;
	}

	public List<WasmSection> getSections() {
		return sections;
	}

	public static class WasmSectionKey<PayloadType extends WasmPayload> {
		public final static WasmSectionKey<WasmCustomSection> CUSTOM = new WasmSectionKey<>(WasmSectionId.SEC_CUSTOM);
		public final static WasmSectionKey<WasmTypeSection> TYPE = new WasmSectionKey<>(WasmSectionId.SEC_TYPE);
		public final static WasmSectionKey<WasmImportSection> IMPORT = new WasmSectionKey<>(WasmSectionId.SEC_IMPORT);
		public final static WasmSectionKey<WasmFunctionSection> FUNCTION = new WasmSectionKey<>(
				WasmSectionId.SEC_FUNCTION);
		public final static WasmSectionKey<WasmTableSection> TABLE = new WasmSectionKey<>(WasmSectionId.SEC_TABLE);
		public final static WasmSectionKey<WasmLinearMemorySection> LINEARMEMORY = new WasmSectionKey<>(
				WasmSectionId.SEC_LINEARMEMORY);
		public final static WasmSectionKey<WasmGlobalSection> GLOBAL = new WasmSectionKey<>(WasmSectionId.SEC_GLOBAL);
		public final static WasmSectionKey<WasmExportSection> EXPORT = new WasmSectionKey<>(WasmSectionId.SEC_EXPORT);
		public final static WasmSectionKey<WasmStartSection> START = new WasmSectionKey<>(WasmSectionId.SEC_START);
		public final static WasmSectionKey<WasmElementSection> ELEMENT = new WasmSectionKey<>(
				WasmSectionId.SEC_ELEMENT);
		public final static WasmSectionKey<WasmCodeSection> CODE = new WasmSectionKey<>(WasmSectionId.SEC_CODE);
		public final static WasmSectionKey<WasmDataSection> DATA = new WasmSectionKey<>(WasmSectionId.SEC_DATA);

		protected WasmSectionId sectionId;

		private WasmSectionKey(WasmSectionId sectionId) {
			this.sectionId = sectionId;
		}

		public WasmSectionId getSectionId() {
			return sectionId;
		}
	}

}

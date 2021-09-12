package wasm.file;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.WasmHeader;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;

public class WasmModule  {
	
	private WasmHeader header;
	private List<WasmSection> sections = new ArrayList<WasmSection>();
	
	public WasmModule(BinaryReader reader) throws IOException {
		header = new WasmHeader(reader);
		while (reader.getPointerIndex() < reader.length()) {
			sections.add(new WasmSection(reader));
		}
	}
	
	public WasmNameSection getNameSection() {
		for(WasmSection section: sections) {
			if(section.getId() == WasmSection.WasmSectionId.SEC_CUSTOM
					&& section.getPayload() instanceof WasmNameSection) {
				return (WasmNameSection)section.getPayload();
			}
		}
		return null;
	}

	/*TODO: put sections to map*/
	public WasmSection getSection(WasmSection.WasmSectionId id) {
		for (WasmSection section: sections) {
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
}

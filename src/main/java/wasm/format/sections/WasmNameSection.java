package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmString;
import wasm.format.sections.structures.WasmNameSegment;
import wasm.format.sections.structures.WasmNameSegment.NAME_TYPES;
import wasm.format.sections.structures.WasmNameSegment.WasmFunctionNamesPayload;
import wasm.format.sections.structures.WasmNameSegment.WasmLocalNamesPayload;
import wasm.format.sections.structures.WasmNameSegment.WasmNamePayload;

public class WasmNameSection extends WasmCustomSection {

	public static final String SECTION_NAME = ".name";

	private List<WasmNameSegment> nameSegments = new ArrayList<>();

	public WasmNameSection(WasmString name, BinaryReader r, int contentlen) throws IOException {
		super(name, r, contentlen);
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(this.contents), true);
		int i = 0;
		while (reader.getPointerIndex() < this.contents.length) {
			nameSegments.add(new WasmNameSegment(i, reader));
			i++;
		}
	}

	@Override
	public void addToStructure(Structure structure)
			throws IllegalArgumentException, DuplicateNameException, IOException {
		name.addToStructure(structure);
		for (int i = 0; i < nameSegments.size(); i++) {
			structure.add(nameSegments.get(i).toDataType(), nameSegments.get(i).toDataType().getLength(),
					"segment_" + i, null);
		}
	}

	public String getFunctionName(int idx) {
		WasmNamePayload funcNames = getNamePayload(NAME_TYPES.FUNCTION_NAMES);
		if (funcNames == null || !(funcNames instanceof WasmFunctionNamesPayload)) {
			return null;
		}
		return ((WasmFunctionNamesPayload) funcNames).getName(idx);
	}

	public Map<Integer, String> getFunctionLocalNames(int idx) {
		WasmNamePayload funcNames = getNamePayload(NAME_TYPES.LOCAL_NAMES);
		if (funcNames == null || !(funcNames instanceof WasmLocalNamesPayload)) {
			return null;
		}
		return ((WasmLocalNamesPayload) funcNames).getLocalNames(idx);
	}

	@Override
	public String getName() {
		return SECTION_NAME;
	}

	public List<WasmNameSegment> getNameSegments() {
		return nameSegments;
	}

	public WasmNamePayload getNamePayload(int type) {
		for (WasmNameSegment seg : nameSegments) {
			if (seg.getPayloadType() == type) {
				return seg.getPayload();
			}
		}
		return null;
	}
}

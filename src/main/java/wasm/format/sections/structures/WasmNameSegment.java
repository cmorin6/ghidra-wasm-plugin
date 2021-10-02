package wasm.format.sections.structures;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmList;
import wasm.format.commons.WasmString;

public class WasmNameSegment implements StructConverter {

	public static interface NAME_TYPES {
		public static final int MODULE_NAME = 0;
		public static final int FUNCTION_NAMES = 1;
		public static final int LOCAL_NAMES = 2;
		public static final int GLOBAL_NAMES = 7;
		public static final int DATA_NAMES = 9;
	}

	protected int index;
	protected LEB128 lebType;
	protected LEB128 lebSize;
	protected WasmNamePayload payload;

	public WasmNameSegment(int index, BinaryReader reader) throws IOException {
		this.index = index;
		lebType = LEB128.readUnsignedValue(reader);
		int type = lebType.asUInt32();
		lebSize = LEB128.readUnsignedValue(reader);
		byte[] subContents = reader.readNextByteArray((int) lebSize.asLong());
		BinaryReader subReader = new BinaryReader(new ByteArrayProvider(subContents), true);
		switch (type) {
		case NAME_TYPES.MODULE_NAME:
			payload = new WasmModuleNamePayload(subReader);
			break;
		case NAME_TYPES.FUNCTION_NAMES:
			payload = new ListIndexNamePayload("func",subReader);
			break;
		case NAME_TYPES.LOCAL_NAMES:
			payload = new WasmLocalNamesPayload(subReader);
			break;
		case NAME_TYPES.GLOBAL_NAMES:
			payload = new ListIndexNamePayload("global",subReader);
			break;
		case NAME_TYPES.DATA_NAMES:
			payload = new ListIndexNamePayload("data",subReader);
			break;

		default:
			break;
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("name_segment_" + index, 0);
		structure.add(new ArrayDataType(BYTE, lebType.getLength(), BYTE.getLength()), "type", null);
		structure.add(new ArrayDataType(BYTE, lebSize.getLength(), BYTE.getLength()), "size", null);
		if (payload != null) {
			payload.addToStructure(structure);
		} else {
			structure.add(new ArrayDataType(BYTE, (int) lebSize.asLong(), BYTE.getLength()), "content", null);
		}
		return structure;
	}

	public int getPayloadType() {
		return (int) lebType.asLong();
	}

	public WasmNamePayload getPayload() {
		return payload;
	}

	// -- payload classes --

	public static interface WasmNamePayload {
		public void addToStructure(Structure structure) throws DuplicateNameException, IOException;
	}

	public static class ListIndexNamePayload extends WasmList<WasmIndexNameEntry> implements WasmNamePayload {

		protected HashMap<Integer, String> namesMap = new HashMap<>();

		public ListIndexNamePayload(String contentType, BinaryReader reader) throws IOException {
			super(reader, (index, brd) -> new WasmIndexNameEntry(index, contentType, brd));
			for (WasmIndexNameEntry entry : this) {
				namesMap.put(entry.getIndex(), entry.getName());
			}
		}

		public String getName(int index) {
			return namesMap.get(index);
		}
		
		public HashMap<Integer, String> getNamesMap() {
			return namesMap;
		}

	}

	public static class WasmModuleNamePayload extends WasmString implements WasmNamePayload {

		public WasmModuleNamePayload(BinaryReader reader) throws IOException {
			super(reader);
		}
	}

	public static class WasmLocalNamesPayload extends WasmList<WasmFunctionLocalNamesEntry> implements WasmNamePayload {

		protected HashMap<Integer, Map<Integer, String>> funcMap = new HashMap<>();

		public WasmLocalNamesPayload(BinaryReader reader) throws IOException {
			super(reader, (i, r) -> new WasmFunctionLocalNamesEntry(i, r));
			for (WasmFunctionLocalNamesEntry entry : this) {
				funcMap.put(entry.getFuncIndex(), entry.getLocalNames());
			}
		}

		public List<WasmFunctionLocalNamesEntry> getFunctionsLocals() {
			return this;
		}

		public Map<Integer, String> getLocalNames(int funcIndex) {
			return funcMap.get(funcIndex);
		}

	}
}

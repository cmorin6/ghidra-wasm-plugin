package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmString;

public class WasmCustomSection implements WasmPayload {
	protected WasmString name;
	byte[] contents;

	protected WasmCustomSection(WasmString name, BinaryReader reader, int contentlen) throws IOException {
		this.name = name;
		contents = reader.readNextByteArray(contentlen);
	}

	public static WasmCustomSection create(BinaryReader reader, long len) throws IOException {
		long readUntil = reader.getPointerIndex() + len;

		WasmString name = new WasmString(reader);

		int contentlen = (int) (readUntil - reader.getPointerIndex());

		if ("name".equals(name.getValue())) {
			return new WasmNameSection(name, reader, contentlen);
		}

		return new WasmCustomSection(name, reader, contentlen);
	}

	@Override
	public void addToStructure(Structure structure)
			throws IllegalArgumentException, DuplicateNameException, IOException {
		name.addToStructure(structure);
		structure.add(StructConverter.STRING, contents.length, "contents", null);
	}

	@Override
	public String getName() {
		return name.getValue();
	}

}

package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmInstrBlock;
import wasm.format.commons.WasmList.ListItem;

public class WasmGlobalSegment implements ListItem {

	protected int index;

	protected byte type;
	protected LEB128 mutability;
	protected WasmInstrBlock initExpr;

	public WasmGlobalSegment(int index, BinaryReader reader) throws IOException {
		this.index = index;
		type = reader.readNextByte();
		mutability = LEB128.readUnsignedValue(reader);
		initExpr = new WasmInstrBlock(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(getStructName(), 0);
		structure.add(BYTE, 1, "type", null);
		structure.add(new ArrayDataType(BYTE, mutability.getLength(), BYTE.getLength()), "mutability", null);
		structure.add(initExpr.toDataType(), "init", null);
		return structure;
	}

	@Override
	public String getStructName() {
		return "global_" + index;
	}

}

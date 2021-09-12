package wasm.format.commons;

import static ghidra.app.util.bin.StructConverter.BYTE;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.commons.WasmList.ListItem;

/**
 * Utility class to parse a list stored with first the number of elements, then
 * the elements themselves.
 * 
 * @param <Item> Type of element stored in the list.
 */
public class WasmList<Item extends ListItem> extends ArrayList<Item> {

	/**
	 * Interface that must be implemented by classes stored in a WasmList
	 */
	public static interface ListItem extends StructConverter {
		public String getStructName();
	}

	/**
	 * Interface used to specify how to construct the list items.
	 * 
	 * @param <Element> The type of data being created.
	 */
	@FunctionalInterface
	public interface ItemConstructor<Element> {

		/**
		 * Create an element corresponding to the index's item in the list.
		 * 
		 * @param index  The index of the element being created in the final array.
		 *               (mostly used to avoid conflicts the final structure name).
		 * @param reader BinaryReader used to construct the new item.
		 * @return The created item.
		 * @throws IOException
		 */
		public Element create(int index, BinaryReader reader) throws IOException;
	}

	protected ItemConstructor<Item> constructor;

	protected LEB128 count;

	public WasmList(BinaryReader reader, ItemConstructor<Item> constructor) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asInt32(); ++i) {
			add(constructor.create(i, reader));
		}
	}

	public void addToStructure(Structure structure) throws DuplicateNameException, IOException {
		structure.add(new ArrayDataType(BYTE, count.getLength(), BYTE.getLength()), "count", null);
		for (Item item : this) {
			DataType dt = item.toDataType();
			structure.add(dt, dt.getLength(), item.getStructName(), null);
		}
	}

}

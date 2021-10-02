package wasm;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.file.WasmModule;
import wasm.file.WasmModule.WasmSectionKey;
import wasm.format.Utils;
import wasm.format.WasmConstants;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.WasmDataSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmLinearMemorySection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmResizableLimits;
import wasm.format.sections.structures.WasmNameSegment.ListIndexNamePayload;
import wasm.format.sections.structures.WasmNameSegment.NAME_TYPES;
import wasm.format.sections.structures.WasmNameSegment.WasmNamePayload;

public class WasmMemoryLoader {

	public static final String DOT_DATA = ".data";
	public static final String DOT_RODATA = ".rodata";

	/**
	 * Creates a memory blocks defined in the WasmModule and fill it with the data
	 * defined in the data segment if any.
	 * 
	 * @param program
	 * @param module
	 * @param monitor
	 * @param log
	 * @throws LockException
	 * @throws IllegalArgumentException
	 * @throws MemoryConflictException
	 * @throws AddressOverflowException
	 * @throws CancelledException
	 * @throws MemoryAccessException
	 */
	public static void initMemory(Program program, WasmModule module, TaskMonitor monitor, MessageLog log)
			throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException,
			CancelledException, MemoryAccessException {

		long memSize = getWasmMemorySize(module);

		// try initializing with emscripten layout.
		if (initEmscriptenMemory(program, module, monitor, log, memSize)) {
			return;
		}

		// ensure that there is sufficient space for data
		WasmDataSection dataSection = module.getSectionPayload(WasmSectionKey.DATA);
		if (dataSection == null && memSize == -1) {
			// no memory defined for this program
			return;
		}

		if (dataSection != null) {
			for (WasmDataSegment segment : dataSection.getSegments()) {
				long dataEnd = segment.getOffset() + segment.getData().length;
				if (memSize < dataEnd) {
					long increment = dataEnd - memSize;
					long added = (increment / WasmConstants.WASM_MEM_BLOCK_SIZE) * WasmConstants.WASM_MEM_BLOCK_SIZE;
					if (increment % WasmConstants.WASM_MEM_BLOCK_SIZE != 0) {
						added += WasmConstants.WASM_MEM_BLOCK_SIZE;
					}
					memSize += added;
				}
			}
		}

		// create memory block
		Address memBase = program.getAddressFactory().getAddressSpace("ram").getAddress(0);
		MemoryBlock block = program.getMemory().createInitializedBlock("memory", memBase, memSize, (byte) 0x00, monitor,
				false);
		block.setRead(true);
		block.setWrite(true);
		block.setExecute(false);

		// fill memory with data segments
		if (dataSection != null) {
			for (WasmDataSegment segment : dataSection.getSegments()) {
				Address where = memBase.add(segment.getOffset());
				block.putBytes(where, segment.getData());
			}
		}
	}

	/**
	 * Compute the size of the memory from either LinearMemory section or import
	 * section.
	 * 
	 * @param module
	 * @return The memory size in bytes or -1 if no memory is defined in the module.
	 */
	protected static long getWasmMemorySize(WasmModule module) {
		// look for memory definition
		WasmLinearMemorySection memSection = module.getSectionPayload(WasmSectionKey.LINEARMEMORY);
		if (memSection != null) {
			List<WasmResizableLimits> memDefs = memSection.getMemoryDefinitions();
			if (memDefs != null && !memDefs.isEmpty()) {
				// note: only consider the first entry as the current Wasm specification
				// only support one memory block
				WasmResizableLimits memDef = memDefs.get(0);
				long finalSize = memDef.getAllocSize() * WasmConstants.WASM_MEM_BLOCK_SIZE;
				return finalSize;
			}
		}

		// otherwise lookup imports
		WasmImportSection importSection = module.getSectionPayload(WasmSectionKey.IMPORT);
		if (importSection != null) {
			for (WasmImportEntry importEntry : importSection.getEntries()) {
				if (importEntry.getKind() == WasmExternalKind.EXT_MEMORY) {
					WasmResizableLimits memDef = importEntry.getMemoryDefinition();
					if (memDef != null) {
						long finalSize = memDef.getAllocSize() * WasmConstants.WASM_MEM_BLOCK_SIZE;
						return finalSize;
					}
				}
			}
		}

		return -1;
	}

	protected static class WasmDataBlock implements Comparable<WasmDataBlock> {
		public String name;
		public long offset;
		public byte[] content;

		@Override
		public int compareTo(WasmDataBlock other) {
			return Long.compare(offset, other.offset);
		}
	}

	/**
	 * Extract a list of WasmDataBlock sorted by their offset.
	 * 
	 * @param dataSection
	 * @param dataNames
	 * @return
	 */
	protected static List<WasmDataBlock> extractDataBlocks(WasmDataSection dataSection,
			ListIndexNamePayload dataNames) {
		List<WasmDataBlock> dataBlocks = new ArrayList<>();
		for (int i = 0; i < dataSection.size(); i++) {
			WasmDataSegment dataSeg = dataSection.get(i);
			WasmDataBlock block = new WasmDataBlock();
			block.name = dataNames.getName(i);
			block.offset = dataSeg.getOffset();
			block.content = dataSeg.getData();
			dataBlocks.add(block);
		}
		Collections.sort(dataBlocks);
		return dataBlocks;
	}

	/**
	 * Detects if the specified program was generated by Emscripten and use the
	 * ".data" ".rodata" data names to setup memory block with suitable permission.
	 * This allows the decompiler to find constant string and display them as such.
	 * 
	 * @param program
	 * @param module
	 * @param monitor
	 * @param log
	 * @param memsize
	 * @return True if the memory was initialized using emscripten layout, false
	 *         otherwise.
	 * @throws LockException
	 * @throws MemoryConflictException
	 * @throws AddressOverflowException
	 * @throws CancelledException
	 * @throws IllegalArgumentException
	 */
	protected static boolean initEmscriptenMemory(Program program, WasmModule module, TaskMonitor monitor,
			MessageLog log, long memsize) throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException, IllegalArgumentException {
		WasmLinearMemorySection memSection = module.getSectionPayload(WasmSectionKey.LINEARMEMORY);
		if (memSection == null) {
			// there should a linear memory section (not imported memory) in wasm c binaries
			return false;
		}

		WasmDataSection dataSection = module.getSectionPayload(WasmSectionKey.DATA);
		if (dataSection == null) {
			// there should be defined data blocks
			return false;
		}

		WasmNameSection nameSection = module.getNameSection();
		if (nameSection == null) {
			// there should be a defined name section
			return false;
		}

		// check globals
		if (!"__stack_pointer".equals(nameSection.getGlobalName(0))) {
			return false;
		}
		if (!"__stack_end".equals(nameSection.getGlobalName(1))) {
			return false;
		}
		if (!"__stack_base".equals(nameSection.getGlobalName(2))) {
			return false;
		}

		WasmNamePayload payload = nameSection.getNamePayload(NAME_TYPES.DATA_NAMES);
		if (payload == null) {
			// there should be names for datas
			return false;
		}

		ListIndexNamePayload dataNames = (ListIndexNamePayload) payload;
		if (dataSection.size() != 2 && dataNames.size() != 2) {
			return false;
		}

		// make sure that we only have two segments ".rodata" and ".data" in this
		// correct order.
		List<WasmDataBlock> dataBlocks = extractDataBlocks(dataSection, dataNames);
		if (!DOT_RODATA.equals(dataBlocks.get(0).name)) {
			return false;
		}
		if (!DOT_DATA.equals(dataBlocks.get(1).name)) {
			return false;
		}

		// create .rodata memory block with readonly perm
		WasmDataBlock rodata = dataBlocks.get(0);
		String secName = "memory" + rodata.name;
		Address memBase = Utils.toAddr(program, rodata.offset);
		ByteArrayInputStream bais = new ByteArrayInputStream(rodata.content);
		MemoryBlock rodataBlock = program.getMemory().createInitializedBlock(secName, memBase, bais,
				rodata.content.length, monitor, false);
		rodataBlock.setPermissions(true, false, false);

		// create .data memory block with read/write perms and stretch it to the end
		// of the memory size.
		WasmDataBlock data = dataBlocks.get(1);
		secName = "memory" + data.name;
		memBase = Utils.toAddr(program, data.offset);
		bais = new ByteArrayInputStream(data.content);
		long blocksize = memsize - data.offset;
		MemoryBlock dataBlock = program.getMemory().createInitializedBlock(secName, memBase, blocksize, (byte) 0x00,
				monitor, false);
		dataBlock.setPermissions(true, true, false);
		try {
			dataBlock.putBytes(memBase, data.content);
		} catch (MemoryAccessException e) {
			e.printStackTrace();
		}
		return true;
	}

}

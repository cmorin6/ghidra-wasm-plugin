/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wasm;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import agent.gdb.pty.linux.Util;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import wasm.analysis.WasmAnalysis;
import wasm.file.WasmModule;
import wasm.format.Utils;
import wasm.format.WasmConstants;
import wasm.format.WasmHeader;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmDataSection;
import wasm.format.sections.WasmExportSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmLocalEntry.WasmLocalType;
/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class WasmLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "WebAssembly";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		WasmHeader header = new WasmHeader(reader);
		
		if(WasmConstants.WASM_MAGIC_BASE.equals(new String(header.getMagic()))) {
			loadSpecs.add(new LoadSpec(this, 0x10000000,
					new LanguageCompilerSpecPair("Wasm:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}
	
	private void createMethodByteCodeBlock(Program program, long length, TaskMonitor monitor) throws Exception {
		Address address = Utils.toAddr( program, Utils.METHOD_ADDRESS );
		MemoryBlock block = program.getMemory( ).createInitializedBlock( "method_bytecode", address, length, (byte) 0xff, monitor, false );
		block.setRead( true );
		block.setWrite( false );
		block.setExecute( true );
	}
	
	private void createImportStubBlock(Program program, long length, TaskMonitor monitor) throws Exception {
		Address address = Utils.toAddr(program, Utils.IMPORTS_BASE);
		MemoryBlock block = program.getMemory().createInitializedBlock( "import_stubs", address, length, (byte) 0xff, monitor, false );
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
	}
	
	public Data createData(Program program, Listing listing, Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "ELF data markup conflict at " + address);
			e.printStackTrace();
		}
		catch (DataTypeConflictException e) {
			Msg.error(this, "ELF data type markup conflict:" + e.getMessage());
		}
		return null;
	}
	
	private void markupHeader(Program program, WasmHeader header, TaskMonitor monitor, InputStream reader, MessageLog log) throws DuplicateNameException, IOException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "Wasm Header";
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress( Utils.HEADER_BASE );
		try {
			MemoryBlockUtils.createInitializedBlock(program, false, ".header", start, reader, 8, "", BLOCK_SOURCE_NAME, r, w, x, log, monitor);
			createData(program, program.getListing(), start, header.toDataType());
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void markupSections(Program program, WasmModule module, TaskMonitor monitor, InputStream reader, MessageLog log) throws DuplicateNameException, IOException, AddressOverflowException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "Wasm Section";
		for (WasmSection section: module.getSections()) {
//			if(section.getId()==WasmSectionId.SEC_DATA) {
//				continue;
//			}
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(Utils.HEADER_BASE + section.getSectionOffset());
			MemoryBlockUtils.createInitializedBlock(program, false, section.getPayload().getName(), start, reader, section.getSectionSize(), "", BLOCK_SOURCE_NAME, r, w, x, log, monitor);
			createData(program, program.getListing(), start, section.toDataType());			
		}
	}
	
	private void addModuleSection(Program program, long length, TaskMonitor monitor, InputStream reader, MessageLog log) throws AddressOverflowException {
		boolean r = true;
		boolean w = false;
		boolean x = false;
		String MODULE_SOURCE_NAME = "Wasm Module";
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(Utils.MODULE_BASE);
		MemoryBlockUtils.createInitializedBlock(program, false, ".module", start, reader, length, "The full file contents of the Wasm module", MODULE_SOURCE_NAME, r, w, x, log, monitor);
	}

	private String getMethodName(WasmNameSection names, WasmExportSection exports, int id) {
		if(names != null) {
			String name = names.getFunctionName(id);
			if(name != null) {
				return "wasm_" + name;
			}
		}
		
		if(exports != null) {
			WasmExportEntry entry = exports.findMethod(id);
			if (entry != null) {
				return "export_" + entry.getName();
			}
		}
		return "unnamed_function_" + id;
	}
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
		Program program, TaskMonitor monitor, MessageLog log)
		throws CancelledException, IOException {
	
		monitor.setMessage( "Wasm Loader: Start loading" );
		
		try {
			long length = provider.length();
	
			InputStream inputStream;
			inputStream = provider.getInputStream(0);
			
			BinaryReader reader = new BinaryReader( provider, true );
			WasmModule module = new WasmModule( reader );
			
			addModuleSection(program, provider.length(), monitor, provider.getInputStream(0), log);
	
			createMethodByteCodeBlock( program, length, monitor);
			markupHeader(program, module.getHeader(), monitor, inputStream, log);
			markupSections(program, module, monitor, inputStream, log);
			monitor.setMessage( "Wasm Loader: Create byte code" );

			FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, provider.length(), monitor);
			
			for (WasmSection section : module.getSections()) {
				monitor.setMessage("Loaded " + section.getId().toString());
				switch(section.getId()) {
				case SEC_CODE: {
					WasmCodeSection codeSection = (WasmCodeSection)section.getPayload();
					long code_offset = section.getPayloadOffset();
					for (int i = 0; i < codeSection.getFunctions().size(); ++i) {
						WasmFunctionBody method = codeSection.getFunctions().get(i);
						long method_offset = code_offset + method.getOffset();
						Address methodAddress = Utils.toAddr( program, Utils.METHOD_ADDRESS + method_offset );
						Address methodend = Utils.toAddr( program, Utils.METHOD_ADDRESS + method_offset + method.getInstructions().length);
						byte [] instructionBytes = method.getInstructions();
						program.getMemory( ).setBytes( methodAddress, instructionBytes );
						//The function index space begins with an index for each imported function, 
						//in the order the imports appear in the Import Section, if present, 
						//followed by an index for each function in the Function Section, 
						WasmSection imports = module.getSection(WasmSectionId.SEC_IMPORT);
						int imports_offset = imports == null? 0 : ((WasmImportSection)imports.getPayload()).getCount();
						WasmSection exports = module.getSection(WasmSectionId.SEC_EXPORT);
						String methodName = getMethodName(
								module.getNameSection(),
								exports == null? null: (WasmExportSection)exports.getPayload(), 
								i + imports_offset);
						program.getFunctionManager().createFunction(
								methodName, methodAddress, 
								new AddressSet(methodAddress, methodend), SourceType.ANALYSIS);
						program.getSymbolTable().createLabel(methodAddress, methodName, SourceType.ANALYSIS);
					}
					break;
				}
				case SEC_DATA: {
					WasmDataSection dataSection = (WasmDataSection)section.getPayload();
					List<WasmDataSegment> dataSegments = dataSection.getSegments();
					for(int i=0; i<dataSegments.size(); i++) {
						WasmDataSegment dataSegment = dataSegments.get(i);
						long offset = dataSegment.getOffset();
						if(offset == -1)
							continue;
						long fileOffset = dataSegment.getFileOffset() + section.getPayloadOffset();
						Address dataStart = program.getAddressFactory().getAddressSpace("mem0").getAddress(offset);
						program.getMemory().createInitializedBlock(".data" + i, dataStart, fileBytes, fileOffset, dataSegment.getSize(), false);
					}
					break;
				}
				case SEC_IMPORT: {
					WasmImportSection importSection = (WasmImportSection)section.getPayload();
					createImportStubBlock(program, importSection.getCount() * Utils.IMPORT_STUB_LEN, monitor);
					int nextFuncIdx = 0;
					for(WasmImportEntry entry : importSection.getEntries()) {
						if(entry.getKind() != WasmExternalKind.EXT_FUNCTION) {
							continue;
						}
						
						String methodName = "import__" + entry.getName();
						Address methodAddress = Utils.toAddr(program, Utils.IMPORTS_BASE + nextFuncIdx * Utils.IMPORT_STUB_LEN);
						Address methodEnd = Utils.toAddr(program,  Utils.IMPORTS_BASE + (nextFuncIdx+1) * Utils.IMPORT_STUB_LEN - 1);
						
						program.getFunctionManager().createFunction(
								methodName, methodAddress, 
								new AddressSet(methodAddress, methodEnd), SourceType.IMPORTED);
						
						program.getSymbolTable().createLabel(methodAddress, methodName, SourceType.IMPORTED);
						
						nextFuncIdx++;
					}
					break;
				}
				}
			}
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}

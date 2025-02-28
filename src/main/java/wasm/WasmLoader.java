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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import wasm.analysis.WasmFunctionData;
import wasm.analysis.WasmModuleData;
import wasm.file.WasmModule;
import wasm.format.Utils;
import wasm.format.WasmConstants;
import wasm.format.WasmHeader;
import wasm.format.sections.WasmCustomSection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class WasmLoader extends AbstractLibrarySupportLoader {

	public static final String WEBASSEMBLY = "WebAssembly";

	@Override
	public String getName() {
		return WEBASSEMBLY;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		WasmHeader header = new WasmHeader(reader);

		if (WasmConstants.WASM_MAGIC_BASE.equals(new String(header.getMagic()))) {
			loadSpecs.add(new LoadSpec(this, 0x10000000, new LanguageCompilerSpecPair("Wasm:LE:32:default", "default"),
					true));
		}

		return loadSpecs;
	}

	private void createMethodByteCodeBlock(Program program, long length, TaskMonitor monitor) throws Exception {
		Address address = Utils.toAddr(program, Utils.METHOD_ADDRESS);
		MemoryBlock block = program.getMemory().createInitializedBlock("method_bytecode", address, length, (byte) 0xff,
				monitor, false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
	}

	private void createImportStubBlock(Program program, long length, TaskMonitor monitor) throws Exception {
		Address address = Utils.toAddr(program, Utils.IMPORTS_BASE);
		MemoryBlock block = program.getMemory().createInitializedBlock("import_stubs", address, length, (byte) 0xff,
				monitor, false);
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
		} catch (CodeUnitInsertionException e) {
			Msg.warn(this, "ELF data markup conflict at " + address);
			e.printStackTrace();
		} catch (DataTypeConflictException e) {
			Msg.error(this, "ELF data type markup conflict:" + e.getMessage());
		}
		return null;
	}

	private void markupHeader(Program program, WasmHeader header, TaskMonitor monitor, InputStream reader,
			MessageLog log) throws DuplicateNameException, IOException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "Wasm Header";
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(Utils.HEADER_BASE);
		try {
			MemoryBlockUtils.createInitializedBlock(program, false, ".header", start, reader, 8, "", BLOCK_SOURCE_NAME,
					r, w, x, log, monitor);
			createData(program, program.getListing(), start, header.toDataType());
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void markupSections(Program program, WasmModule module, TaskMonitor monitor, InputStream reader,
			MessageLog log) throws DuplicateNameException, IOException, AddressOverflowException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "Wasm Section";
		for (WasmSection section : module.getSections()) {
			if (section.getId() == WasmSectionId.SEC_CUSTOM && !(section.getPayload() instanceof WasmNameSection)) {
				// Special case for Custom section to remove their section header.
				// this allows to reuse standard parsing of Dwarf sections.
				WasmCustomSection customSection = (WasmCustomSection) section.getPayload();
				Address start = Utils.toAddr(program,
						Utils.HEADER_BASE + section.getPayloadOffset() + customSection.getContentOffset());
				// discard section header bytes
				int headerSize = (int) ((section.getPayloadOffset() - section.getSectionOffset())
						+ customSection.getContentOffset());
				reader.readNBytes(headerSize);
				MemoryBlockUtils.createInitializedBlock(program, false, customSection.getName(), start, reader,
						customSection.getContents().length, "", BLOCK_SOURCE_NAME, r, w, x, log, monitor);
			} else {
				Address start = Utils.toAddr(program, Utils.HEADER_BASE + section.getSectionOffset());
				MemoryBlockUtils.createInitializedBlock(program, false, section.getPayload().getName(), start, reader,
						section.getSectionSize(), "", BLOCK_SOURCE_NAME, r, w, x, log, monitor);
				createData(program, program.getListing(), start, section.toDataType());
			}
		}
	}

	private String getMethodName(WasmFunctionData function) {
		String res = function.getName();
		if (res == null) {
			res = function.getExportName();
		}
		if (res == null) {
			res = function.getFullImportName();
		}
		if (res == null) {
			res = "unnamed_function_" + function.getIndex();
		}
		return res;
	}

	protected boolean isValidFunctionName(String functionName) {
		try {
			SymbolUtilities.validateName(functionName);
			return true;
		} catch (InvalidInputException e) {
			return false;
		}
	}

	protected String extractValidFunctionName(String functionName) {
		// TODO:
		// replace with proper parsing to retrieve namespaces and parameter types

		// namepace1::class::method(type ,type) res;

		// strip parameter definition
		functionName = functionName.split("\\(")[0];
		functionName = functionName.replaceAll(" ", "");
		return functionName;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		monitor.setMessage("Wasm Loader: Start loading");

		try {
			long length = provider.length();

			InputStream inputStream;
			inputStream = provider.getInputStream(0);

			BinaryReader reader = new BinaryReader(provider, true);
			WasmModule module = new WasmModule(reader);

			createMethodByteCodeBlock(program, length, monitor);
			markupHeader(program, module.getHeader(), monitor, inputStream, log);
			markupSections(program, module, monitor, inputStream, log);
			monitor.setMessage("Wasm Loader: Create byte code");

			WasmMemoryLoader.initMemory(program, module, monitor, log);

			WasmModuleData moduleData = new WasmModuleData(program, module);

			// create functions
			for (WasmFunctionData functionData : moduleData.getRealFunctions()) {
				Address methodAddress = functionData.getEntryPoint();
				byte[] instructionBytes = functionData.getBody().getInstructions();

				// write actual function bytes
				program.getMemory().setBytes(methodAddress, instructionBytes);

				// create Function and symbols
				Address methodEnd = methodAddress.add(instructionBytes.length);
				String methodName = getMethodName(functionData);
				Function function;
				if (isValidFunctionName(methodName)) {
					function = program.getFunctionManager().createFunction(methodName, methodAddress,
							new AddressSet(methodAddress, methodEnd), SourceType.ANALYSIS);
				} else {
					String validFuncName = extractValidFunctionName(methodName);
					function = program.getFunctionManager().createFunction(validFuncName, methodAddress,
							new AddressSet(methodAddress, methodEnd), SourceType.ANALYSIS);
					// add the original name as a comment
					function.setComment(methodName);
				}

				// create Export symbol
				if (functionData.getExportName() != null) {
					program.getSymbolTable().addExternalEntryPoint(methodAddress);
				}

			}

			// create imported functions
			List<WasmFunctionData> importedFuncs = moduleData.getImportedFunctions();
			if (!importedFuncs.isEmpty()) {
				createImportStubBlock(program, importedFuncs.size() * Utils.IMPORT_STUB_LEN, monitor);
				for (WasmFunctionData functionData : importedFuncs) {
					String methodName = getMethodName(functionData);
					Address methodAddress = functionData.getEntryPoint();
					Address methodEnd = methodAddress.add(Utils.IMPORT_STUB_LEN - 1);

					// create function
					Function function = program.getFunctionManager().createFunction(methodName, methodAddress,
							new AddressSet(methodAddress, methodEnd), SourceType.IMPORTED);

					// create Import symbol
					ExternalLocation extLoc = program.getExternalManager().addExtFunction(
							functionData.getImportModuleName(), functionData.getImportFunctionName(), methodAddress,
							SourceType.IMPORTED);
					function.setThunkedFunction(extLoc.getFunction());

				}
			}

		} catch (Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}

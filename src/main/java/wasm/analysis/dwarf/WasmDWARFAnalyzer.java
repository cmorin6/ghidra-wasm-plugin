package wasm.analysis.dwarf;

import ghidra.app.plugin.core.analysis.DWARFAnalyzer;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProviderFactory;
import ghidra.program.model.listing.Program;
import wasm.WasmLoader;

public class WasmDWARFAnalyzer extends DWARFAnalyzer {

	// Note:
	// DataType parsing is supported out of the box, but function import requires
	// deep changes.
	// see https://yurydelendik.github.io/webassembly-dwarf/
	//
	// * consider function imports address as relative to the code section (the
	// offset points to the function header so we also need to add the function
	// header size to the address to get the actual function offset).
	// * implement the custom DWARF expression (DW_OP_WASM_location := 0xED) used to
	// describe function variables and arguments.

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();

		if (WasmLoader.WEBASSEMBLY.equals(format)
				&& DWARFSectionProviderFactory.createSectionProviderFor(program) != null) {
			return true;
		}
		return false;
	}
}

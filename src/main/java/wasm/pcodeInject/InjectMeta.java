package wasm.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.analysis.flow.MetaInstruction;
import wasm.analysis.flow.WasmFlowAnalysis;

public class InjectMeta extends InjectPayloadWasm {
	MetaInstruction.Type opKind;
	static boolean tested = false; // TODO: remove test var

	public InjectMeta(String sourceName, SleighLanguage language, long uniqBase, MetaInstruction.Type opKind) {
		super(sourceName, language, uniqBase);
		this.opKind = opKind;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {

		MetaInstruction mi = WasmFlowAnalysis.getMetaInstruction(program,con.baseAddr, opKind);

		PcodeOpEmitter pCode = new PcodeOpEmitter(language, con.baseAddr, this.uniqueBase);
		if(mi!=null) {
			mi.synthesize(pCode);
		}else {
			pCode.emitNop();
		}
		return pCode.getPcodeOps();
	}
}

package wasm.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.analysis.flow.InstructionFlowUtil.InstructionGenerator;
import wasm.analysis.flow.WasmFlowAnalysis;

public class InjectMeta extends InjectPayloadWasm {
	String callotherName;
	static boolean tested = false; // TODO: remove test var

	public InjectMeta(String sourceName, SleighLanguage language, long uniqBase, String callotherName) {
		super(sourceName, language, uniqBase);
		this.callotherName = callotherName;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {

		InstructionGenerator ig = WasmFlowAnalysis.getMetaInstruction(program, con.baseAddr, callotherName);

		PcodeOpEmitter pCode = new PcodeOpEmitter(language, con.baseAddr, this.uniqueBase);
		if (ig != null) {
			ig.synthesize(pCode);
		} else {
			pCode.emitNop();
		}
		return pCode.getPcodeOps();
	}
}

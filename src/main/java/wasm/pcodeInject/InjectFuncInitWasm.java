package wasm.pcodeInject;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;
import wasm.analysis.flow.WasmFlowAnalysis;
import wasm.analysis.flow.WasmFunctionFlowAnalysis.GlobalStack;

public class InjectFuncInitWasm implements InjectPayload {
	private String name;
	private String sourceName;
	private InjectParameter[] noParams;
	private SleighLanguage language;
	private long uniqBase;

	public InjectFuncInitWasm(String name, String srcName, SleighLanguage language, long uniqBase) {
		this.uniqBase = uniqBase;
		this.language = language;
		this.name = name;
		sourceName = srcName;
		noParams = new InjectParameter[0];
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getType() {
		return CALLMECHANISM_TYPE;
	}

	@Override
	public String getSource() {
		return sourceName;
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public InjectParameter[] getInput() {
		return noParams;
	}

	@Override
	public InjectParameter[] getOutput() {
		return noParams;
	}

	@Override
	public boolean isErrorPlaceholder() {
		return false;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
		// not used
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {

		PcodeOpEmitter pCode = new PcodeOpEmitter(language, con.baseAddr, this.uniqBase);
		GlobalStack globalStack = WasmFlowAnalysis.getGlobalStack(program, con.baseAddr);
		if(globalStack==null) {
			pCode.emitNop();
		}else {
			pCode.emitStackSetup(globalStack);
		}
		return pCode.getPcodeOps();
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

	@Override
	public boolean isIncidentalCopy() {
		return true;
	}

	@Override
	public void saveXml(StringBuilder buffer) {
		// Provide a minimal tag so decompiler can call-back
		buffer.append("<pcode");
		SpecXmlUtils.encodeStringAttribute(buffer, "inject", "uponentry");
		SpecXmlUtils.encodeBooleanAttribute(buffer, "dynamic", true);
		buffer.append("/>\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement el = parser.start();
		String injectString = el.getAttribute("inject");
		if (injectString == null || !injectString.equals("uponentry")) {
			throw new XmlParseException("Expecting inject=\"uponentry\" attribute");
		}
		boolean isDynamic = SpecXmlUtils.decodeBoolean(el.getAttribute("dynamic"));
		if (!isDynamic) {
			throw new XmlParseException("Expecting dynamic attribute");
		}
		parser.end(el);
	}

	@Override
	public boolean equals(Object obj) {
		return (obj instanceof InjectFuncInitWasm); // All instances are equal
	}

	@Override
	public int hashCode() {
		return 1234742621; // All instances are equal
	}
}
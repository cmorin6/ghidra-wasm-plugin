package wasm.pcodeInject;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibraryWasm extends PcodeInjectLibrary {

	private Map<String, InjectPayloadWasm> implementedOps;

	public static final String BR = "brCallOther";
	public static final String IF = "ifCallOther";
	public static final String ELSE = "elseCallOther";
	public static final String RETURN = "returnCallOther";
	public static final String CALL = "callCallOther";
	public static final String CALL_INDIRECT = "callIndirectCallOther";
	public static final String BR_TABLE = "brTableCallOther";

	public static final String SOURCENAME = "wasmsource";

	public static final long BASE_CHUNK_SIZE = 0x200;
	private long nextUniqueBase;
	long funcInitUniqueBase;

	public long getNextUniqueBase() {
		long res = nextUniqueBase;
		nextUniqueBase += BASE_CHUNK_SIZE;
		return res;
	}

	public PcodeInjectLibraryWasm(SleighLanguage l) {
		super(l);
		nextUniqueBase = this.uniqueBase;

		implementedOps = new HashMap<>();
		implementedOps.put(BR, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), BR));
		implementedOps.put(IF, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), IF));
		implementedOps.put(ELSE, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), ELSE));
		implementedOps.put(RETURN, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), RETURN));
		implementedOps.put(CALL, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), CALL));
		implementedOps.put(CALL_INDIRECT, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), CALL_INDIRECT));
		implementedOps.put(BR_TABLE, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), BR_TABLE));
		funcInitUniqueBase = getUniqueBase();
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLOTHERFIXUP_TYPE) {
			InjectPayloadWasm payload = implementedOps.get(name);
			if (payload != null) {
				return payload;
			}
		} else if (tp == InjectPayload.CALLMECHANISM_TYPE) {
			return new InjectFuncInitWasm(name, SOURCENAME, language, funcInitUniqueBase);
		}
		return super.allocateInject(sourceName, name, tp);
	}
}

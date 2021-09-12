package wasm;

import java.util.Arrays;
import java.util.Map;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.FunctionSignature;
import wasm.format.WasmEnums.ValType;
import wasm.format.sections.structures.WasmFuncType;

public class FunctionSignatureImpl implements FunctionSignature {

	protected String name;
	protected ParameterDefinition[] arguments;
	protected DataType returnType;

	public FunctionSignatureImpl(String name, WasmFuncType funcType, Map<Integer, String> paramNames) {
		// params
		byte[] params = funcType.getParamTypes();

		arguments = new ParameterDefinition[params.length];
		for (int i = 0; i < params.length; i++) {
			DataType dt = ValType.fromByte(params[i]).toDatatType();
			String paramName = null;
			if (paramNames != null) {
				paramName = paramNames.get(i);
			}
			arguments[i] = new ParameterDefinitionImpl(paramName, dt, null);
		}

		// returns
		byte[] rets = funcType.getReturnTypes();
		ValType retvt = null;
		if (rets.length > 0) {
			retvt = ValType.fromByte(rets[0]);
		}
		if (retvt == null) {
			returnType = StructConverter.VOID;
		} else {
			returnType = retvt.toDatatType();
		}
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getPrototypeString() {
		return name;
	}

	@Override
	public String getPrototypeString(boolean includeCallingConvention) {
		return name;
	}

	@Override
	public ParameterDefinition[] getArguments() {
		return arguments;
	}

	@Override
	public DataType getReturnType() {
		return returnType;
	}

	@Override
	public String getComment() {
		return null;
	}

	@Override
	public boolean hasVarArgs() {
		return false;
	}

	@Override
	public GenericCallingConvention getGenericCallingConvention() {
		return GenericCallingConvention.getGenericCallingConvention("__asmA");
	}

	@Override
	public boolean isEquivalentSignature(FunctionSignature signature) {
		return equals(signature);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(arguments);
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((returnType == null) ? 0 : returnType.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		FunctionSignatureImpl other = (FunctionSignatureImpl) obj;
		if (!Arrays.equals(arguments, other.arguments))
			return false;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		if (returnType == null) {
			if (other.returnType != null)
				return false;
		} else if (!returnType.equals(other.returnType))
			return false;
		return true;
	}

}

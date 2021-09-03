package wasm.util;

public interface Initializable<InitParam> {

	void init(InitParam param);

	default boolean needReset(InitParam param) {
		return false;
	}
}

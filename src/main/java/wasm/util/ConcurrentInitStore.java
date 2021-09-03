package wasm.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility collection to manage access to {@link wasm.util.Initializable
 * Initializable} items concurrently.<br/>
 * <br/>
 * This make sure to always store only one instance of
 * {@link wasm.util.Initializable Initializable} object per key and to return it
 * only once fully initialized. Concurrent accesses for the same key will block
 * until the object if fully initialized, while accesses for different keys can
 * occur in parallel. <br/>
 * <br/>
 * Before returning an existing object, a call to
 * {@link wasm.util.Initializable#needReset(Object) Initializable.needReset()}
 * is made to check whether the current object is obsolete. If it is a new
 * instance is initialized blocking current access for this key until this new
 * instance is fully initialized and stored as a replacement for the obsolete
 * one.
 * 
 * 
 * @author cedric
 *
 * @param <InitParam> Parameter type for Initializable objects. This is the storage key.
 * @param <Stored> Type of object stored in this structure.
 */
public abstract class ConcurrentInitStore<InitParam, Stored extends Initializable<InitParam>> {

	private Map<Object, StorageWrapper<InitParam, Stored>> store = new ConcurrentHashMap<>();

	public ConcurrentInitStore() {

	}

	// implement this in subclasses to construct a Stored object instance
	protected abstract Stored create();

	// override this to define a custom storage key derived from the InitParam
	protected Object toStorageKey(InitParam param) {
		return param;
	}

	public Stored get(InitParam init) {
		Object key = toStorageKey(init);
		if (key == null) {
			return null;
		}
		StorageWrapper<InitParam, Stored> wrapper = store.get(key);
		// avoid blocking if the wrapper already exists
		if (wrapper == null) {
			synchronized (store) {
				// make sure only first thread created the wrapper
				wrapper = store.get(key);
				if (wrapper == null) {
					wrapper = new StorageWrapper<>(this);
					store.put(key, wrapper);
				}
			}
		}
		return wrapper.getInitialyzedObject(init);
	}

	private static class StorageWrapper<I, S extends Initializable<I>> {
		private S storedObject;
		private ConcurrentInitStore<I, S> store;

		protected StorageWrapper(ConcurrentInitStore<I, S> store) {
			this.store = store;
		}

		public synchronized S getInitialyzedObject(I param) {
			if (storedObject == null || (storedObject != null && storedObject.needReset(param))) {
				storedObject = store.create();
				storedObject.init(param);
			}
			return storedObject;
		}

	}

}

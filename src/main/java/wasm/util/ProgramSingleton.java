package wasm.util;

import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.program.model.listing.Program;

/**
 * {@link ConcurrentInitStore} implementation for storing data by
 * {@link ghidra.program.model.listing.Program Program} that automatically
 * clears data when the corresponding program is closed.
 *
 * @param <Init> type of data stored in this singleton.
 */
public abstract class ProgramSingleton<Init extends Initializable<Program>> extends ConcurrentInitStore<Program, Init> {

	@Override
	protected void onInsert(Object key, Program prog, StorageWrapper<Program, Init> stored) {
		prog.addCloseListener(new ProgramCloseListener(key, prog));
	}

	protected void removeEntry(Object key, Program prog) {
		synchronized (store) {
			store.remove(key);
		}
	}

	protected class ProgramCloseListener implements DomainObjectClosedListener {
		protected Object key;
		protected Program program;

		protected ProgramCloseListener(Object key, Program program) {
			this.key = key;
			this.program = program;
		}

		@Override
		public void domainObjectClosed() {
			ProgramSingleton.this.removeEntry(key, program);
		}
	}

}

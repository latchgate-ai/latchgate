//! Adversarial WASM fixture: tight infinite loop with no host imports.
//!
//! Used exclusively in `epoch_deadline_terminates_infinite_loop_provider` to
//! prove that the wasmtime epoch ticker interrupts pure-compute WASM.
//! tokio::time::timeout cannot fire here — no await points inside the loop.
//! Never deploy as a real action provider.

wit_bindgen::generate!({
    world: "provider",
    path: "../../../providers/wit",
});

struct Provider;
export!(Provider);

impl Guest for Provider {
    fn execute(_task_json: String) -> Result<String, String> {
        // Pure computation — no host imports, no await, no fuel checking.
        // Only the engine epoch ticker can interrupt this loop.
        let mut counter: u64 = 0;
        loop {
            counter = core::hint::black_box(counter.wrapping_add(1));
        }
    }
}
